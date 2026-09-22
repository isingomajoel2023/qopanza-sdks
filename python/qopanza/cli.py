"""qopanza — command-line interface for the Qopanza API.

    qopanza login                      store credentials
    qopanza scan .                     scan a local directory
    qopanza scan --tls example.com     probe a live TLS endpoint
    qopanza posture                    quantum risk score
    qopanza inventory                  cryptographic inventory
    qopanza key create --purpose kem   create a key
    qopanza key rotate <id>            rotate a key
    qopanza audit                      recent audit entries
    qopanza audit --verify             verify the audit hash chain
    qopanza migrate --plan             generate a migration plan
    qopanza compliance                 compliance report
    qopanza threats                    behavioural anomalies (not threats — read the caveats)
    qopanza secret set NAME            store a versioned secret
    qopanza secret get NAME            reveal it
    qopanza cert ca --common-name X    create an internal ML-DSA-65 root CA
    qopanza cert issue --common-name Y issue a leaf from it
    qopanza zk keygen                  generate a keypair locally (never uploaded)
    qopanza zk encrypt --key k.json    encrypt on this machine only

Talks to https://api.qopanza.com. To reach a backend you run yourself,
`qopanza login --base-url http://localhost:8000`, or set
QOPANZA_BASE_URL for a single invocation.

Deliberately stdlib-only apart from the SDK's own httpx dependency: a
security tool that drags in a tree of transitive packages is a harder
sell to the teams most likely to care about supply chain.

Exit codes are chosen so this composes in CI: 0 success, 1 usage/API
error, 2 findings above the requested severity threshold (see
`qopanza scan --fail-on`).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import httpx

from qopanza.client import DEFAULT_BASE_URL, QopanzaAPIError, QopanzaClient

CONFIG_PATH = Path(os.environ.get("QOPANZA_CONFIG", Path.home() / ".config" / "qopanza" / "config.json"))

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_FINDINGS = 2

_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


# ---- configuration ---------------------------------------------------------


def load_config() -> dict:
    """Environment always wins over the config file, so CI can inject
    credentials without writing them to disk."""
    config: dict = {}
    if CONFIG_PATH.exists():
        try:
            config = json.loads(CONFIG_PATH.read_text())
        except (OSError, json.JSONDecodeError):
            config = {}

    if os.environ.get("QOPANZA_API_KEY"):
        config["api_key"] = os.environ["QOPANZA_API_KEY"]
    if os.environ.get("QOPANZA_BASE_URL"):
        config["base_url"] = os.environ["QOPANZA_BASE_URL"]
    return config


def save_config(config: dict) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(config, indent=2))
    # The file holds an API key — make it user-only, like an SSH key.
    try:
        CONFIG_PATH.chmod(0o600)
    except OSError:  # pragma: no cover — best effort on exotic filesystems
        pass


def resolve_base_url(config: dict) -> str:
    """Where to send requests.

    A saved config written by an older version pinned
    http://localhost:8000, because `login` used to persist the default
    it was given. Those files are still on disk, so the value is read
    back as-is and the error path (see `main`) names it — silently
    rewriting somebody's stored endpoint would be worse than telling
    them which one is being used.
    """
    return config.get("base_url") or DEFAULT_BASE_URL


def make_client(config: dict) -> QopanzaClient:
    if not config.get("api_key"):
        raise SystemExit("Not logged in. Run 'qopanza login' or set QOPANZA_API_KEY.")
    return QopanzaClient(base_url=resolve_base_url(config), api_key=config["api_key"])


# ---- output helpers --------------------------------------------------------


def emit(data, as_json: bool) -> None:
    if as_json:
        print(json.dumps(data, indent=2, default=str))


def severity_at_least(severity: str, threshold: str) -> bool:
    try:
        return _SEVERITY_ORDER.index(severity) >= _SEVERITY_ORDER.index(threshold)
    except ValueError:
        return False


# ---- commands --------------------------------------------------------------


def cmd_login(args) -> int:
    config = load_config()
    api_key = args.api_key or input("API key: ").strip()
    if not api_key:
        print("No API key provided.", file=sys.stderr)
        return EXIT_ERROR

    config["api_key"] = api_key
    # Only an explicit --base-url is persisted. Writing the default into
    # the file is what made the old localhost default so sticky: every
    # user who ever ran `login` had it frozen on disk, so changing the
    # default in a later release would not have reached them.
    if args.base_url:
        config["base_url"] = args.base_url
    save_config(config)
    print(f"Credentials saved to {CONFIG_PATH}")
    print(f"API endpoint: {resolve_base_url(config)}")
    return EXIT_OK


def cmd_scan(args) -> int:
    client = make_client(load_config())

    if args.tls:
        host, _, port = args.tls.partition(":")
        run = client.scan_tls(host=host, port=int(port) if port else 443)
    elif args.repository:
        run = client.scan_repository(repository_url=args.repository, branch=args.branch)
    else:
        path = Path(args.path)
        if not path.exists():
            print(f"No such path: {path}", file=sys.stderr)
            return EXIT_ERROR
        run = _scan_path(client, path)

    if args.json:
        emit(run, True)
    else:
        _print_scan(client, run)

    if run.get("status") == "failed":
        print(f"\nScan failed: {run.get('error')}", file=sys.stderr)
        return EXIT_ERROR

    if args.fail_on:
        assets = client.list_scan_assets(run["id"])
        offending = [a for a in assets if severity_at_least(a["severity"], args.fail_on)]
        if offending:
            if not args.json:
                print(
                    f"\n{len(offending)} finding(s) at or above '{args.fail_on}' severity.",
                    file=sys.stderr,
                )
            return EXIT_FINDINGS

    return EXIT_OK


def _scan_path(client: QopanzaClient, path: Path) -> dict:
    """Concatenate scannable files and submit them.

    Sent as one payload with per-file markers rather than one request per
    file: a repository scan would otherwise be thousands of round trips.
    """
    if path.is_file():
        return client.scan_code(filename=str(path), content=path.read_text(errors="ignore"))

    chunks: list[str] = []
    scanned = 0
    for candidate in sorted(path.rglob("*")):
        if not candidate.is_file() or candidate.stat().st_size > 1_000_000:
            continue
        if any(part in {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}
               for part in candidate.parts):
            continue
        if candidate.suffix.lower() not in {
            ".py", ".js", ".ts", ".tsx", ".java", ".go", ".cs", ".rb", ".php", ".rs",
            ".c", ".cpp", ".h", ".yaml", ".yml", ".json", ".toml", ".conf", ".tf",
        }:
            continue
        try:
            chunks.append(f"# --- {candidate.relative_to(path)} ---\n{candidate.read_text(errors='ignore')}")
            scanned += 1
        except OSError:
            continue

    if not chunks:
        print("No scannable files found.", file=sys.stderr)
    return client.scan_code(filename=str(path), content="\n".join(chunks))


def _print_scan(client: QopanzaClient, run: dict) -> None:
    print(f"Scan {run['id'][:8]}  target={run['target']}  status={run['status']}")
    if run["status"] != "completed":
        return
    print(f"  assets found      {run['assets_found']}")
    print(f"  quantum vulnerable {run['quantum_vulnerable']}")
    print(f"  quantum safe       {run['quantum_safe']}")
    print(f"  risk score         {run['risk_score']}/100")

    assets = client.list_scan_assets(run["id"])
    flagged = [a for a in assets if a["quantum_status"] in ("vulnerable", "weak")]
    if flagged:
        print("\n  Findings:")
        for asset in flagged[:25]:
            where = asset["location"]
            if asset.get("line_number"):
                where += f":{asset['line_number']}"
            print(f"    [{asset['severity']:8s}] {asset['algorithm']:8s} {where}")
        if len(flagged) > 25:
            print(f"    ... and {len(flagged) - 25} more")


def cmd_posture(args) -> int:
    client = make_client(load_config())
    posture = client.security_posture()
    if args.json:
        emit(posture, True)
        return EXIT_OK

    print(f"Quantum Security Score: {posture['score']}/100  ({posture['quantum_risk']} risk)")
    print(f"  assets={posture['total_assets']}  vulnerable={posture['vulnerable_assets']}  "
          f"pqc={posture['pqc_assets']}")
    print("\n  By category:")
    for category, score in posture["category_scores"].items():
        print(f"    {category:16s} {score:3d}")
    if posture["recommended_actions"]:
        print("\n  Recommended actions:")
        for action in posture["recommended_actions"]:
            print(f"    - {action}")
    return EXIT_OK


def cmd_inventory(args) -> int:
    client = make_client(load_config())
    inventory = client.crypto_inventory()
    if args.json:
        emit(inventory, True)
        return EXIT_OK

    print("CRYPTO INVENTORY")
    print(f"  scans run          {inventory['scans_run']}")
    print(f"  assets discovered  {inventory['total_assets']}")
    print(f"  quantum vulnerable {inventory['quantum_vulnerable']}")
    print(f"  quantum safe       {inventory['quantum_safe']}")
    if inventory["by_algorithm"]:
        print("\n  By algorithm:")
        for row in inventory["by_algorithm"]:
            print(f"    {row['algorithm']:12s} {row['count']:5d}   {row['quantum_status']}")
    return EXIT_OK


def cmd_key(args) -> int:
    client = make_client(load_config())

    if args.key_command == "create":
        key = client.create_key(purpose=args.purpose, label=args.label)
        emit(key, args.json) or print(f"Created {key['purpose']} key {key['id']} ({key['algorithm']})")
        return EXIT_OK

    if args.key_command == "rotate":
        new_version = client.rotate_key(args.key_id)
        if args.json:
            emit(new_version, True)
        else:
            print(f"Rotated to v{new_version['version']} ({new_version['id']})")
            print("Previous versions remain able to decrypt existing data.")
        return EXIT_OK

    if args.key_command == "versions":
        versions = client.list_key_versions(args.key_id)
        if args.json:
            emit(versions, True)
        else:
            for version in versions:
                print(f"  v{version['version']}  {version['status']:11s} {version['id']}")
        return EXIT_OK

    return EXIT_ERROR


def cmd_threats(args) -> int:
    client = make_client(load_config())
    result = client.threat_detection(args.window_hours)

    if args.json:
        emit(result, True)
    else:
        print(f"Window: last {result['window_hours']}h  ({result['events_analyzed']} events, "
              f"baseline {result['baseline_events']})")
        if not result["sufficient_history"]:
            print("\n  INSUFFICIENT HISTORY — comparative detectors were skipped.")
        print()
        for signal in result["signals"]:
            print(f"  [{signal['severity']:8s} conf:{signal['confidence']:6s}] "
                  f"{signal['signal_id']} {signal['title']}")
            print(f"      {signal['detail']}")
            # Printed every time, never behind a flag: a signal without its
            # innocent reading beside it gets read as an accusation.
            print(f"      Likely benign: {signal['benign_explanation']}")
            print(f"      Suggested:     {signal['recommendation']}\n")
        if not result["signals"]:
            print("  No signals.\n")
        print(f"  {result['summary']}\n")
        print(f"  {result['coverage_note']}")

    # Exit 2 on a high/critical signal so CI can gate on it — but only on
    # severity, never on the AI narrative, which is advisory prose.
    serious = [s for s in result["signals"] if s["severity"] in ("high", "critical")]
    return EXIT_FINDINGS if serious else EXIT_OK


def cmd_secret(args) -> int:
    client = make_client(load_config())

    if args.secret_command == "set":
        value = Path(args.file).read_bytes() if args.file else sys.stdin.buffer.read()
        if not value:
            raise SystemExit("Refusing to store an empty value.")
        record = client.put_secret(args.name, value, args.description)
        emit(record, args.json) or print(f"Stored {args.name} v{record['version']}")
        return EXIT_OK

    if args.secret_command == "get":
        value = client.reveal_secret(args.name, args.version)
        if args.out:
            Path(args.out).write_bytes(value)
            print(f"Wrote {args.name} -> {args.out}", file=sys.stderr)
        else:
            # Raw bytes to stdout with no trailing newline, so
            # `export TOKEN=$(qopanza secret get ...)` gets the value and not
            # the value plus whitespace.
            sys.stdout.buffer.write(value)
        return EXIT_OK

    if args.secret_command == "list":
        secrets = client.list_secrets()
        if args.json:
            emit(secrets, True)
        elif not secrets:
            print("No secrets stored.")
        else:
            for secret in secrets:
                reads = f"{secret['access_count']} read(s)"
                print(f"  {secret['name']:40s} v{secret['version']:<4d} {secret['status']:10s} {reads}")
        return EXIT_OK

    if args.secret_command == "versions":
        versions = client.list_secret_versions(args.name)
        if args.json:
            emit(versions, True)
        else:
            for version in versions:
                print(f"  v{version['version']:<4d} {version['status']:11s} {version['created_at']}")
        return EXIT_OK

    if args.secret_command == "rollback":
        record = client.rollback_secret(args.name, args.version)
        emit(record, args.json) or print(
            f"Restored {args.name} v{args.version} as v{record['version']}"
        )
        return EXIT_OK

    if args.secret_command == "destroy":
        result = client.destroy_secret(args.name)
        emit(result, args.json) or print(
            f"Destroyed {result['versions_destroyed']} version(s) of {args.name}. {result['detail']}"
        )
        return EXIT_OK

    return EXIT_ERROR


def cmd_cert(args) -> int:
    client = make_client(load_config())

    if args.cert_command == "ca":
        certificate = client.create_certificate_authority(
            args.common_name, args.organization, args.valid_days
        )
        if args.json:
            emit(certificate, True)
        else:
            print(f"Created CA {certificate['common_name']} ({certificate['algorithm']})")
            print(f"  serial {certificate['serial_number']}, expires {certificate['not_after']}")
            print(f"\n{certificate['trust_note']}\n")
        _write_pair(args, certificate)
        return EXIT_OK

    if args.cert_command == "issue":
        certificate = client.issue_certificate(
            args.common_name, args.dns, args.organization, args.valid_days
        )
        if args.json:
            emit(certificate, True)
        else:
            print(f"Issued {certificate['common_name']} until {certificate['not_after']}")
            print(f"\n{certificate['trust_note']}\n")
        _write_pair(args, certificate)
        return EXIT_OK

    if args.cert_command == "list":
        certificates = client.list_certificates()
        if args.json:
            emit(certificates, True)
        elif not certificates:
            print("No certificates. Create a CA first: qopanza cert ca --common-name '<name>'")
        else:
            for certificate in certificates:
                print(
                    f"  {certificate['kind']:5s} {certificate['common_name']:35s} "
                    f"{certificate['status']:8s} expires {certificate['not_after'][:10]}"
                )
        return EXIT_OK

    if args.cert_command == "verify":
        result = client.verify_certificate(args.certificate_id)
        if args.json:
            emit(result, True)
        else:
            print(f"  signature valid: {result['signature_valid']}")
            print(f"  expired:         {result['expired']}")
            print(f"  revoked:         {result['revoked']}")
            print(f"\n{result['checked']}")
        # A certificate that fails any of the three is a finding, not a
        # successful check — CI needs to be able to tell.
        broken = (not result["signature_valid"]) or result["expired"] or result["revoked"]
        return EXIT_FINDINGS if broken else EXIT_OK

    if args.cert_command == "revoke":
        certificate = client.revoke_certificate(args.certificate_id, args.reason)
        emit(certificate, args.json) or print(
            f"Revoked {certificate['common_name']} ({args.reason}).\n"
            "Note: this platform records the revocation but publishes no CRL or OCSP, "
            "so rotate the affected service's certificate as well."
        )
        return EXIT_OK

    return EXIT_ERROR


def _write_pair(args, certificate: dict) -> None:
    """Save cert and key if asked. The private key is in the response once
    and never again, so losing it means reissuing."""
    if getattr(args, "cert_out", None):
        Path(args.cert_out).write_text(certificate["certificate_pem"])
        print(f"  certificate -> {args.cert_out}", file=sys.stderr)
    if getattr(args, "key_out", None) and certificate.get("private_key_pem"):
        target = Path(args.key_out)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(certificate["private_key_pem"])
        print(f"  private key -> {target} (mode 0600)", file=sys.stderr)


def cmd_zk(args) -> int:
    """Zero-knowledge commands. Everything except `register` runs entirely
    locally — no network call, no credentials needed — which is the whole
    point: the private key must never reach anything but this machine."""
    from qopanza import zk

    if args.zk_command == "keygen":
        keypair = zk.generate_keypair(args.algorithm)
        path = zk.save_keypair(keypair, args.out)
        if args.json:
            emit({"algorithm": keypair.algorithm, "public_key": keypair.public_b64(), "path": str(path)}, True)
        else:
            print(f"Generated {keypair.algorithm} keypair -> {path} (mode 0600)")
            print("")
            print("  There is no escrow. Back this file up somewhere you control.")
            print("  If you lose it, data encrypted to this key is unrecoverable.")
            print("")
            print(f"  Register the public half:  qopanza zk register --key {path}")
        return EXIT_OK

    if args.zk_command == "register":
        keypair = zk.load_keypair(args.key)
        client = make_client(load_config())
        purpose = "signature" if keypair.algorithm == zk.SIG_ALGORITHM else "kem"
        registered = client.register_key(
            purpose=purpose,
            algorithm=keypair.algorithm,
            public_key=keypair.public_key,
            label=args.label,
            rotated_from_id=args.rotated_from,
        )
        if args.json:
            emit(registered, True)
        else:
            print(f"Registered public key {registered['id']} ({registered['algorithm']}, v{registered.get('version', 1)})")
            print("The platform holds the public half only and cannot decrypt or sign with it.")
        return EXIT_OK

    if args.zk_command == "encrypt":
        keypair = zk.load_keypair(args.key)
        data = Path(args.infile).read_bytes() if args.infile else sys.stdin.buffer.read()
        envelope = zk.encrypt(keypair.public_key, data)
        if args.out:
            Path(args.out).write_text(envelope.to_json() + "\n")
            print(f"Encrypted {len(data)} bytes -> {args.out}", file=sys.stderr)
        else:
            print(envelope.to_json())
        return EXIT_OK

    if args.zk_command == "decrypt":
        keypair = zk.load_keypair(args.key)
        text = Path(args.infile).read_text() if args.infile else sys.stdin.read()
        plaintext = zk.decrypt(keypair.secret_key, zk.ZkEnvelope.from_json(text))
        if args.out:
            Path(args.out).write_bytes(plaintext)
            print(f"Decrypted -> {args.out}", file=sys.stderr)
        else:
            sys.stdout.buffer.write(plaintext)
        return EXIT_OK

    return EXIT_ERROR


def cmd_audit(args) -> int:
    client = make_client(load_config())

    if args.verify:
        result = client.verify_audit_chain()
        if args.json:
            emit(result, True)
        else:
            status = "INTACT" if result["intact"] else "BROKEN"
            print(f"Audit chain: {status}")
            print(f"  checked   {result['entries_checked']}")
            print(f"  verified  {result['entries_verified']}")
            if result["entries_unchained"]:
                print(f"  unchained {result['entries_unchained']} (predate hash chaining)")
            if result["broken_entry_ids"]:
                print(f"  BROKEN    {len(result['broken_entry_ids'])} entries")
        return EXIT_OK if result["intact"] else EXIT_FINDINGS

    entries = client.list_audit_log(limit=args.limit)
    if args.json:
        emit(entries, True)
    else:
        for entry in entries:
            print(f"  {entry['created_at'][:19]}  {entry['action']:24s} {entry.get('detail') or ''}")
    return EXIT_OK


def cmd_migrate(args) -> int:
    client = make_client(load_config())

    if args.plan:
        plan = client.create_migration_plan(name=args.name)
        if args.json:
            emit(plan, True)
            return EXIT_OK
        print(f"Migration plan {plan['id'][:8]}  '{plan['name']}'")
        print(f"  total items      {plan['total_items']}")
        print(f"  automatable      {plan['automatable_items']}  (platform can do these)")
        print(f"  manual           {plan['manual_items']}  (need your infrastructure changes)")
        print(f"  baseline risk    {plan['baseline_risk_score']}/100")

        items = client.list_migration_plan_items(plan["id"])
        if items:
            print("\n  Plan:")
            for item in items[:25]:
                tag = "auto  " if item["automatable"] else "manual"
                print(f"    [{tag}] {item['current_algorithm']:9s} -> {item['target_algorithm']}")
                print(f"             {item['location']}")
        return EXIT_OK

    progress = client.migration_progress()
    if args.json:
        emit(progress, True)
    else:
        print(f"Migration progress: {progress['completed_items']}/{progress['total_items']} "
              f"({progress['percent_complete']}%) across {progress['plans']} plan(s)")
    return EXIT_OK


def cmd_compliance(args) -> int:
    client = make_client(load_config())
    report = client.compliance_report()
    if args.json:
        emit(report, True)
        return EXIT_OK

    print("COMPLIANCE")
    for framework in report["frameworks"]:
        print(f"\n  {framework['framework']}")
        print(f"    {framework['score']}%  ({framework['checks_passed']}/{framework['checks_total']} checks)")
        for check in framework["checks"]:
            mark = "PASS" if check["status"] == "passed" else "FAIL"
            print(f"      [{mark}] {check['control_id']:8s} {check['title']}")
            if check["status"] != "passed" and check.get("remediation"):
                print(f"             -> {check['remediation']}")
    print(f"\n  {report['disclaimer']}")
    return EXIT_OK


# ---- argument parsing ------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="qopanza", description="Qopanza API command line")
    parser.add_argument("--json", action="store_true", help="Emit raw JSON instead of a table")
    sub = parser.add_subparsers(dest="command", required=True)

    p_login = sub.add_parser("login", help="Store API credentials")
    p_login.add_argument("--api-key")
    p_login.add_argument("--base-url")
    p_login.set_defaults(func=cmd_login)

    p_scan = sub.add_parser("scan", help="Scan code, a TLS endpoint, or a repository")
    p_scan.add_argument("path", nargs="?", default=".", help="Path to scan (default: .)")
    p_scan.add_argument("--tls", metavar="HOST[:PORT]", help="Probe a live TLS endpoint instead")
    p_scan.add_argument("--repository", metavar="URL", help="Clone and scan a Git repository")
    p_scan.add_argument("--branch")
    p_scan.add_argument(
        "--fail-on",
        choices=_SEVERITY_ORDER,
        help="Exit 2 if any finding is at or above this severity (for CI gating)",
    )
    p_scan.set_defaults(func=cmd_scan)

    sub.add_parser("posture", help="Quantum risk score").set_defaults(func=cmd_posture)
    sub.add_parser("inventory", help="Cryptographic inventory").set_defaults(func=cmd_inventory)

    p_key = sub.add_parser("key", help="Key operations")
    key_sub = p_key.add_subparsers(dest="key_command", required=True)
    p_key_create = key_sub.add_parser("create")
    p_key_create.add_argument("--purpose", default="kem", choices=["kem", "signature", "hybrid_kem"])
    p_key_create.add_argument("--label")
    p_key_rotate = key_sub.add_parser("rotate")
    p_key_rotate.add_argument("key_id")
    p_key_versions = key_sub.add_parser("versions")
    p_key_versions.add_argument("key_id")
    p_key.set_defaults(func=cmd_key)

    p_audit = sub.add_parser("audit", help="Audit log")
    p_audit.add_argument("--verify", action="store_true", help="Verify the tamper-evident hash chain")
    p_audit.add_argument("--limit", type=int, default=20)
    p_audit.set_defaults(func=cmd_audit)

    p_migrate = sub.add_parser("migrate", help="Migration planning")
    p_migrate.add_argument("--plan", action="store_true", help="Generate a new plan")
    p_migrate.add_argument("--name", default="Quantum-safe migration")
    p_migrate.set_defaults(func=cmd_migrate)

    sub.add_parser("compliance", help="Compliance report").set_defaults(func=cmd_compliance)

    p_threats = sub.add_parser(
        "threats", help="Behavioural anomalies in this account's audit history"
    )
    p_threats.add_argument("--window-hours", dest="window_hours", type=int, default=24)
    p_threats.set_defaults(func=cmd_threats)

    p_secret = sub.add_parser("secret", help="Versioned secrets, sealed with post-quantum keys")
    secret_sub = p_secret.add_subparsers(dest="secret_command", required=True)

    p_secret_set = secret_sub.add_parser("set", help="Store a new version (stdin, or --file)")
    p_secret_set.add_argument("name")
    p_secret_set.add_argument("--file", help="Read the value from this file instead of stdin")
    p_secret_set.add_argument("--description")

    p_secret_get = secret_sub.add_parser("get", help="Reveal a value")
    p_secret_get.add_argument("name")
    p_secret_get.add_argument("--version", type=int)
    p_secret_get.add_argument("--out", help="Write to this file instead of stdout")

    secret_sub.add_parser("list", help="List secrets (metadata only)")

    p_secret_versions = secret_sub.add_parser("versions", help="Version history")
    p_secret_versions.add_argument("name")

    p_secret_rollback = secret_sub.add_parser("rollback", help="Restore an earlier version")
    p_secret_rollback.add_argument("name")
    p_secret_rollback.add_argument("--version", type=int, required=True)

    p_secret_destroy = secret_sub.add_parser("destroy", help="Wipe every version's value")
    p_secret_destroy.add_argument("name")

    p_secret.set_defaults(func=cmd_secret)

    p_cert = sub.add_parser("cert", help="Internal PKI: ML-DSA-65 X.509 certificates")
    cert_sub = p_cert.add_subparsers(dest="cert_command", required=True)

    p_cert_ca = cert_sub.add_parser("ca", help="Create this account's internal root CA")
    p_cert_ca.add_argument("--common-name", dest="common_name", required=True)
    p_cert_ca.add_argument("--organization")
    p_cert_ca.add_argument("--valid-days", dest="valid_days", type=int, default=1825)

    p_cert_issue = cert_sub.add_parser("issue", help="Issue a leaf certificate")
    p_cert_issue.add_argument("--common-name", dest="common_name", required=True)
    p_cert_issue.add_argument("--dns", action="append", help="Subject alternative name (repeatable)")
    p_cert_issue.add_argument("--organization")
    p_cert_issue.add_argument("--valid-days", dest="valid_days", type=int, default=90)

    cert_sub.add_parser("list", help="List certificates")

    p_cert_verify = cert_sub.add_parser("verify", help="Check signature, expiry and revocation")
    p_cert_verify.add_argument("certificate_id")

    p_cert_revoke = cert_sub.add_parser("revoke", help="Record a revocation")
    p_cert_revoke.add_argument("certificate_id")
    p_cert_revoke.add_argument("--reason", default="unspecified")

    # Only the two subcommands that actually produce material take these.
    for issuing_parser in (p_cert_ca, p_cert_issue):
        issuing_parser.add_argument("--cert-out", dest="cert_out", help="Write the certificate PEM here")
        issuing_parser.add_argument(
            "--key-out",
            dest="key_out",
            help="Write the private key here (0600). It is returned once and never again.",
        )

    p_cert.set_defaults(func=cmd_cert)

    p_zk = sub.add_parser(
        "zk",
        help="Zero-knowledge mode: keys and encryption that never leave this machine",
    )
    zk_sub = p_zk.add_subparsers(dest="zk_command", required=True)

    p_zk_keygen = zk_sub.add_parser("keygen", help="Generate a keypair locally")
    p_zk_keygen.add_argument("--algorithm", default="ML-KEM-768", choices=["ML-KEM-768", "ML-DSA-65"])
    p_zk_keygen.add_argument("--out", default="qopanza-key.json", help="Where to write the keypair (0600)")

    p_zk_register = zk_sub.add_parser("register", help="Send the PUBLIC half to the platform")
    p_zk_register.add_argument("--key", required=True, help="Key file from 'qopanza zk keygen'")
    p_zk_register.add_argument("--label")
    p_zk_register.add_argument("--rotated-from", dest="rotated_from", help="Chain onto an existing key id")

    p_zk_encrypt = zk_sub.add_parser("encrypt", help="Encrypt locally (stdin, or --in)")
    p_zk_encrypt.add_argument("--key", required=True)
    p_zk_encrypt.add_argument("--in", dest="infile")
    p_zk_encrypt.add_argument("--out")

    p_zk_decrypt = zk_sub.add_parser("decrypt", help="Decrypt locally (stdin, or --in)")
    p_zk_decrypt.add_argument("--key", required=True)
    p_zk_decrypt.add_argument("--in", dest="infile")
    p_zk_decrypt.add_argument("--out")

    p_zk.set_defaults(func=cmd_zk)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except QopanzaAPIError as exc:
        print(f"API error [{exc.status_code}]: {exc.detail}", file=sys.stderr)
        return EXIT_ERROR
    except httpx.TimeoutException:
        base_url = resolve_base_url(load_config())
        print(f"Timed out talking to {base_url}.", file=sys.stderr)
        return EXIT_ERROR
    except httpx.TransportError as exc:
        # The first thing a new install can hit, so it gets a sentence
        # rather than a stack trace. Before this, `qopanza scan .` on a
        # machine that could not reach the API printed seventy lines of
        # httpx internals — which is not an error message, it is a crash,
        # and it read as a broken package rather than a wrong address.
        #
        # TransportError is the base class for connect/read/write/proxy
        # failures, so this covers DNS, refused connections and TLS
        # without enumerating them.
        base_url = resolve_base_url(load_config())
        print(f"Cannot reach the Qopanza API at {base_url}", file=sys.stderr)
        print(f"  ({type(exc).__name__}: {exc})", file=sys.stderr)
        if "localhost" in base_url or "127.0.0.1" in base_url:
            # Almost always a config file written by an older version,
            # which pinned localhost whether or not you asked for it.
            print(
                f"\nThat is a local address, so this is looking for a backend on your\n"
                f"own machine. If you meant the hosted API, repoint it:\n"
                f"\n    qopanza login --base-url {DEFAULT_BASE_URL}\n",
                file=sys.stderr,
            )
        else:
            print(
                "\nCheck your network, or set a different endpoint with\n"
                "QOPANZA_BASE_URL or 'qopanza login --base-url ...'.",
                file=sys.stderr,
            )
        return EXIT_ERROR
    except SystemExit as exc:
        if isinstance(exc.code, str):
            print(exc.code, file=sys.stderr)
            return EXIT_ERROR
        return int(exc.code or 0)
    except KeyboardInterrupt:  # pragma: no cover
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
