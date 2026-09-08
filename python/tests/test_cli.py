"""qopanza CLI: argument parsing, config precedence, and CI exit codes.

The HTTP layer is faked at the client boundary, so these run without a
server — the same approach the TypeScript/C#/C++ SDK suites use.
"""

import json
from types import SimpleNamespace

import pytest

from qopanza import cli


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    """Never touch the developer's real ~/.config/qopanza/config.json."""
    monkeypatch.setattr(cli, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.delenv("QOPANZA_API_KEY", raising=False)
    monkeypatch.delenv("QOPANZA_BASE_URL", raising=False)


class FakeClient:
    def __init__(self, **responses):
        self._responses = responses
        self.calls: list[str] = []

    def __getattr__(self, name):
        def call(*args, **kwargs):
            self.calls.append(name)
            value = self._responses.get(name)
            if value is None:
                raise AssertionError(f"FakeClient has no canned response for {name}")
            return value

        return call


def run(monkeypatch, argv, client) -> int:
    monkeypatch.setattr(cli, "make_client", lambda config: client)
    return cli.main(argv)


# ---- config ---------------------------------------------------------------


def test_login_saves_credentials(tmp_path, capsys):
    code = cli.main(["login", "--api-key", "qsk_test", "--base-url", "http://localhost:8000"])
    assert code == cli.EXIT_OK
    saved = json.loads(cli.CONFIG_PATH.read_text())
    assert saved["api_key"] == "qsk_test"
    assert saved["base_url"] == "http://localhost:8000"


def test_config_file_is_not_world_readable():
    """It holds an API key; treat it like an SSH key."""
    cli.main(["login", "--api-key", "qsk_secret"])
    mode = cli.CONFIG_PATH.stat().st_mode & 0o777
    assert mode == 0o600


def test_environment_overrides_config_file(monkeypatch):
    """CI injects credentials via env; they must win over a stale file."""
    cli.main(["login", "--api-key", "from_file"])
    monkeypatch.setenv("QOPANZA_API_KEY", "from_env")
    assert cli.load_config()["api_key"] == "from_env"


def test_missing_credentials_is_a_clear_error(monkeypatch, capsys):
    code = cli.main(["posture"])
    assert code == cli.EXIT_ERROR
    assert "Not logged in" in capsys.readouterr().err


# ---- severity gating -------------------------------------------------------


@pytest.mark.parametrize(
    "severity,threshold,expected",
    [
        ("critical", "high", True),
        ("high", "high", True),
        ("medium", "high", False),
        ("info", "low", False),
        ("low", "low", True),
    ],
)
def test_severity_threshold_comparison(severity, threshold, expected):
    assert cli.severity_at_least(severity, threshold) is expected


def test_unknown_severity_does_not_trip_the_gate():
    """An unrecognised severity must not silently fail a build."""
    assert cli.severity_at_least("bogus", "high") is False


# ---- scan exit codes (the CI contract) -------------------------------------


_CLEAN_SCAN = {
    "id": "scan-1",
    "status": "completed",
    "target": ".",
    "assets_found": 1,
    "quantum_vulnerable": 0,
    "quantum_safe": 1,
    "risk_score": 100,
}
_DIRTY_SCAN = {**_CLEAN_SCAN, "quantum_vulnerable": 1, "risk_score": 30}


def test_clean_scan_exits_zero(monkeypatch, tmp_path):
    (tmp_path / "ok.py").write_text("pq = 'ML-KEM-768'")
    client = FakeClient(scan_code=_CLEAN_SCAN, list_scan_assets=[])
    assert run(monkeypatch, ["scan", str(tmp_path), "--fail-on", "high"], client) == cli.EXIT_OK


def test_findings_above_threshold_exit_two(monkeypatch, tmp_path):
    (tmp_path / "bad.py").write_text("key = RSA-2048")
    assets = [{"severity": "high", "algorithm": "RSA", "location": "bad.py",
               "line_number": 1, "quantum_status": "vulnerable"}]
    client = FakeClient(scan_code=_DIRTY_SCAN, list_scan_assets=assets)
    assert run(monkeypatch, ["scan", str(tmp_path), "--fail-on", "high"], client) == cli.EXIT_FINDINGS


def test_findings_below_threshold_exit_zero(monkeypatch, tmp_path):
    (tmp_path / "bad.py").write_text("aes = AES-128")
    assets = [{"severity": "medium", "algorithm": "AES", "location": "bad.py",
               "line_number": 1, "quantum_status": "weak"}]
    client = FakeClient(scan_code=_DIRTY_SCAN, list_scan_assets=assets)
    assert run(monkeypatch, ["scan", str(tmp_path), "--fail-on", "critical"], client) == cli.EXIT_OK


def test_without_fail_on_findings_do_not_fail_the_build(monkeypatch, tmp_path):
    """Reporting mode: an existing estate shouldn't block every PR on day one."""
    (tmp_path / "bad.py").write_text("key = RSA-2048")
    assets = [{"severity": "critical", "algorithm": "MD5", "location": "bad.py",
               "line_number": 1, "quantum_status": "weak"}]
    client = FakeClient(scan_code=_DIRTY_SCAN, list_scan_assets=assets)
    assert run(monkeypatch, ["scan", str(tmp_path)], client) == cli.EXIT_OK


def test_failed_scan_exits_error_not_success(monkeypatch, tmp_path):
    """A scan that couldn't run must never read as a clean build."""
    (tmp_path / "x.py").write_text("x = 1")
    failed = {**_CLEAN_SCAN, "status": "failed", "error": "unreachable", "risk_score": None}
    client = FakeClient(scan_code=failed, list_scan_assets=[])
    assert run(monkeypatch, ["scan", str(tmp_path)], client) == cli.EXIT_ERROR


def test_nonexistent_path_is_an_error(monkeypatch):
    client = FakeClient()
    assert run(monkeypatch, ["scan", "/no/such/path"], client) == cli.EXIT_ERROR


# ---- other commands --------------------------------------------------------


def test_audit_verify_exits_two_when_chain_broken(monkeypatch):
    broken = {"intact": False, "entries_checked": 3, "entries_verified": 2,
              "entries_unchained": 0, "broken_entry_ids": ["e1"]}
    client = FakeClient(verify_audit_chain=broken)
    assert run(monkeypatch, ["audit", "--verify"], client) == cli.EXIT_FINDINGS


def test_audit_verify_exits_zero_when_intact(monkeypatch):
    intact = {"intact": True, "entries_checked": 3, "entries_verified": 3,
              "entries_unchained": 0, "broken_entry_ids": []}
    client = FakeClient(verify_audit_chain=intact)
    assert run(monkeypatch, ["audit", "--verify"], client) == cli.EXIT_OK


def test_migrate_plan_reports_automatable_split(monkeypatch, capsys):
    plan = {"id": "plan-1", "name": "Q1", "total_items": 3, "automatable_items": 1,
            "manual_items": 2, "completed_items": 0, "baseline_risk_score": 40}
    items = [{"automatable": True, "current_algorithm": "ML-KEM-768",
              "target_algorithm": "X25519+ML-KEM-768", "location": "platform key"},
             {"automatable": False, "current_algorithm": "RSA",
              "target_algorithm": "ML-DSA-65", "location": "app.py"}]
    client = FakeClient(create_migration_plan=plan, list_migration_plan_items=items)
    assert run(monkeypatch, ["migrate", "--plan"], client) == cli.EXIT_OK

    out = capsys.readouterr().out
    assert "automatable      1" in out
    assert "manual           2" in out


def test_json_flag_emits_parseable_output(monkeypatch, capsys):
    posture = {"score": 72, "quantum_risk": "medium", "total_assets": 10,
               "vulnerable_assets": 3, "pqc_assets": 7, "unknown_assets": 0,
               "category_scores": {}, "top_risks": [], "recommended_actions": []}
    client = FakeClient(security_posture=posture)
    run(monkeypatch, ["--json", "posture"], client)
    assert json.loads(capsys.readouterr().out)["score"] == 72


def test_scan_skips_vendor_directories(monkeypatch, tmp_path):
    """node_modules would otherwise dominate every scan."""
    (tmp_path / "app.py").write_text("key = RSA-2048")
    vendor = tmp_path / "node_modules" / "pkg"
    vendor.mkdir(parents=True)
    (vendor / "index.js").write_text("crypto = RSA-4096")

    captured = {}

    class CapturingClient(FakeClient):
        def scan_code(self, filename, content):
            captured["content"] = content
            return _CLEAN_SCAN

    client = CapturingClient(list_scan_assets=[])
    run(monkeypatch, ["scan", str(tmp_path)], client)
    assert "app.py" in captured["content"]
    assert "node_modules" not in captured["content"]
