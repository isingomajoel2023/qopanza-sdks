# qopanza (Python)

Python client for the Qopanza API — post-quantum encryption and
signing (ML-KEM, ML-DSA, SLH-DSA) behind one API call, plus the `qopanza`
CLI. Python 3.9+, one runtime dependency (`httpx`).

## Install

```bash
pip install qopanza
```

Optional extras:

```bash
pip install 'qopanza[zk]'    # zero-knowledge: local PQC, needs liboqs
pip install 'qopanza[test]'  # to run the test suite
```

From a checkout of this repo instead:

```bash
cd sdks/python && pip install -e .
```

## Usage

### Start from nothing

`signup` is the one call that works without credentials, and it adopts
the returned key onto the client so the next call is authenticated.

```python
from qopanza import QopanzaClient

with QopanzaClient() as client:
    account = client.signup("you@example.com", "a-real-password")
    print(account["api_key"])   # shown once — store it now

    enc = client.encrypt(plaintext=b"customer sensitive information")
    assert client.decrypt(**enc) == b"customer sensitive information"
```

The API key is returned rather than hidden inside the client on purpose:
it is issued once and cannot be retrieved again, so a version of this
that quietly kept it would lose it when the process exited.

### One-line encryption (no cryptography knowledge required)

With a key you already have. Don't create or manage keys at all — the
platform provisions a managed key for your account on first use and
reuses it.

```python
from qopanza import QopanzaClient

with QopanzaClient(api_key=api_key) as client:
    enc = client.encrypt(plaintext=b"customer sensitive information")
    data = client.decrypt(**enc)
    assert data == b"customer sensitive information"
```

### Zero-knowledge: keys that never leave your machine

Install with the `zk` extra (`pip install 'qopanza[zk]'`) and the
private key is generated locally and stays there. The platform holds the
public half, so it can inventory, version and police the key — and cannot
decrypt with it.

```python
from qopanza import QopanzaClient, zk

keypair = zk.generate_keypair()                        # local, never uploaded
envelope = zk.encrypt(keypair.public_key, b"secret")   # local
assert zk.decrypt(keypair.secret_key, envelope) == b"secret"

with QopanzaClient(api_key=api_key) as client:
    client.register_key(
        purpose="kem", algorithm=keypair.algorithm, public_key=keypair.public_key
    )
```

**There is no escrow.** Lose the private key and the data is unrecoverable
— that is the guarantee, not a gap. `/encrypt`, `/decrypt` and `/sign`
return 409 for these keys rather than quietly routing your plaintext
through the server. See `docs/zero-knowledge.md`.

### Full control

```python
from qopanza import QopanzaClient

with QopanzaClient(api_key=api_key) as client:
    # Generate a KEM keypair
    key = client.create_key(purpose="kem", label="order-service-kem")

    # Encrypt / decrypt
    enc = client.encrypt(key_id=key["id"], plaintext=b"hello quantum-safe world")
    plaintext = client.decrypt(**enc)
    assert plaintext == b"hello quantum-safe world"

    # Signatures
    sig_key = client.create_key(purpose="signature", label="order-service-sig")
    signed = client.sign(key_id=sig_key["id"], message=b"order-42-confirmed")
    assert client.verify(
        key_id=sig_key["id"], message=b"order-42-confirmed", signature=signed["signature"]
    )

    # AI security analysis
    report = client.analyze(
        context={"algorithms_in_use": ["RSA-2048"], "key_reuse_count": 3}
    )
    for finding in report["findings"]:
        print(finding["severity"], finding["title"])
```

See `examples/quickstart.py` for a runnable script.

## `qopanza` command line

Installing the SDK also installs the `qopanza` CLI.

```bash
qopanza login                       # store credentials (chmod 600)
qopanza scan .                      # scan a directory
qopanza scan --tls api.example.com  # probe a live TLS endpoint
qopanza scan --repository https://github.com/org/repo
qopanza posture                     # quantum risk score + category breakdown
qopanza inventory                   # cryptographic inventory
qopanza key create --purpose hybrid_kem
qopanza key rotate <key-id>         # old versions still decrypt
qopanza audit --verify              # verify the audit hash chain
qopanza migrate --plan              # generate a migration plan
qopanza compliance                  # control checks (not an audit result)

qopanza zk keygen --out key.json    # generate locally; nothing is uploaded
qopanza zk register --key key.json  # send the PUBLIC half only
qopanza zk encrypt --key key.json --in secrets.txt --out sealed.json
qopanza zk decrypt --key key.json --in sealed.json
```

`qopanza zk keygen/encrypt/decrypt` make no network calls and need no API
key at all.

Add `--json` to any command for machine-readable output.

Credentials come from `~/.config/qopanza/config.json` or, taking
precedence, `QOPANZA_API_KEY` / `QOPANZA_BASE_URL` — so CI can inject them
without writing anything to disk.

### Which API it talks to

`https://api.qopanza.com`, unless you say otherwise. Nothing to
configure for normal use.

To point it somewhere else — a local backend, or a staging
deployment — either persist it:

```bash
qopanza login --base-url http://localhost:8000
```

or set it per-invocation, which wins over the saved value:

```bash
QOPANZA_BASE_URL=http://localhost:8000 qopanza posture
```

`qopanza login` prints the endpoint it will use, so you can see which
one is in effect without opening the config file.

> **Upgrading from 0.1.0?** That release defaulted to
> `http://localhost:8000` and wrote it into your config file on login,
> so every command failed with a connection error unless you were also
> running the backend. Upgrading alone will not clear the saved value —
> run `qopanza login --base-url https://api.qopanza.com` once, or delete
> `~/.config/qopanza/config.json` and log in again.

### Using it as a CI gate

```bash
qopanza scan . --fail-on high
```

Exit codes: `0` clean, `1` the scan could not run, `2` findings at or
above the threshold. `1` and `2` are deliberately distinct — a scan that
failed to run must never be read as a clean build. See
`integrations/README.md` for ready-made GitHub Actions and GitLab CI
configurations, and for advice on rolling the gate out without blocking
every PR on day one.
