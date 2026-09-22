"""Run against a local `docker compose up` stack:

    python examples/quickstart.py

Signs up for a fresh account to get a real API key (this SDK covers the
crypto/analyze endpoints only — account signup isn't part of it yet, see
the client module docstring), then exercises encrypt/decrypt, sign/verify,
and the AI analysis endpoint.
"""

import os

import httpx

from qopanza import QopanzaClient

# Local by default, because this script signs up a throwaway account and
# that belongs on a stack you own. Point it elsewhere to run the same
# walkthrough against the hosted API:
#
#     QOPANZA_BASE_URL=https://api.qopanza.com python examples/quickstart.py
BASE_URL = os.environ.get("QOPANZA_BASE_URL", "http://localhost:8000")


def get_api_key() -> str:
    resp = httpx.post(
        f"{BASE_URL}/v1/accounts",
        json={"email": "quickstart@example.com", "password": "quickstart-password-1"},
    )
    if resp.status_code == 409:
        raise SystemExit(
            "Account already exists — this quickstart signs up fresh each run. "
            "Change the email above or delete the account first."
        )
    resp.raise_for_status()
    return resp.json()["api_key"]


def main():
    api_key = get_api_key()

    with QopanzaClient(base_url=BASE_URL, api_key=api_key) as client:
        print("== Key encapsulation (encrypt/decrypt) ==")
        kem_key = client.create_key(purpose="kem", label="quickstart-kem")
        print("Created KEM key:", kem_key["id"], kem_key["algorithm"], kem_key["backend"])

        enc = client.encrypt(key_id=kem_key["id"], plaintext=b"hello quantum-safe world")
        plaintext = client.decrypt(**enc)
        print("Round-trip OK:", plaintext == b"hello quantum-safe world")

        print("\n== Signatures ==")
        sig_key = client.create_key(purpose="signature", label="quickstart-sig")
        signed = client.sign(key_id=sig_key["id"], message=b"order-42-confirmed")
        valid = client.verify(
            key_id=sig_key["id"], message=b"order-42-confirmed", signature=signed["signature"]
        )
        print("Signature valid:", valid)

        print("\n== AI security analysis ==")
        report = client.analyze(
            context={
                "algorithms_in_use": ["RSA-2048"],
                "key_ages_days": [400, 20],
                "key_reuse_count": 3,
            }
        )
        print("Summary:", report["summary"])
        for finding in report["findings"]:
            print(f"  [{finding['severity']}] {finding['rule_id']}: {finding['title']}")


if __name__ == "__main__":
    main()
