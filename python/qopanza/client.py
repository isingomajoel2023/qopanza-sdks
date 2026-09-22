"""Qopanza API Python SDK.

This client covers signup plus the crypto/analyze endpoints (keys,
encrypt, decrypt, sign, verify, analyze, scanning, secrets,
certificates). It does not cover billing, usage, support or webhook
management — those stay dashboard-only for now (see the repo README).

Start from nothing:

    from qopanza import QopanzaClient

    with QopanzaClient() as client:
        account = client.signup("you@example.com", "a-real-password")
        print(account["api_key"])   # shown once — store it now

        key = client.create_key(purpose="kem", label="my-service-kem-key")
        enc = client.encrypt(key_id=key["id"], plaintext=b"hello world")
        assert client.decrypt(**enc) == b"hello world"

Already have a key:

    client = QopanzaClient(api_key=key)

Running the backend yourself:

    client = QopanzaClient(base_url="http://localhost:8000", api_key=key)
"""

from __future__ import annotations

import base64
from typing import Any

import httpx


# The hosted API. This is the default because the overwhelmingly common
# case for an installed package is somebody talking to the service, not
# somebody running the backend on their own machine.
#
# It used to default to http://localhost:8000, which meant `pip install
# qopanza && qopanza login && qopanza scan .` ended in a connection
# refused against a server the user had never heard of. Anyone running
# the backend locally still passes base_url, or sets QOPANZA_BASE_URL.
#
# Defined once, here, and imported by the CLI. Before this there were
# three copies of the literal — client default, CLI client factory, CLI
# login — which is how they were able to be wrong together.
DEFAULT_BASE_URL = "https://api.qopanza.com"


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode())


class QopanzaAPIError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"[{status_code}] {detail}")


class QopanzaClient:
    """Synchronous client for the Qopanza API.

    Synchronous only. There is no async client in this package yet —
    an earlier version of this docstring pointed at an
    `async_client.py` that was never written. Under asyncio, call
    these methods through `asyncio.to_thread`.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        api_key: str | None = None,
        timeout: float = 15.0,
    ):
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(
            base_url=f"{self.base_url}/v1",
            headers={"X-API-Key": api_key} if api_key else {},
            timeout=timeout,
        )

    def _request(self, method: str, path: str, **kwargs) -> dict[str, Any]:
        resp = self._client.request(method, path, **kwargs)
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:  # noqa: BLE001
                detail = resp.text
            raise QopanzaAPIError(resp.status_code, detail)
        return resp.json()

    # -- Account ----------------------------------------------------------
    def signup(self, email: str, password: str) -> dict[str, Any]:
        """Create an account and adopt its API key for this client.

        This is the one call that works *without* credentials, so it is
        how a new user starts:

            with QopanzaClient() as client:
                account = client.signup("you@example.com", "a-real-password")
                print(account["api_key"])   # store this — shown once
                client.encrypt(plaintext=b"already authenticated")

        Two deliberate choices:

        **The full response is returned, not swallowed.** ``api_key`` is
        issued once and never retrievable again — if this method quietly
        kept it inside the client, the obvious usage would lose the key
        the moment the process exited. Returning it forces the caller to
        see it.

        **The key is also adopted onto this client**, so the next call
        works without constructing a second one. Both, not either.

        Raises QopanzaAPIError with status 409 if the email is
        already registered, or 429 if signup throttling has tripped
        (see SIGNUP_LIMIT_PER_WINDOW on the server).
        """
        result = self._request(
            "POST", "/accounts", json={"email": email, "password": password}
        )
        api_key = result.get("api_key")
        if api_key:
            self._client.headers["X-API-Key"] = api_key
        return result

    # -- Keys -----------------------------------------------------------
    def create_key(self, purpose: str, label: str | None = None) -> dict[str, Any]:
        """purpose: 'kem' or 'signature'"""
        return self._request("POST", "/keys", json={"purpose": purpose, "label": label})

    def get_key(self, key_id: str) -> dict[str, Any]:
        return self._request("GET", f"/keys/{key_id}")

    def register_key(
        self,
        purpose: str,
        algorithm: str,
        public_key: bytes,
        label: str | None = None,
        classical_public_key: bytes | None = None,
        expires_in_days: int | None = None,
        rotated_from_id: str | None = None,
    ) -> dict[str, Any]:
        """Register a public key you generated yourself (zero-knowledge mode).

        Only the public half is sent. The platform can then inventory,
        version and police this key, and verify signatures made with it,
        but it cannot decrypt or sign — it has no private material. Use
        `qopanza.zk` for the local operations.

        There is no escrow: keep the private key, or lose the data.
        """
        return self._request(
            "POST",
            "/keys/register",
            json={
                "purpose": purpose,
                "algorithm": algorithm,
                "public_key": _b64e(public_key),
                "classical_public_key": (
                    _b64e(classical_public_key) if classical_public_key else None
                ),
                "label": label,
                "expires_in_days": expires_in_days,
                "rotated_from_id": rotated_from_id,
            },
        )

    # -- Encrypt / Decrypt ------------------------------------------------
    def encrypt(self, key_id: str | None = None, plaintext: bytes = b"") -> dict[str, Any]:
        """Encrypt data.

        One-line form — no key management at all. The platform provisions a
        managed key for your account on first use and reuses it after:

            enc = client.encrypt(plaintext=b"customer sensitive information")
            data = client.decrypt(**enc)

        Or name a key you created yourself (unchanged from before):

            enc = client.encrypt(key_id=key["id"], plaintext=b"...")

        key_id stays the first parameter so existing positional callers keep
        working; pass plaintext as a keyword for the one-line form.
        """
        body: dict[str, Any] = {"plaintext": _b64e(plaintext)}
        if key_id is not None:
            body["key_id"] = key_id
        return self._request("POST", "/encrypt", json=body)

    def decrypt(
        self,
        key_id: str,
        ciphertext_kem: str,
        ciphertext_payload: str,
        nonce: str,
        **_ignore,
    ) -> bytes:
        result = self._request(
            "POST",
            "/decrypt",
            json={
                "key_id": key_id,
                "ciphertext_kem": ciphertext_kem,
                "ciphertext_payload": ciphertext_payload,
                "nonce": nonce,
            },
        )
        return _b64d(result["plaintext"])

    # -- Sign / Verify ----------------------------------------------------
    def sign(self, key_id: str, message: bytes) -> dict[str, Any]:
        return self._request(
            "POST", "/sign", json={"key_id": key_id, "message": _b64e(message)}
        )

    def verify(self, key_id: str, message: bytes, signature: str) -> bool:
        result = self._request(
            "POST",
            "/verify",
            json={"key_id": key_id, "message": _b64e(message), "signature": signature},
        )
        return result["valid"]

    # -- AI analysis --------------------------------------------------------
    def analyze(self, context: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/analyze", json={"context": context})

    # -- Scanner ------------------------------------------------------------
    def scan_code(self, filename: str, content: str) -> dict[str, Any]:
        """Scan source or manifest text for cryptographic usage."""
        return self._request("POST", "/scan/code", json={"filename": filename, "content": content})

    def scan_tls(self, host: str, port: int = 443) -> dict[str, Any]:
        """Probe a live TLS endpoint and inventory what it negotiates."""
        return self._request("POST", "/scan/tls", json={"host": host, "port": port})

    def scan_repository(self, repository_url: str, branch: str | None = None,
                        token: str | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"repository_url": repository_url}
        if branch:
            body["branch"] = branch
        if token:
            body["token"] = token
        return self._request("POST", "/scan/repository", json=body)

    def list_scans(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._request("GET", f"/scans?limit={limit}")

    def list_scan_assets(self, scan_id: str) -> list[dict[str, Any]]:
        return self._request("GET", f"/scans/{scan_id}/assets")

    def crypto_inventory(self) -> dict[str, Any]:
        return self._request("GET", "/inventory")

    def security_posture(self) -> dict[str, Any]:
        """Quantum risk score, category breakdown and recommended actions."""
        return self._request("GET", "/security/posture")

    # -- Key lifecycle ------------------------------------------------------
    def rotate_key(self, key_id: str) -> dict[str, Any]:
        """Create the next version of a key. Older versions stay able to
        decrypt, so this is safe to run on a schedule."""
        return self._request("POST", f"/keys/{key_id}/rotate")

    def list_key_versions(self, key_id: str) -> list[dict[str, Any]]:
        return self._request("GET", f"/keys/{key_id}/versions")

    def set_rotation_policy(self, key_id: str, rotation_period_days: int | None) -> dict[str, Any]:
        return self._request(
            "PATCH", f"/keys/{key_id}/rotation-policy",
            json={"rotation_period_days": rotation_period_days},
        )

    def revoke_key(self, key_id: str) -> dict[str, Any]:
        """Revoke a key version outright. Unlike rotation this is
        destructive: data still encrypted under it becomes unreadable."""
        return self._request("POST", f"/keys/{key_id}/revoke")

    # -- Audit --------------------------------------------------------------
    def list_audit_log(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._request("GET", f"/audit-log?limit={limit}")

    def verify_audit_chain(self) -> dict[str, Any]:
        """Verify the tamper-evident hash chain over this account's audit log."""
        return self._request("GET", "/audit-log/verify")

    # -- Migration ----------------------------------------------------------
    def create_migration_plan(self, name: str = "Quantum-safe migration") -> dict[str, Any]:
        return self._request("POST", "/migration/plans", json={"name": name})

    def list_migration_plan_items(self, plan_id: str) -> list[dict[str, Any]]:
        return self._request("GET", f"/migration/plans/{plan_id}/items")

    def approve_migration_plan(self, plan_id: str) -> dict[str, Any]:
        return self._request("POST", f"/migration/plans/{plan_id}/approve")

    def execute_migration_plan(self, plan_id: str) -> dict[str, Any]:
        """Execute the automatable items. Manual items are reported, never
        marked complete on your behalf."""
        return self._request("POST", f"/migration/plans/{plan_id}/execute")

    def migration_progress(self) -> dict[str, Any]:
        return self._request("GET", "/migration/progress")

    # -- Compliance ---------------------------------------------------------
    def compliance_report(self) -> dict[str, Any]:
        """Control checks against real account state. Not an audit result —
        read each framework's coverage_note before quoting the score."""
        return self._request("GET", "/compliance/report")

    def threat_detection(self, window_hours: int = 24) -> dict[str, Any]:
        """Behavioural anomalies in this account's own audit history.

        Anomalies, not threats. Every signal reports a confidence
        separately from severity and states the most likely benign cause —
        read it before escalating. An empty result means no detector
        fired, not that the account is safe.
        """
        return self._request("GET", f"/threat-detection?window_hours={window_hours}")

    # -- Secrets ------------------------------------------------------------
    #
    # These store and return plaintext through this platform, so the
    # platform can read them. That is inherent to a managed secrets store.
    # For values it must not be able to read, seal them locally with
    # `qopanza.zk` first and store the envelope here.

    def put_secret(self, name: str, value: bytes, description: str | None = None) -> dict[str, Any]:
        """Write a new version. The previous value becomes a superseded
        version you can still read and roll back to."""
        return self._request(
            "PUT",
            f"/secrets/{name}",
            json={"value": _b64e(value), "description": description},
        )

    def reveal_secret(self, name: str, version: int | None = None) -> bytes:
        path = f"/secrets/{name}/reveal" + (f"?version={version}" if version else "")
        return _b64d(self._request("POST", path)["value"])

    def list_secrets(self) -> list[dict[str, Any]]:
        """Metadata only — values are never returned by a listing."""
        return self._request("GET", "/secrets")

    def list_secret_versions(self, name: str) -> list[dict[str, Any]]:
        return self._request("GET", f"/secrets/{name}/versions")

    def rollback_secret(self, name: str, version: int) -> dict[str, Any]:
        return self._request("POST", f"/secrets/{name}/rollback?version={version}")

    def destroy_secret(self, name: str) -> dict[str, Any]:
        """Wipe every version's value. Metadata and access history survive
        so the audit trail outlives the deletion."""
        return self._request("DELETE", f"/secrets/{name}")

    # -- Certificates -------------------------------------------------------
    #
    # ML-DSA-65 X.509 for INTERNAL PKI. No public CA issues post-quantum
    # certificates and no browser trusts one — see docs/certificates.md.

    def create_certificate_authority(
        self, common_name: str, organization: str | None = None, valid_days: int = 1825
    ) -> dict[str, Any]:
        """Create this account's internal root CA. The private key is in
        the response and is not retrievable again."""
        return self._request(
            "POST",
            "/certificates/ca",
            json={
                "common_name": common_name,
                "organization": organization,
                "valid_days": valid_days,
            },
        )

    def issue_certificate(
        self,
        common_name: str,
        dns_names: list[str] | None = None,
        organization: str | None = None,
        valid_days: int = 90,
    ) -> dict[str, Any]:
        """Issue a leaf signed by the account CA. Capture `private_key_pem`
        from the response — it is never stored server-side."""
        return self._request(
            "POST",
            "/certificates",
            json={
                "common_name": common_name,
                "dns_names": dns_names,
                "organization": organization,
                "valid_days": valid_days,
            },
        )

    def list_certificates(self) -> list[dict[str, Any]]:
        return self._request("GET", "/certificates")

    def get_certificate(self, certificate_id: str) -> dict[str, Any]:
        return self._request("GET", f"/certificates/{certificate_id}")

    def verify_certificate(self, certificate_id: str) -> dict[str, Any]:
        """Signature, expiry and revocation reported separately — read
        `checked` for what this does not cover."""
        return self._request("GET", f"/certificates/{certificate_id}/verify")

    def revoke_certificate(self, certificate_id: str, reason: str = "unspecified") -> dict[str, Any]:
        """Records revocation here. There is no CRL or OCSP responder yet,
        so rotate the affected service's certificate too."""
        return self._request(
            "POST", f"/certificates/{certificate_id}/revoke", json={"reason": reason}
        )

    def close(self):
        self._client.close()

    def __enter__(self) -> "QopanzaClient":
        return self

    def __exit__(self, *exc):
        self.close()
