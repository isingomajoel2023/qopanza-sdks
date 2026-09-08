"""Zero-knowledge mode: post-quantum encryption that runs on your machine.

Everything here happens locally. The private key is generated on this
machine, stays on this machine, and is never sent anywhere — not to the
Qopanza API, not to us. The platform's role shrinks to what it can do
without secrets: hold the public key, version and expire it, apply your
organisation's policy, verify signatures, and keep the audit trail.

The trade, stated plainly because it is not reversible:

    There is no escrow. If you lose the private key, the data encrypted
    to it is gone. Nobody — including us — can recover it.

That is not a limitation to be engineered away; it is the guarantee. A
provider who can recover your data on request is a provider who can read
it. Choose this mode when that trade is the one you want.

Requires ``liboqs-python``; install with ``pip install qopanza[zk]``.
The import is deferred so that the rest of the SDK works without it, and
so a missing dependency produces a clear message rather than an
ImportError from three frames down.

Wire format (``ZkEnvelope``) is deliberately boring and self-describing:
ML-KEM-768 encapsulation to the recipient's public key, AES-256-GCM over
the payload under the resulting shared secret, 12-byte random nonce. The
same construction the platform-managed ``/v1/encrypt`` endpoint uses, so
the two are interoperable in one direction: anything encrypted here can be
decrypted by whoever holds the private key, and nowhere else.
"""

from __future__ import annotations

import base64
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

KEM_ALGORITHM = "ML-KEM-768"
SIG_ALGORITHM = "ML-DSA-65"
_NONCE_LEN = 12

_MISSING_LIBOQS = (
    "Zero-knowledge mode needs liboqs-python for local post-quantum crypto.\n"
    "  pip install 'qopanza[zk]'\n"
    "The first install builds native liboqs (needs cmake + a C compiler), or use the "
    "qopanza/python base image which ships it prebuilt."
)


class ZeroKnowledgeError(RuntimeError):
    """Local crypto could not be performed."""


def _oqs():
    try:
        import oqs  # type: ignore
    except ImportError as exc:  # pragma: no cover - depends on install
        raise ZeroKnowledgeError(_MISSING_LIBOQS) from exc
    return oqs


def _aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:  # pragma: no cover - depends on install
        raise ZeroKnowledgeError(
            "Zero-knowledge mode needs the 'cryptography' package for AES-256-GCM.\n"
            "  pip install 'qopanza[zk]'"
        ) from exc
    return AESGCM


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text)


@dataclass(frozen=True)
class ZkKeypair:
    """A locally generated keypair. ``secret_key`` never leaves this process
    unless you write it somewhere yourself."""

    algorithm: str
    public_key: bytes
    secret_key: bytes

    def public_b64(self) -> str:
        return b64e(self.public_key)


@dataclass(frozen=True)
class ZkEnvelope:
    """Everything needed to decrypt, and nothing that helps without the key."""

    algorithm: str
    ciphertext_kem: bytes
    nonce: bytes
    ciphertext: bytes

    def to_dict(self) -> dict[str, str]:
        return {
            "algorithm": self.algorithm,
            "ciphertext_kem": b64e(self.ciphertext_kem),
            "nonce": b64e(self.nonce),
            "ciphertext": b64e(self.ciphertext),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ZkEnvelope":
        missing = {"algorithm", "ciphertext_kem", "nonce", "ciphertext"} - set(data)
        if missing:
            raise ZeroKnowledgeError(f"Envelope is missing: {', '.join(sorted(missing))}")
        return cls(
            algorithm=data["algorithm"],
            ciphertext_kem=b64d(data["ciphertext_kem"]),
            nonce=b64d(data["nonce"]),
            ciphertext=b64d(data["ciphertext"]),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, text: str) -> "ZkEnvelope":
        return cls.from_dict(json.loads(text))


# ---- Key generation ---------------------------------------------------------


def generate_keypair(algorithm: str = KEM_ALGORITHM) -> ZkKeypair:
    """Generate a post-quantum keypair locally."""
    oqs = _oqs()
    if algorithm in (KEM_ALGORITHM,):
        with oqs.KeyEncapsulation(algorithm) as kem:
            public_key = kem.generate_keypair()
            return ZkKeypair(algorithm, public_key, kem.export_secret_key())
    if algorithm in (SIG_ALGORITHM,):
        with oqs.Signature(algorithm) as sig:
            public_key = sig.generate_keypair()
            return ZkKeypair(algorithm, public_key, sig.export_secret_key())
    raise ZeroKnowledgeError(
        f"Unsupported algorithm {algorithm!r}; expected {KEM_ALGORITHM} or {SIG_ALGORITHM}."
    )


# ---- Encrypt / decrypt ------------------------------------------------------


def encrypt(public_key: bytes, plaintext: bytes, algorithm: str = KEM_ALGORITHM) -> ZkEnvelope:
    """Encrypt to a public key. Needs no secret, so it is safe to do this
    anywhere — including on a machine that will never decrypt."""
    oqs = _oqs()
    AESGCM = _aesgcm()
    with oqs.KeyEncapsulation(algorithm) as kem:
        ciphertext_kem, shared_secret = kem.encap_secret(public_key)
    nonce = os.urandom(_NONCE_LEN)
    return ZkEnvelope(
        algorithm=algorithm,
        ciphertext_kem=ciphertext_kem,
        nonce=nonce,
        ciphertext=AESGCM(shared_secret).encrypt(nonce, plaintext, None),
    )


def decrypt(secret_key: bytes, envelope: ZkEnvelope) -> bytes:
    """Decrypt with the private key. This is the operation the platform
    cannot perform for you, by construction."""
    oqs = _oqs()
    AESGCM = _aesgcm()
    with oqs.KeyEncapsulation(envelope.algorithm, secret_key) as kem:
        shared_secret = kem.decap_secret(envelope.ciphertext_kem)
    try:
        return AESGCM(shared_secret).decrypt(envelope.nonce, envelope.ciphertext, None)
    except Exception as exc:  # noqa: BLE001 - any AEAD failure means the same thing
        raise ZeroKnowledgeError(
            "Decryption failed: wrong key, or the envelope was modified. AES-GCM "
            "authenticates the ciphertext, so a tampered payload fails here rather "
            "than returning corrupted plaintext."
        ) from exc


# ---- Sign / verify ----------------------------------------------------------


def sign(secret_key: bytes, message: bytes, algorithm: str = SIG_ALGORITHM) -> bytes:
    oqs = _oqs()
    with oqs.Signature(algorithm, secret_key) as sig:
        return sig.sign(message)


def verify(public_key: bytes, message: bytes, signature: bytes, algorithm: str = SIG_ALGORITHM) -> bool:
    oqs = _oqs()
    with oqs.Signature(algorithm) as sig:
        return bool(sig.verify(message, signature, public_key))


# ---- Key files --------------------------------------------------------------


def save_keypair(keypair: ZkKeypair, path: str | Path) -> Path:
    """Write a keypair to disk with 0600 permissions.

    Written owner-only *before* any secret bytes reach the file: creating
    it world-readable and chmod-ing afterwards leaves a window in which
    another local user can read the private key.
    """
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        {
            "algorithm": keypair.algorithm,
            "public_key": b64e(keypair.public_key),
            "secret_key": b64e(keypair.secret_key),
            "warning": (
                "This file contains a PRIVATE key. There is no escrow: if you lose it, "
                "data encrypted to the matching public key is unrecoverable. If someone "
                "else obtains it, they can read that data."
            ),
        },
        indent=2,
    )
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w") as handle:
        handle.write(payload + "\n")
    return target


def load_keypair(path: str | Path) -> ZkKeypair:
    source = Path(path).expanduser()
    if not source.exists():
        raise ZeroKnowledgeError(f"No key file at {source}")
    data = json.loads(source.read_text())
    for field in ("algorithm", "public_key", "secret_key"):
        if field not in data:
            raise ZeroKnowledgeError(f"Key file {source} is missing '{field}'.")
    return ZkKeypair(
        algorithm=data["algorithm"],
        public_key=b64d(data["public_key"]),
        secret_key=b64d(data["secret_key"]),
    )
