"""Local zero-knowledge crypto and the `qopanza zk` commands.

These exercise real ML-KEM-768 and ML-DSA-65 through liboqs — there is no
point unit-testing a mock of the one thing that has to be genuinely
correct. When liboqs isn't installed the module is skipped rather than
faked, so a green run always means the real primitives were used.
"""

import json
import os
import stat

import pytest

from qopanza import cli, zk

pytest.importorskip("oqs", reason="zero-knowledge mode needs liboqs-python")
pytest.importorskip("cryptography", reason="zero-knowledge mode needs cryptography")


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.delenv("QOPANZA_API_KEY", raising=False)
    monkeypatch.delenv("QOPANZA_BASE_URL", raising=False)


# ---- the primitives --------------------------------------------------------


def test_encrypt_decrypt_roundtrip():
    keypair = zk.generate_keypair()
    envelope = zk.encrypt(keypair.public_key, b"customer sensitive information")
    assert zk.decrypt(keypair.secret_key, envelope) == b"customer sensitive information"


def test_key_sizes_match_fips_203():
    """ML-KEM-768: 1184-byte public key, 2400-byte secret key. Pinned so a
    backend swap that silently changed parameter set would be caught."""
    keypair = zk.generate_keypair()
    assert len(keypair.public_key) == 1184
    assert len(keypair.secret_key) == 2400


def test_a_different_key_cannot_decrypt():
    """The whole guarantee in one assertion."""
    mine = zk.generate_keypair()
    theirs = zk.generate_keypair()
    envelope = zk.encrypt(mine.public_key, b"private")

    with pytest.raises(zk.ZeroKnowledgeError):
        zk.decrypt(theirs.secret_key, envelope)


def test_tampered_ciphertext_fails_rather_than_returning_garbage():
    keypair = zk.generate_keypair()
    envelope = zk.encrypt(keypair.public_key, b"transfer $100")
    flipped = zk.ZkEnvelope(
        envelope.algorithm,
        envelope.ciphertext_kem,
        envelope.nonce,
        envelope.ciphertext[:-1] + bytes([envelope.ciphertext[-1] ^ 0x01]),
    )
    with pytest.raises(zk.ZeroKnowledgeError):
        zk.decrypt(keypair.secret_key, flipped)


def test_each_encryption_uses_a_fresh_nonce():
    """Reusing a nonce under the same AES-GCM key is catastrophic, and the
    shared secret is per-encapsulation, so both must vary."""
    keypair = zk.generate_keypair()
    first = zk.encrypt(keypair.public_key, b"same plaintext")
    second = zk.encrypt(keypair.public_key, b"same plaintext")

    assert first.nonce != second.nonce
    assert first.ciphertext_kem != second.ciphertext_kem
    assert first.ciphertext != second.ciphertext


def test_sign_and_verify():
    keypair = zk.generate_keypair(zk.SIG_ALGORITHM)
    signature = zk.sign(keypair.secret_key, b"order-42")

    assert zk.verify(keypair.public_key, b"order-42", signature) is True
    assert zk.verify(keypair.public_key, b"order-43", signature) is False


def test_envelope_survives_json():
    keypair = zk.generate_keypair()
    envelope = zk.encrypt(keypair.public_key, b"across the wire")
    restored = zk.ZkEnvelope.from_json(envelope.to_json())
    assert zk.decrypt(keypair.secret_key, restored) == b"across the wire"


def test_incomplete_envelope_names_what_is_missing():
    with pytest.raises(zk.ZeroKnowledgeError) as exc:
        zk.ZkEnvelope.from_dict({"algorithm": "ML-KEM-768"})
    assert "ciphertext" in str(exc.value)


def test_unsupported_algorithm_is_rejected():
    with pytest.raises(zk.ZeroKnowledgeError):
        zk.generate_keypair("RSA-2048")


# ---- key files -------------------------------------------------------------


def test_key_file_is_owner_only(tmp_path):
    """A private key written world-readable is a private key you have to
    treat as compromised."""
    path = zk.save_keypair(zk.generate_keypair(), tmp_path / "k.json")
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600, oct(mode)


def test_key_file_roundtrips(tmp_path):
    original = zk.generate_keypair()
    loaded = zk.load_keypair(zk.save_keypair(original, tmp_path / "k.json"))
    assert loaded.public_key == original.public_key
    assert loaded.secret_key == original.secret_key


def test_key_file_warns_about_the_absence_of_escrow(tmp_path):
    path = zk.save_keypair(zk.generate_keypair(), tmp_path / "k.json")
    assert "unrecoverable" in json.loads(path.read_text())["warning"]


def test_missing_key_file_is_a_clear_error(tmp_path):
    with pytest.raises(zk.ZeroKnowledgeError) as exc:
        zk.load_keypair(tmp_path / "nope.json")
    assert "No key file" in str(exc.value)


# ---- CLI -------------------------------------------------------------------


def test_cli_keygen_encrypt_decrypt(tmp_path, capsys, monkeypatch):
    key_path = tmp_path / "k.json"
    plaintext = tmp_path / "secret.txt"
    plaintext.write_bytes(b"board minutes")
    sealed = tmp_path / "sealed.json"
    opened = tmp_path / "opened.txt"

    assert cli.main(["zk", "keygen", "--out", str(key_path)]) == 0
    assert cli.main(
        ["zk", "encrypt", "--key", str(key_path), "--in", str(plaintext), "--out", str(sealed)]
    ) == 0

    # The sealed file must not contain the plaintext in any recoverable form.
    assert b"board minutes" not in sealed.read_bytes()

    assert cli.main(
        ["zk", "decrypt", "--key", str(key_path), "--in", str(sealed), "--out", str(opened)]
    ) == 0
    assert opened.read_bytes() == b"board minutes"


def test_cli_keygen_states_there_is_no_escrow(tmp_path, capsys):
    cli.main(["zk", "keygen", "--out", str(tmp_path / "k.json")])
    output = capsys.readouterr().out
    assert "no escrow" in output.lower()
    assert "unrecoverable" in output.lower()


def test_cli_local_commands_need_no_credentials(tmp_path, monkeypatch):
    """keygen/encrypt/decrypt must never call make_client — if they did,
    a local operation would fail without an API key, and worse, would be
    reaching the network at all."""
    def explode(config):
        raise AssertionError("local zk commands must not construct an API client")

    monkeypatch.setattr(cli, "make_client", explode)
    key_path = tmp_path / "k.json"
    assert cli.main(["zk", "keygen", "--out", str(key_path)]) == 0
    assert cli.main(["zk", "encrypt", "--key", str(key_path), "--in", str(key_path), "--out", str(tmp_path / "e.json")]) == 0


def test_cli_register_sends_only_the_public_half(tmp_path, monkeypatch):
    key_path = tmp_path / "k.json"
    cli.main(["zk", "keygen", "--out", str(key_path)])
    keypair = zk.load_keypair(key_path)

    sent = {}

    class Client:
        def register_key(self, **kwargs):
            sent.update(kwargs)
            return {"id": "key-1", "algorithm": kwargs["algorithm"], "version": 1}

    monkeypatch.setattr(cli, "make_client", lambda config: Client())
    assert cli.main(["zk", "register", "--key", str(key_path), "--label", "laptop"]) == 0

    assert sent["public_key"] == keypair.public_key
    assert sent["purpose"] == "kem"
    # The decisive assertion: no secret material anywhere in the payload.
    assert keypair.secret_key not in sent.values()
    assert "secret_key" not in sent
