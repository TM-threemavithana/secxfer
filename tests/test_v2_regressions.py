import asyncio
from pathlib import Path

import pytest

from secxfer.crypto import decrypt_private_key, encrypt_private_key
from secxfer.client import SecXferClient
from secxfer.keystore import Keystore, generate_keypair, get_unused_prekeys, load_identity
from secxfer.transfer import NonceCache, TruncationError, build_file_v2, decrypt_file_v2


async def _build_payload(identity, receiver, receiver_dir: Path, source: Path, chunk_size: int = 17) -> bytes:
    prekey = get_unused_prekeys(receiver_dir, "receiver")[0]
    chunks = []
    async for chunk in build_file_v2(
        identity,
        receiver.key_id,
        prekey["id"],
        bytes.fromhex(prekey["pubkey"]),
        receiver.kyber_pubkey,
        source,
        chunk_size=chunk_size,
    ):
        chunks.append(chunk)
    return b"".join(chunks)


@pytest.mark.parametrize("content", [b"not aligned to a chunk", b""])
def test_v2_round_trip_preserves_exact_content(tmp_path: Path, content: bytes):
    sender_dir = tmp_path / "sender"
    receiver_dir = tmp_path / "receiver"
    sender = generate_keypair(sender_dir, "sender", num_prekeys=1)
    receiver = generate_keypair(receiver_dir, "receiver", num_prekeys=1)
    (receiver_dir / "sender.pub").write_bytes((sender_dir / "sender.pub").read_bytes())
    source = sender_dir / "message.bin"
    source.write_bytes(content)

    payload = asyncio.run(_build_payload(sender, receiver, receiver_dir, source))
    decrypt_file_v2(
        receiver,
        Keystore.from_directory(receiver_dir),
        receiver_dir,
        payload,
        receiver_dir / "downloads",
        NonceCache(),
        "receiver",
    )
    assert (receiver_dir / "downloads" / "message.bin").read_bytes() == content


def test_v2_rejects_missing_final_trailer(tmp_path: Path):
    sender_dir = tmp_path / "sender"
    receiver_dir = tmp_path / "receiver"
    sender = generate_keypair(sender_dir, "sender", num_prekeys=1)
    receiver = generate_keypair(receiver_dir, "receiver", num_prekeys=1)
    (receiver_dir / "sender.pub").write_bytes((sender_dir / "sender.pub").read_bytes())
    source = sender_dir / "message.bin"
    source.write_bytes(b"payload")
    payload = asyncio.run(_build_payload(sender, receiver, receiver_dir, source))

    with pytest.raises(TruncationError):
        decrypt_file_v2(receiver, Keystore.from_directory(receiver_dir), receiver_dir, payload[:-10], receiver_dir / "downloads", NonceCache(), "receiver")
    assert not (receiver_dir / "downloads" / "message.bin").exists()
    assert not list((receiver_dir / "downloads").glob("*.part"))


def test_password_encrypted_hybrid_identity_round_trip(tmp_path: Path):
    identity = generate_keypair(tmp_path, "protected", num_prekeys=1, password="correct horse battery staple")
    loaded = load_identity(tmp_path / "protected.key", "correct horse battery staple")
    assert loaded.key_id == identity.key_id
    assert len(loaded.kyber_privkey) == len(identity.kyber_privkey)
    assert loaded.kyber_pubkey == identity.kyber_pubkey


def test_client_initializes_with_locked_httpx_version(tmp_path: Path):
    generate_keypair(tmp_path, "identity", num_prekeys=1)
    client = SecXferClient(tmp_path / "identity.key", tmp_path)
    asyncio.run(client.aclose())


def test_payload_size_matches_stream_output(tmp_path: Path):
    sender_dir = tmp_path / "sender"
    receiver_dir = tmp_path / "receiver"
    sender = generate_keypair(sender_dir, "sender", num_prekeys=1)
    receiver = generate_keypair(receiver_dir, "receiver", num_prekeys=1)
    source = sender_dir / "payload.bin"
    source.write_bytes(b"payload with a non-aligned length")
    payload = asyncio.run(_build_payload(sender, receiver, receiver_dir, source, chunk_size=65_536))
    assert SecXferClient._payload_size(source) == len(payload)


def test_deniable_encryption_handles_large_private_material():
    plaintext = b"x" * 2464
    encrypted = encrypt_private_key(plaintext, "password")
    assert len(encrypted) > len(plaintext)
    assert decrypt_private_key(encrypted, "password") == plaintext
