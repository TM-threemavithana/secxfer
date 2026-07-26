import pytest
from async_mock import AsyncBytesIO
import tempfile
import struct
import hashlib
from pathlib import Path
from io import BytesIO

from secxfer.keystore import generate_keypair, Keystore, key_id_from_x25519_pubkey, UnknownSenderError
from secxfer.transfer import send_file_v2 as send_file, receive_file, ProtocolError, PreKeyConsumedError
from secxfer.crypto import SignatureError
from secxfer.transfer import NonceCache
from secxfer.wire import _PREAMBLE_FMT_V2 as _PREAMBLE_FMT

@pytest.fixture
def test_env(tmp_path):
    alice_dir = tmp_path / "alice"
    bob_dir = tmp_path / "bob"
    carol_dir = tmp_path / "carol"
    alice_dir.mkdir()
    bob_dir.mkdir()
    carol_dir.mkdir()
    
    from secxfer.keystore import get_unused_prekeys
    alice_id = generate_keypair(alice_dir, "alice", 5)
    alice_pks = get_unused_prekeys(alice_dir, "alice")
    bob_id = generate_keypair(bob_dir, "bob", 5)
    bob_pks = get_unused_prekeys(bob_dir, "bob")
    carol_id = generate_keypair(carol_dir, "carol", 5)
    carol_pks = get_unused_prekeys(carol_dir, "carol")
    
    alice_ks_dir = alice_dir / "keystore"
    bob_ks_dir = bob_dir / "keystore"
    alice_ks_dir.mkdir()
    bob_ks_dir.mkdir()
    carol_ks_dir = carol_dir / "keystore"
    carol_ks_dir.mkdir()
    
    dummy_file = tmp_path / "dummy.txt"
    dummy_file.write_bytes(b"Top Secret Data")
    
    return {
        "alice": alice_id,
        "bob": bob_id,
        "carol": carol_id,
        "bob_pks": bob_pks,
        "alice_ks_dir": alice_ks_dir,
        "bob_ks_dir": bob_ks_dir,
        "carol_ks_dir": carol_ks_dir,
        "bob_dir": bob_dir,
        "dummy_file": dummy_file,
        "tmp_path": tmp_path,
    }

@pytest.mark.asyncio
async def test_unpinned_sender_hard_fails(test_env):
    """
    Validates that a transfer from an unpinned sender is immediately rejected,
    preventing any pre-key burning or cryptographic processing.
    """
    alice = test_env["alice"]
    bob = test_env["bob"]
    bob_pks = test_env["bob_pks"]
    
    # Alice is NOT pinned by Bob.
    keystore = Keystore.from_directory(test_env["bob_ks_dir"])
    nonce_cache = NonceCache()
    
    out = AsyncBytesIO()
    await send_file(
        identity=alice,
        receiver_key_id=bob.key_id,
        receiver_prekey_id=bob_pks[0]["id"],
        receiver_prekey_pubkey=bytes.fromhex(bob_pks[0]["pubkey"]),
        file_path=test_env["dummy_file"],
        out=out,
    )
    
    out.seek(0)
    
    with pytest.raises(UnknownSenderError):
        await receive_file(
            identity=bob,
            keystore=keystore,
            keystore_dir=test_env["bob_dir"],
            identity_name="bob",
            inp=out,
            dest_path=test_env["tmp_path"] / "out.txt",
            nonce_cache=nonce_cache,
        )

@pytest.mark.asyncio
async def test_dual_store_desync_fails_safely(test_env):
    """
    Simulates a race or server compromise where the server hands out a pre-key
    that the receiver has already consumed locally.
    Validates that `receive_file` fails safely without corrupting state.
    """
    alice = test_env["alice"]
    bob = test_env["bob"]
    bob_pks = test_env["bob_pks"]
    
    # Pin Alice
    (test_env["bob_ks_dir"] / "alice.pub").write_bytes(alice.x25519_pubkey + alice.ed25519_pubkey)
    keystore = Keystore.from_directory(test_env["bob_ks_dir"])
    nonce_cache = NonceCache()
    
    target_pk = bob_pks[0]
    
    # 1. Manually burn the pre-key on Bob's side (simulating a prior transfer)
    pk_path = test_env["bob_dir"] / "bob_prekeys" / f"{target_pk['id']}.key"
    pk_path.rename(pk_path.with_suffix('.used'))
    
    out = AsyncBytesIO()
    await send_file(
        identity=alice,
        receiver_key_id=bob.key_id,
        receiver_prekey_id=target_pk["id"],
        receiver_prekey_pubkey=bytes.fromhex(target_pk["pubkey"]),
        file_path=test_env["dummy_file"],
        out=out,
    )
    
    out.seek(0)
    
    # 2. Attempt to receive using the burned pre-key
    with pytest.raises(PreKeyConsumedError, match="does not exist or was already consumed"):
        await receive_file(
            identity=bob,
            keystore=keystore,
            keystore_dir=test_env["bob_dir"],
            identity_name="bob",
            inp=out,
            dest_path=test_env["tmp_path"] / "out2.txt",
            nonce_cache=nonce_cache,
        )

@pytest.mark.asyncio
async def test_context_binding_unknown_key_share(test_env):
    """
    Simulates an Unknown-Key-Share (UKS) attack.
    Alice signs a transfer intended for Bob, but Mallory forwards it to Carol.
    Carol should reject it because the signature's context does not match Carol's ID.
    """
    alice = test_env["alice"]
    bob = test_env["bob"]
    carol = test_env["carol"]
    bob_pks = test_env["bob_pks"]
    
    # Pin Alice for both Bob and Carol
    (test_env["bob_ks_dir"] / "alice.pub").write_bytes(alice.x25519_pubkey + alice.ed25519_pubkey)
    (test_env["carol_ks_dir"] / "alice.pub").write_bytes(alice.x25519_pubkey + alice.ed25519_pubkey)
    carol_keystore = Keystore.from_directory(test_env["carol_ks_dir"])
    nonce_cache = NonceCache()
    
    out = AsyncBytesIO()
    
    # 1. Alice creates a transfer legitimately for Bob
    await send_file(
        identity=alice,
        receiver_key_id=bob.key_id,
        receiver_prekey_id=bob_pks[0]["id"],
        receiver_prekey_pubkey=bytes.fromhex(bob_pks[0]["pubkey"]),
        file_path=test_env["dummy_file"],
        out=out,
    )
    
    # 2. Mallory intercepts the bytes and forwards to Carol
    # Even if Mallory somehow replaced the prekey ID with Carol's, 
    # the signature bound inside the preamble would fail to verify 
    # because it was signed over Bob's key_id and prekey_id!
    out.seek(0)
    
    # We pass it to Carol's receive_file. It will unpack the preamble.
    # Carol's receive_file expects the signature to be over:
    # ephemeral_pub + carol.key_id + (the prekey ID from the wire)
    # But Alice signed:
    # ephemeral_pub + bob.key_id + (the prekey ID from the wire)
    with pytest.raises(SignatureError, match="Sender authentication failed"):
        await receive_file(
            identity=carol,
            keystore=carol_keystore,
            keystore_dir=test_env["tmp_path"] / "carol",
            identity_name="carol",
            inp=out,
            dest_path=test_env["tmp_path"] / "out3.txt",
            nonce_cache=nonce_cache,
        )
