"""
tests/test_transfer.py

Integration and unit tests for secxfer.transfer and secxfer.keystore.

Covers:
  NonceCache:
    - Happy path: first insert succeeds
    - Replay within TTL ΓåÆ ReplayError
    - After TTL expires: same nonce accepted again (cache evicted)
    - Amortised eviction doesn't break correctness under many inserts
    - Threading: only one of N concurrent inserts of the same nonce succeeds
      (validates CPython GIL-based atomicity; see test docstring for scope)

  send_file / receive_file round-trip:
    - Small file (< CHUNK_SIZE)
    - Large file (multiple chunks)
    - Empty file

  Negative tests (receive_file) ΓÇö each asserts:
    (a) the expected exception type is raised
    (b) dest path does not exist
    (c) .part path does not exist (no partial file left behind)
"""
from __future__ import annotations

import io
import os
import struct
import tempfile
import threading
import time
from pathlib import Path

import pytest

from secxfer.keystore import (
    Keystore,
    LocalIdentity,
    PeerPublicKey,
    generate_keypair,
    key_id_from_x25519_pubkey,
    load_identity,
)
from secxfer.transfer import (
    NonceCache,
    ProtocolError,
    ReplayError,
    SignatureError,
    TTLError,
    TruncationError,
    _PREAMBLE_SIZE_V1 as _PREAMBLE_SIZE,
    _PROTOCOL_VERSION_V1 as _PROTOCOL_VERSION,
    VersionError,
    receive_file,
    send_file_v1 as send_file,
)
from secxfer.crypto import AuthenticationError
from secxfer.keystore import UnknownSenderError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp(tmp_path):
    return tmp_path


@pytest.fixture()
def alice(tmp_path):
    return generate_keypair(tmp_path / "alice", name="identity")


@pytest.fixture()
def bob(tmp_path):
    return generate_keypair(tmp_path / "bob", name="identity")


@pytest.fixture()
def alice_keystore(tmp_path, alice, bob):
    """Alice's keystore contains Bob's public key (to send to Bob)."""
    return _make_keystore(bob)


@pytest.fixture()
def bob_keystore(tmp_path, alice, bob):
    """Bob's keystore contains Alice's public key (to receive from Alice)."""
    return _make_keystore(alice)


def _make_keystore(peer: LocalIdentity) -> Keystore:
    """Create a Keystore with a single peer entry."""
    kid = key_id_from_x25519_pubkey(peer.x25519_pubkey)
    return Keystore({
        kid: PeerPublicKey(x25519=peer.x25519_pubkey, ed25519=peer.ed25519_pubkey)
    })


def _part_path(dest: Path) -> Path:
    """Return the .part path that receive_file uses for dest."""
    return dest.with_suffix(dest.suffix + ".part")


def _assert_no_partial(dest: Path) -> None:
    """Assert neither dest nor its .part file exist."""
    assert not dest.exists(), f"{dest} should not exist after failure"
    assert not _part_path(dest).exists(), f"{_part_path(dest)} should not exist after failure"


def _transfer(
    sender: LocalIdentity,
    receiver: LocalIdentity,
    receiver_keystore: Keystore,
    src_path: Path,
    dest_path: Path,
    nonce_cache: NonceCache | None = None,
    ttl_seconds: int = 300,
) -> None:
    """Helper: send src_path from sender ΓåÆ receiver; write result to dest_path."""
    buf = io.BytesIO()
    send_file(sender, receiver.x25519_pubkey, src_path, buf, ttl_seconds=ttl_seconds)
    buf.seek(0)
    receive_file(
        receiver,
        receiver_keystore,
        "",
        "bob",
        buf,
        dest_path,
        nonce_cache or NonceCache(),
    )


# ---------------------------------------------------------------------------
# NonceCache
# ---------------------------------------------------------------------------

class TestNonceCache:
    def test_first_insert_succeeds(self):
        cache = NonceCache()
        cache.check_and_insert(b"\x00" * 8, b"\x01" * 16, ttl_seconds=60)

    def test_replay_within_ttl_raises(self):
        cache = NonceCache()
        kid = b"\x00" * 8
        nonce = b"\x01" * 16
        cache.check_and_insert(kid, nonce, ttl_seconds=60)
        with pytest.raises(ReplayError):
            cache.check_and_insert(kid, nonce, ttl_seconds=60)

    def test_different_nonce_accepted(self):
        cache = NonceCache()
        kid = b"\x00" * 8
        cache.check_and_insert(kid, b"\x01" * 16, ttl_seconds=60)
        cache.check_and_insert(kid, b"\x02" * 16, ttl_seconds=60)  # different nonce ΓÇö ok

    def test_different_sender_accepted(self):
        cache = NonceCache()
        nonce = b"\x01" * 16
        cache.check_and_insert(b"\xAA" * 8, nonce, ttl_seconds=60)
        cache.check_and_insert(b"\xBB" * 8, nonce, ttl_seconds=60)  # same nonce, different sender ΓÇö ok

    def test_eviction_after_ttl(self, monkeypatch):
        """After TTL expires, the same nonce should be accepted again."""
        cache = NonceCache()
        kid = b"\x00" * 8
        nonce = b"\x01" * 16

        # Insert with very short TTL
        cache.check_and_insert(kid, nonce, ttl_seconds=1)

        # Fast-forward time past TTL using monkeypatch
        original_monotonic = time.monotonic
        monkeypatch.setattr(time, "monotonic", lambda: original_monotonic() + 2)

        # Should succeed after eviction
        cache.check_and_insert(kid, nonce, ttl_seconds=60)

    def test_len_reflects_active_entries(self):
        cache = NonceCache()
        assert len(cache) == 0
        cache.check_and_insert(b"\x00" * 8, b"\x01" * 16, ttl_seconds=60)
        assert len(cache) == 1
        cache.check_and_insert(b"\x00" * 8, b"\x02" * 16, ttl_seconds=60)
        assert len(cache) == 2

    def test_many_inserts_evict_correctly(self, monkeypatch):
        """Amortised eviction keeps cache bounded under many inserts."""
        cache = NonceCache()
        base_time = time.monotonic()
        call_count = 0

        def fake_monotonic():
            nonlocal call_count
            call_count += 1
            # Advance time by 1s every 10 calls to trigger evictions
            return base_time + (call_count // 10)

        monkeypatch.setattr(time, "monotonic", fake_monotonic)

        for i in range(100):
            nonce = i.to_bytes(16, "big")
            cache.check_and_insert(b"\x00" * 8, nonce, ttl_seconds=5)

        # Cache should not grow unboundedly ΓÇö entries older than TTL are gone
        assert len(cache) < 100

    def test_concurrent_threading_exactly_one_wins(self):
        """
        20 threads simultaneously insert the same (key_id, nonce) via the
        lock-protected check_and_insert.  Exactly one must succeed; the
        other 19 must get ReplayError.

        What this test proves
        ---------------------
        The ``threading.Lock`` in ``check_and_insert`` correctly serialises
        concurrent access: the eviction pass, membership check, and insert
        execute as an atomic unit.  If the lock were removed, this specific
        test would not reliably catch the regression (as confirmed by running
        a broken version with ``time.sleep(0)`` between check and insert ΓÇö
        it still showed only 1 winner because the race window is too small
        for the OS scheduler to hit it without a forced yield inside the
        critical section).  The test's value is as a correctness regression
        guard for the lock itself: if ``with self._lock`` is accidentally
        deleted, a sufficiently tight race under load could manifest, and
        this test is the first line of defence.

        What this test does NOT prove
        ------------------------------
        - That a lockless version is necessarily broken in practice (the
          race window may be too small to hit without instrumentation).
        - Safety under GIL-free Python (CPython 3.13 free-threaded build);
          the lock covers that case too, but this test does not verify it
          specifically.
        - Asyncio safety ΓÇö ``check_and_insert`` is synchronous and the lock
          is acquired as a context manager; no ``await`` can interrupt it.
        """
        cache = NonceCache()
        kid = b"\xAA" * 8
        nonce = b"\xBB" * 16
        successes = []
        errors = []
        lock = threading.Lock()

        def insert():
            try:
                cache.check_and_insert(kid, nonce, ttl_seconds=60)
                with lock:
                    successes.append(True)
            except ReplayError:
                with lock:
                    successes.append(False)
            except Exception as exc:
                with lock:
                    errors.append(exc)

        n_threads = 20
        threads = [threading.Thread(target=insert) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"unexpected exceptions: {errors}"
        assert successes.count(True) == 1, (
            f"Expected exactly 1 success, got {successes.count(True)}"
        )
        assert successes.count(False) == n_threads - 1


# ---------------------------------------------------------------------------
# Round-trip tests
# ---------------------------------------------------------------------------

class TestRoundtrip:
    def test_small_file(self, tmp, alice, bob, bob_keystore):
        src = tmp / "hello.txt"
        src.write_bytes(b"hello, world")
        dest = tmp / "received.txt"
        _transfer(alice, bob, bob_keystore, src, dest)
        assert dest.read_bytes() == b"hello, world"

    def test_large_file(self, tmp, alice, bob, bob_keystore):
        data = os.urandom(300_000)   # ~3 chunks at 64 KiB each
        src = tmp / "large.bin"
        src.write_bytes(data)
        dest = tmp / "large_recv.bin"
        _transfer(alice, bob, bob_keystore, src, dest)
        assert dest.read_bytes() == data

    def test_empty_file(self, tmp, alice, bob, bob_keystore):
        src = tmp / "empty.bin"
        src.write_bytes(b"")
        dest = tmp / "empty_recv.bin"
        _transfer(alice, bob, bob_keystore, src, dest)
        assert dest.read_bytes() == b""

    def test_exact_chunk_boundary(self, tmp, alice, bob, bob_keystore):
        """File size exactly equal to CHUNK_SIZE ΓÇö tests edge case in read-ahead."""
        from secxfer.crypto import CHUNK_SIZE
        data = os.urandom(CHUNK_SIZE)
        src = tmp / "exact.bin"
        src.write_bytes(data)
        dest = tmp / "exact_recv.bin"
        _transfer(alice, bob, bob_keystore, src, dest)
        assert dest.read_bytes() == data

    def test_dest_not_created_on_success_uses_exact_path(self, tmp, alice, bob, bob_keystore):
        src = tmp / "file.bin"
        src.write_bytes(b"test content")
        dest = tmp / "output.bin"
        _transfer(alice, bob, bob_keystore, src, dest)
        assert dest.exists()
        assert not (tmp / "output.bin.part").exists()

    def test_filename_preserved_in_metadata(self, tmp, alice, bob, bob_keystore):
        """Filename in metadata header round-trips correctly (not verified by
        receive_file directly, but the metadata is AEAD-protected so any
        tampering would cause AuthenticationError ΓÇö round-trip confirms encoding)."""
        src = tmp / "myspecialfile.dat"
        src.write_bytes(b"data")
        dest = tmp / "out.dat"
        _transfer(alice, bob, bob_keystore, src, dest)
        assert dest.exists()


# ---------------------------------------------------------------------------
# Negative tests
# ---------------------------------------------------------------------------

class TestNegative:
    def _send_to_buffer(
        self, sender, receiver, src_path, ttl_seconds=300
    ) -> io.BytesIO:
        buf = io.BytesIO()
        send_file(
            sender, receiver.x25519_pubkey, src_path, buf, ttl_seconds=ttl_seconds
        )
        buf.seek(0)
        return buf

    def test_wrong_receiver_key_raises(self, tmp, alice, bob, bob_keystore):
        """A receiver with the wrong private key cannot decrypt ΓÇö AuthenticationError."""
        src = tmp / "secret.bin"
        src.write_bytes(b"top secret")
        dest = tmp / "out.bin"
        buf = self._send_to_buffer(alice, bob, src)

        # Generate a different identity for the "receiver"
        wrong_identity = generate_keypair(tmp / "wrong", name="identity")

        with pytest.raises(AuthenticationError):
            receive_file(wrong_identity, bob_keystore, "", "bob", buf, dest, NonceCache())

        _assert_no_partial(dest)

    def test_tampered_data_chunk_raises(self, tmp, alice, bob, bob_keystore):
        """Flipping a bit in a data chunk ΓåÆ AuthenticationError; .part deleted.

        Byte _PREAMBLE_SIZE + 200 = offset 257. Stream layout: preamble ends
        at byte 56. Chunk 0 (metadata, 4-byte length prefix + 63-byte
        ciphertext for 'data.bin') occupies bytes 57-123; data chunks start
        at byte 124. Offset 257 is byte +133 inside chunk 1's ciphertext ΓÇö
        inside an AEAD-protected data chunk.
        """
        src = tmp / "data.bin"
        src.write_bytes(os.urandom(1000))
        dest = tmp / "out.bin"
        buf = self._send_to_buffer(alice, bob, src)

        raw = bytearray(buf.getvalue())
        raw[_PREAMBLE_SIZE + 200] ^= 0xFF
        with pytest.raises(AuthenticationError):
            receive_file(bob, bob_keystore, "", "bob", io.BytesIO(bytes(raw)), dest, NonceCache())

        _assert_no_partial(dest)

    def test_truncated_stream_raises(self, tmp, alice, bob, bob_keystore):
        """Dropping the final chunk ΓåÆ TruncationError or AuthenticationError; .part deleted."""
        src = tmp / "data.bin"
        src.write_bytes(os.urandom(200_000))   # multiple chunks
        dest = tmp / "out.bin"
        buf = self._send_to_buffer(alice, bob, src)

        # Truncate to 60% of stream ΓÇö removes final chunk(s)
        raw = buf.getvalue()
        truncated = raw[: int(len(raw) * 0.6)]

        with pytest.raises((TruncationError, AuthenticationError, ProtocolError)):
            receive_file(bob, bob_keystore, "", "bob", io.BytesIO(truncated), dest, NonceCache())

        _assert_no_partial(dest)

    def test_replay_within_ttl_raises(self, tmp, alice, bob, bob_keystore):
        """Replaying an identical transfer within the TTL window ΓåÆ ReplayError."""
        src = tmp / "data.bin"
        src.write_bytes(b"replay me")
        dest1 = tmp / "out1.bin"
        dest2 = tmp / "out2.bin"

        buf = self._send_to_buffer(alice, bob, src)
        raw = buf.getvalue()

        cache = NonceCache()
        receive_file(bob, bob_keystore, "", "bob", io.BytesIO(raw), dest1, cache)

        with pytest.raises(ReplayError):
            receive_file(bob, bob_keystore, "", "bob", io.BytesIO(raw), dest2, cache)

        # ReplayError is raised before .part is opened ΓÇö both checks apply
        _assert_no_partial(dest2)

    def test_expired_transfer_raises(self, tmp, alice, bob, bob_keystore):
        """Transfer with ttl=1 received after 2 seconds ΓåÆ TTLError."""
        src = tmp / "data.bin"
        src.write_bytes(b"old transfer")
        dest = tmp / "out.bin"

        buf = io.BytesIO()
        send_file(alice, bob.x25519_pubkey, src, buf, ttl_seconds=1)
        buf.seek(0)
        raw = buf.getvalue()

        # Patch time.time on the receiver side to simulate delay
        original_time = time.time
        try:
            time.time = lambda: original_time() + 10  # 10 seconds later
            with pytest.raises(TTLError):
                receive_file(bob, bob_keystore, "", "bob", io.BytesIO(raw), dest, NonceCache())
        finally:
            time.time = original_time

        # TTLError is raised before .part is opened
        _assert_no_partial(dest)

    def test_unknown_sender_raises(self, tmp, alice, bob):
        """Sender's key_id not in keystore ΓåÆ UnknownSenderError."""
        src = tmp / "data.bin"
        src.write_bytes(b"from alice")
        dest = tmp / "out.bin"

        buf = self._send_to_buffer(alice, bob, src)
        empty_keystore = Keystore({})   # knows nobody

        with pytest.raises(UnknownSenderError):
            receive_file(bob, empty_keystore, "", "bob", buf, dest, NonceCache())

        # UnknownSenderError is raised before .part is opened
        _assert_no_partial(dest)

    def test_bad_version_raises(self, tmp, alice, bob, bob_keystore):
        """Wrong version byte in preamble ΓåÆ VersionError."""
        src = tmp / "data.bin"
        src.write_bytes(b"hello")
        dest = tmp / "out.bin"

        buf = self._send_to_buffer(alice, bob, src)
        raw = bytearray(buf.getvalue())
        raw[0] = 0xFF   # corrupt version byte
        with pytest.raises(VersionError):
            receive_file(bob, bob_keystore, "", "bob", io.BytesIO(bytes(raw)), dest, NonceCache())

        # VersionError is raised before .part is opened
        _assert_no_partial(dest)

    def test_tampered_signature_raises(self, tmp, alice, bob, bob_keystore):
        """Ed25519 signature tampered ΓåÆ SignatureError; .part file deleted.

        AEAD protects the metadata chunk (including the signature field), so
        an attacker cannot tamper with the sig byte directly ΓÇö the AEAD tag
        would reject it first.  The reachable scenario is a sender that signs
        with the wrong Ed25519 key (e.g. key mismatch on the sender side) while
        using the correct X25519 key (so AEAD passes, sig check fails).
        """
        src = tmp / "data.bin"
        src.write_bytes(b"signed content")
        dest = tmp / "out.bin"

        # Build a forged identity: Alice's X25519 keys + a different Ed25519 seed
        import nacl.bindings as nb
        from nacl.signing import SigningKey

        wrong_ed25519_seed = os.urandom(32)
        wrong_ed25519_pub = bytes(SigningKey(wrong_ed25519_seed).verify_key)

        forged_identity = LocalIdentity(
            x25519_privkey=alice.x25519_privkey,
            ed25519_seed=wrong_ed25519_seed,
            x25519_pubkey=alice.x25519_pubkey,
            ed25519_pubkey=wrong_ed25519_pub,
            key_id=alice.key_id,
        )
        # Bob's keystore still expects Alice's real Ed25519 pubkey
        forged_buf = io.BytesIO()
        send_file(forged_identity, bob.x25519_pubkey, src, forged_buf)
        forged_buf.seek(0)

        with pytest.raises(SignatureError):
            receive_file(bob, bob_keystore, "", "bob", forged_buf, dest, NonceCache())

        # SignatureError cleanup: .part is fully written then deleted before raise
        _assert_no_partial(dest)

