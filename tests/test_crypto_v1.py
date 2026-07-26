"""
tests/test_crypto.py

Unit tests for secxfer.crypto.

Covers:
  - derive_stream_key: same inputs ΓåÆ same output; different stream_header ΓåÆ different key
  - SecretstreamPusher/Puller: happy path round-trip
  - Negative: tampered ciphertext ΓåÆ AuthenticationError
  - Negative: out-of-order chunks ΓåÆ AuthenticationError
  - Negative: chunk from different stream (wrong key) ΓåÆ AuthenticationError
  - Negative: push after push_final ΓåÆ RuntimeError
  - sign_digest / verify_digest: happy path
  - Negative: wrong pubkey ΓåÆ SignatureError
  - Negative: tampered digest ΓåÆ SignatureError
  - Negative: tampered signature ΓåÆ SignatureError
  - hash_stream: deterministic, chunked reads match full read
"""
from __future__ import annotations

import io
import os

import pytest

from secxfer.crypto import (
    CHUNK_SIZE,
    AuthenticationError,
    SecretstreamPuller,
    SecretstreamPusher,
    SignatureError,
    derive_stream_key,
    sign_digest,
    verify_digest,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _keypair() -> tuple[bytes, bytes]:
    """Generate a random Curve25519 keypair (privkey, pubkey)."""
    import nacl.bindings as nb
    privkey = os.urandom(32)
    pubkey = nb.crypto_scalarmult_base(privkey)
    return privkey, pubkey


def _ed25519_keypair() -> tuple[bytes, bytes]:
    """Generate a random Ed25519 keypair (seed, pubkey)."""
    from nacl.signing import SigningKey
    sk = SigningKey.generate()
    return bytes(sk), bytes(sk.verify_key)


def _make_stream(key: bytes) -> tuple[SecretstreamPusher, bytes]:
    """Return a pusher and its header."""
    pusher = SecretstreamPusher(key)
    return pusher, pusher.header


# ---------------------------------------------------------------------------
# derive_stream_key
# ---------------------------------------------------------------------------

class TestDeriveStreamKey:
    def test_deterministic(self):
        priv, pub = _keypair()
        header = os.urandom(24)
        k1 = derive_stream_key(priv, pub, header)
        k2 = derive_stream_key(priv, pub, header)
        assert k1 == k2

    def test_different_header_different_key(self):
        priv, pub = _keypair()
        k1 = derive_stream_key(priv, pub, os.urandom(24))
        k2 = derive_stream_key(priv, pub, os.urandom(24))
        assert k1 != k2

    def test_dh_symmetric(self):
        """X25519 is symmetric: DH(a, B) == DH(b, A)."""
        priv_a, pub_a = _keypair()
        priv_b, pub_b = _keypair()
        header = os.urandom(24)
        k_a = derive_stream_key(priv_a, pub_b, header)
        k_b = derive_stream_key(priv_b, pub_a, header)
        assert k_a == k_b

    def test_output_is_32_bytes(self):
        priv, pub = _keypair()
        key = derive_stream_key(priv, pub, os.urandom(24))
        assert len(key) == 32


# ---------------------------------------------------------------------------
# SecretstreamPusher / SecretstreamPuller
# ---------------------------------------------------------------------------

class TestSecretstreamRoundtrip:
    def test_single_chunk_roundtrip(self):
        stream_key = os.urandom(32)
        pusher = SecretstreamPusher(stream_key)
        plaintext = b"hello, world"
        ciphertext = pusher.push_final(plaintext)

        puller = SecretstreamPuller(stream_key, pusher.header)
        result, is_final = puller.pull(ciphertext)
        assert result == plaintext
        assert is_final is True

    def test_multi_chunk_roundtrip(self):
        stream_key = os.urandom(32)
        pusher = SecretstreamPusher(stream_key)
        chunks = [os.urandom(CHUNK_SIZE) for _ in range(3)]
        ciphertexts = [pusher.push(c) for c in chunks]
        ciphertexts.append(pusher.push_final(b"tail"))

        puller = SecretstreamPuller(stream_key, pusher.header)
        results = []
        for ct in ciphertexts:
            pt, is_final = puller.pull(ct)
            results.append((pt, is_final))

        assert [r[0] for r in results] == chunks + [b"tail"]
        assert [r[1] for r in results] == [False, False, False, True]

    def test_header_is_24_bytes(self):
        pusher = SecretstreamPusher(os.urandom(32))
        assert len(pusher.header) == 24


class TestSecretstreamNegative:
    def test_tampered_ciphertext_raises(self):
        stream_key = os.urandom(32)
        pusher = SecretstreamPusher(stream_key)
        ct = pusher.push_final(b"secret data")

        tampered = bytearray(ct)
        tampered[5] ^= 0xFF          # flip a bit
        puller = SecretstreamPuller(stream_key, pusher.header)
        with pytest.raises(AuthenticationError):
            puller.pull(bytes(tampered))

    def test_wrong_key_raises(self):
        stream_key = os.urandom(32)
        pusher = SecretstreamPusher(stream_key)
        ct = pusher.push_final(b"secret data")

        wrong_key = os.urandom(32)
        puller = SecretstreamPuller(wrong_key, pusher.header)
        with pytest.raises(AuthenticationError):
            puller.pull(ct)

    def test_out_of_order_chunks_raises(self):
        stream_key = os.urandom(32)
        pusher = SecretstreamPusher(stream_key)
        ct0 = pusher.push(b"chunk zero")
        ct1 = pusher.push_final(b"chunk one")

        puller = SecretstreamPuller(stream_key, pusher.header)
        # Feed chunk 1 before chunk 0 ΓÇö stream state machine rejects it
        with pytest.raises(AuthenticationError):
            puller.pull(ct1)  # out of order: ct0 was never fed

    def test_injected_chunk_from_other_stream_raises(self):
        stream_key = os.urandom(32)

        # Stream A
        pusher_a = SecretstreamPusher(stream_key)
        ct_a = pusher_a.push(b"from stream A")

        # Stream B ΓÇö same key, different stream (different header)
        pusher_b = SecretstreamPusher(stream_key)
        ct_b = pusher_b.push(b"injected from B")

        # Feed chunk from B into puller expecting A
        puller = SecretstreamPuller(stream_key, pusher_a.header)
        with pytest.raises(AuthenticationError):
            puller.pull(ct_b)

    def test_push_after_final_raises(self):
        pusher = SecretstreamPusher(os.urandom(32))
        pusher.push_final(b"done")
        with pytest.raises(RuntimeError):
            pusher.push(b"too late")

    def test_push_final_twice_raises(self):
        pusher = SecretstreamPusher(os.urandom(32))
        pusher.push_final(b"done")
        with pytest.raises(RuntimeError):
            pusher.push_final(b"again")


# ---------------------------------------------------------------------------
# sign_digest / verify_digest
# ---------------------------------------------------------------------------

class TestSignVerify:
    def test_happy_path(self):
        seed, pubkey = _ed25519_keypair()
        digest = os.urandom(32)
        sig = sign_digest(seed, digest)
        verify_digest(pubkey, sig, digest)  # must not raise

    def test_signature_is_64_bytes(self):
        seed, _ = _ed25519_keypair()
        sig = sign_digest(seed, os.urandom(32))
        assert len(sig) == 64

    def test_wrong_pubkey_raises(self):
        seed, _ = _ed25519_keypair()
        _, wrong_pubkey = _ed25519_keypair()
        digest = os.urandom(32)
        sig = sign_digest(seed, digest)
        with pytest.raises(SignatureError):
            verify_digest(wrong_pubkey, sig, digest)

    def test_tampered_digest_raises(self):
        seed, pubkey = _ed25519_keypair()
        digest = os.urandom(32)
        sig = sign_digest(seed, digest)
        tampered = bytes(b ^ 0xFF for b in digest)
        with pytest.raises(SignatureError):
            verify_digest(pubkey, sig, tampered)

    def test_tampered_signature_raises(self):
        seed, pubkey = _ed25519_keypair()
        digest = os.urandom(32)
        sig = bytearray(sign_digest(seed, digest))
        sig[10] ^= 0x01
        with pytest.raises(SignatureError):
            verify_digest(pubkey, bytes(sig), digest)

    def test_deterministic(self):
        """Ed25519 signatures are deterministic ΓÇö same inputs, same output."""
        seed, _ = _ed25519_keypair()
        digest = os.urandom(32)
        assert sign_digest(seed, digest) == sign_digest(seed, digest)


# ---------------------------------------------------------------------------
# hash_stream
# ---------------------------------------------------------------------------
