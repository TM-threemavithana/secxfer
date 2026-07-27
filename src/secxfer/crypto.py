"""
secxfer.crypto — stateless cryptographic primitives.

Boundary contract
-----------------
- Accepts and returns bytes or BinaryIO. No file paths. No session state.
- No nonce cache, no TTL logic, no .part file lifecycle.
- Every public function is independently unit-testable with synthetic inputs.

Primitives used
---------------
- Key exchange:  X25519 (Curve25519 ECDH) via nacl.bindings.crypto_scalarmult
- KDF:           HKDF-SHA256 (RFC 5869), implemented over stdlib hmac + hashlib
- Stream cipher: XChaCha20-Poly1305 via libsodium secretstream
                 (crypto_secretstream_xchacha20poly1305)
- Signing:       Ed25519 via nacl.signing
- Hashing:       SHA-256 via stdlib hashlib
"""
from __future__ import annotations


# ---------------------------------------------------------------------------
# Secure Memory Management
# ---------------------------------------------------------------------------
import ctypes
import sys

def secure_wipe(b: bytes) -> None:
    """
    Overwrite key material with zeros using libsodium's guaranteed-not-to-be-
    optimized-away sodium_memzero, which is immune to compiler dead-store
    elimination.

    Falls back to ctypes on PyNaCl versions that do not expose the binding
    (pre-1.4). The ctypes path uses the CPython bytes layout heuristic and is
    unreliable on PyPy — prefer upgrading PyNaCl.
    """
    if not isinstance(b, bytes) or len(b) == 0:
        return
    try:
        # PyNaCl >= 1.4 exposes sodium_memzero directly
        import nacl.bindings as _nb_wipe
        # Create a mutable copy via ctypes, zero it, then let it be GC'd.
        # The canonical approach for immutable bytes in CPython.
        buf = (ctypes.c_char * len(b)).from_buffer_copy(b)
        _nb_wipe.sodium_memzero(buf)
    except (AttributeError, TypeError):
        # Fallback: CPython bytes layout heuristic (version-specific offset)
        offset = 32 if sys.maxsize > 2**32 else 16
        buf_addr = id(b) + offset
        ctypes.memset(buf_addr, 0, len(b))

import hashlib
import os
import hmac as _hmac
from typing import BinaryIO

import nacl.bindings as _nb
from nacl.exceptions import CryptoError as _NaClCryptoError
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

import oqs



# ---------------------------------------------------------------------------
# Public errors
# ---------------------------------------------------------------------------

class AuthenticationError(Exception):
    """AEAD tag verification failed; ciphertext was tampered or is corrupt."""


class SignatureError(Exception):
    """Ed25519 signature did not verify against the supplied public key."""


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Bytes required for a secretstream public header (sent in wire preamble).
STREAM_HEADER_SIZE: int = _nb.crypto_secretstream_xchacha20poly1305_HEADERBYTES  # 24

#: Bytes required for a secretstream symmetric key.
STREAM_KEY_SIZE: int = _nb.crypto_secretstream_xchacha20poly1305_KEYBYTES  # 32

#: Tag value for non-final chunks.
TAG_MESSAGE: int = _nb.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE

#: Tag value for the final chunk; signals stream completeness.
TAG_FINAL: int = _nb.crypto_secretstream_xchacha20poly1305_TAG_FINAL

#: Default plaintext chunk size (64 KiB).
CHUNK_SIZE: int = 65_536


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def derive_stream_key(
    local_privkey: bytes,
    remote_pubkey: bytes,
    stream_salt: bytes,
    kyber_secret: bytes | None = None,
) -> bytes:
    """
    Derive a 32-byte secretstream key from a Curve25519 DH exchange.

    Uses HKDF-SHA256 with *stream_salt* as the salt.  *stream_salt* is 24
    bytes of randomness generated fresh by the sender each transfer, sent
    in the wire preamble alongside (but independently of) the secretstream
    header produced by ``SecretstreamPusher``.

    Why two separate 24-byte values in the preamble?
    -------------------------------------------------
    ``init_push(state, key) -> header`` generates its header internally using
    libsodium's own RNG — the caller cannot supply an external value.  This
    means the HKDF salt (which must be chosen *before* the key, so it can
    feed into key derivation) and the secretstream header (which is an
    *output* of ``init_push``, produced *after* the key is known) are
    necessarily distinct values.  One random value cannot serve both roles.

    The result is defence-in-depth: per-stream freshness comes from two
    independent random sources (``stream_salt`` for HKDF, secretstream's
    own internal header for the stream cipher), rather than relying solely
    on secretstream's internal nonce freshness under a static derived key.

    Args:
        local_privkey:  32-byte raw Curve25519 private key.
        remote_pubkey:  32-byte raw Curve25519 public key.
        stream_salt:    24 bytes of fresh randomness generated per transfer
                        by the sender (sent in the wire preamble).
        kyber_secret:   Optional 32-byte ML-KEM-768 shared secret to mix.

    Returns:
        32-byte key for ``SecretstreamPusher`` / ``SecretstreamPuller``.
    """
    shared_secret: bytes = _nb.crypto_scalarmult(local_privkey, remote_pubkey)
    if kyber_secret:
        # Mix the ML-KEM-768 shared secret into the DH output
        shared_secret = _hmac.new(kyber_secret, shared_secret, hashlib.sha256).digest()
        
    return _hkdf_sha256(
        ikm=shared_secret,
        salt=stream_salt,
        info=b"secxfer-v1-stream",
        length=STREAM_KEY_SIZE,
    )

def generate_ephemeral_keypair() -> tuple[bytes, bytes]:
    """
    Generate a fresh Curve25519 keypair.
    Returns (private_key, public_key), both 32 bytes.
    """
    priv = os.urandom(32)
    pub = _nb.crypto_scalarmult_base(priv)
    return priv, pub


def kyber_generate_keypair() -> tuple[bytes, bytes]:
    """Generate ML-KEM-768 keypair. Returns (pubkey, privkey)."""
    with oqs.KeyEncapsulation("Kyber768") as kem:
        pubkey = kem.generate_keypair()
        privkey = kem.export_secret_key()
        return pubkey, privkey


def kyber_encapsulate(pubkey: bytes) -> tuple[bytes, bytes]:
    """Encapsulate ML-KEM-768. Returns (ciphertext, shared_secret)."""
    with oqs.KeyEncapsulation("Kyber768") as kem:
        return kem.encap_secret(pubkey)


def kyber_decapsulate(privkey: bytes, ciphertext: bytes) -> bytes:
    """Decapsulate ML-KEM-768. Returns shared_secret."""
    with oqs.KeyEncapsulation("Kyber768", secret_key=privkey) as kem:
        return kem.decap_secret(ciphertext)



def _hkdf_sha256(
    ikm: bytes,
    salt: bytes,
    info: bytes,
    length: int,
) -> bytes:
    """
    HKDF per RFC 5869, SHA-256 variant.  Internal; not part of the public API.

    Steps: Extract (HMAC-SHA256(salt, ikm) → PRK), then Expand.
    """
    # Extract
    if not salt:
        salt = bytes(32)  # RFC 5869 §2.2: if salt not provided, set to HashLen zeros
    prk = _hmac.new(salt, ikm, hashlib.sha256).digest()

    # Expand
    output = b""
    block = b""
    counter = 1
    while len(output) < length:
        block = _hmac.new(
            prk, block + info + bytes([counter]), hashlib.sha256
        ).digest()
        output += block
        counter += 1
    return output[:length]


# ---------------------------------------------------------------------------
# Secretstream wrappers
# ---------------------------------------------------------------------------

class SecretstreamPusher:
    """
    Sender-side secretstream state for exactly one transfer.

    **Not reusable across transfers.**  Each instance wraps a single libsodium
    secretstream push state.  Calling ``push_final()`` permanently exhausts the
    pusher; further calls raise ``RuntimeError``.

    The ``header`` property must be included in the wire preamble *before* any
    encrypted chunks are sent — the receiver needs it to initialise its pull
    state.

    Typical usage::

        pusher = SecretstreamPusher(stream_key)
        out.write(pusher.header)           # 24 bytes; must precede all chunks
        out.write(pusher.push(chunk))      # zero or more TAG_MESSAGE chunks
        out.write(pusher.push_final(last)) # exactly one TAG_FINAL chunk
    """

    def __init__(self, stream_key: bytes) -> None:
        self._state = _nb.crypto_secretstream_xchacha20poly1305_state()
        self._header: bytes = _nb.crypto_secretstream_xchacha20poly1305_init_push(
            self._state, stream_key
        )
        self._finalised: bool = False

    @property
    def header(self) -> bytes:
        """24-byte public stream header.  Embed verbatim in wire preamble."""
        return self._header

    def push(self, plaintext: bytes) -> bytes:
        """
        Encrypt one non-final chunk with ``TAG_MESSAGE``.

        Returns ciphertext (length = len(plaintext) + 17 bytes overhead).

        Raises:
            RuntimeError: if ``push_final`` has already been called.
        """
        if self._finalised:
            raise RuntimeError("SecretstreamPusher is already finalised")
        return _nb.crypto_secretstream_xchacha20poly1305_push(
            self._state, plaintext, ad=None, tag=TAG_MESSAGE
        )

    def push_final(self, plaintext: bytes) -> bytes:
        """
        Encrypt the final chunk with ``TAG_FINAL``.

        ``plaintext`` may be empty if the file size is an exact multiple of
        ``CHUNK_SIZE``.  After this call the pusher is exhausted.

        Raises:
            RuntimeError: if called more than once.
        """
        if self._finalised:
            raise RuntimeError("SecretstreamPusher is already finalised")
        self._finalised = True
        return _nb.crypto_secretstream_xchacha20poly1305_push(
            self._state, plaintext, ad=None, tag=TAG_FINAL
        )


class SecretstreamPuller:
    """
    Receiver-side secretstream state for exactly one transfer.

    **Not reusable across transfers.**  The puller's internal state is consumed
    sequentially; out-of-order or replayed ciphertext will fail authentication.

    Typical usage::

        puller = SecretstreamPuller(stream_key, stream_header)
        while True:
            plaintext, is_final = puller.pull(read_next_chunk(src))
            dest.write(plaintext)
            if is_final:
                break
    """

    def __init__(self, stream_key: bytes, stream_header: bytes) -> None:
        self._state = _nb.crypto_secretstream_xchacha20poly1305_state()
        _nb.crypto_secretstream_xchacha20poly1305_init_pull(
            self._state, stream_header, stream_key
        )

    def pull(self, ciphertext: bytes) -> tuple[bytes, bool]:
        """
        Decrypt and authenticate one chunk.

        Args:
            ciphertext: One encrypted chunk as produced by ``SecretstreamPusher``.

        Returns:
            ``(plaintext, is_final)`` — ``is_final`` is ``True`` iff the chunk
            carried ``TAG_FINAL``, indicating the stream is complete.

        Raises:
            AuthenticationError: AEAD tag mismatch.  Ciphertext was tampered,
                truncated, injected, or fed out of order.
        """
        try:
            plaintext, tag = _nb.crypto_secretstream_xchacha20poly1305_pull(
                self._state, ciphertext, ad=None
            )
        except _NaClCryptoError as exc:
            raise AuthenticationError("Chunk authentication failed") from exc
        return plaintext, (tag == TAG_FINAL)


# ---------------------------------------------------------------------------
# Ed25519 sign / verify
# ---------------------------------------------------------------------------

def sign_digest(privkey_seed: bytes, digest: bytes) -> bytes:
    """
    Sign an arbitrary digest with an Ed25519 private key.

    Args:
        privkey_seed:  32-byte Ed25519 private key seed.
        digest:        Bytes to sign.  Caller is responsible for ensuring
                       this is a cryptographic hash of the actual data,
                       not raw plaintext.

    Returns:
        64-byte Ed25519 signature.
    """
    return SigningKey(privkey_seed).sign(digest).signature


def verify_digest(pubkey: bytes, sig: bytes, digest: bytes) -> None:
    """
    Verify an Ed25519 signature over a digest.

    Args:
        pubkey:   32-byte Ed25519 public key.
        sig:      64-byte signature to verify.
        digest:   The digest that was signed.

    Returns:
        ``None`` on success.

    Raises:
        SignatureError: Signature is invalid, or inputs are malformed.
    """
    try:
        VerifyKey(pubkey).verify(digest, sig)
    except (BadSignatureError, Exception) as exc:
        raise SignatureError("Ed25519 verification failed") from exc

# ---------------------------------------------------------------------------
# Password-Based Encryption (for Keystore)
# ---------------------------------------------------------------------------
import nacl.pwhash
import nacl.secret
import nacl.utils

class WrongPasswordError(Exception):
    """Raised when the provided password fails to decrypt the private key."""

def encrypt_private_key(privkey_data: bytes, password: str, duress_password: str | None = None, fake_privkey_data: bytes | None = None) -> bytes:
    """
    Encrypt a private key using Argon2i for key derivation and XSalsa20-Poly1305.
    Implements Plausible Deniability by storing two indistinguishable slots.
    Total length = 240 bytes (Slot 1: 120 bytes, Slot 2: 120 bytes).
    """
    def _encrypt_slot(data: bytes, pwd: str) -> bytes:
        salt = nacl.utils.random(nacl.pwhash.argon2i.SALTBYTES)
        key = nacl.pwhash.argon2i.kdf(
            nacl.secret.SecretBox.KEY_SIZE,
            pwd.encode('utf-8'),
            salt,
            opslimit=nacl.pwhash.argon2i.OPSLIMIT_INTERACTIVE,
            memlimit=nacl.pwhash.argon2i.MEMLIMIT_INTERACTIVE,
        )
        box = nacl.secret.SecretBox(key)
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        encrypted = box.encrypt(data, nonce)
        return salt + encrypted

    slot1 = _encrypt_slot(privkey_data, password)
    
    if duress_password and fake_privkey_data:
        slot2 = _encrypt_slot(fake_privkey_data, duress_password)
    else:
        # Fill slot 2 with completely random noise
        slot2 = os.urandom(120)

    return slot1 + slot2

def decrypt_private_key(encrypted_data: bytes, password: str) -> bytes:
    """
    Decrypt a private key previously encrypted by `encrypt_private_key`.
    Attempts to decrypt both slots. If the real password is provided, slot 1 decrypts.
    If the duress password is provided, slot 2 decrypts.
    """
    # Legacy check for the old format (88 bytes for 32-byte key, or 120 bytes for 64-byte key)
    # The new deniable format is exactly 240 bytes.
    if len(encrypted_data) != 240:
        if len(encrypted_data) < nacl.pwhash.argon2i.SALTBYTES + nacl.secret.SecretBox.NONCE_SIZE + 16:
            raise WrongPasswordError("Invalid or corrupted private key file.")
        
        # Legacy fallback
        salt = encrypted_data[:nacl.pwhash.argon2i.SALTBYTES]
        ciphertext = encrypted_data[nacl.pwhash.argon2i.SALTBYTES:]
        key = nacl.pwhash.argon2i.kdf(
            nacl.secret.SecretBox.KEY_SIZE,
            password.encode('utf-8'),
            salt,
            opslimit=nacl.pwhash.argon2i.OPSLIMIT_INTERACTIVE,
            memlimit=nacl.pwhash.argon2i.MEMLIMIT_INTERACTIVE,
        )
        box = nacl.secret.SecretBox(key)
        try:
            return box.decrypt(ciphertext)
        except _NaClCryptoError as exc:
            raise WrongPasswordError("Incorrect password.") from exc

    # New Deniable Format (240 bytes)
    slots = [encrypted_data[:120], encrypted_data[120:]]
    for slot in slots:
        salt = slot[:nacl.pwhash.argon2i.SALTBYTES]
        ciphertext = slot[nacl.pwhash.argon2i.SALTBYTES:]
        key = nacl.pwhash.argon2i.kdf(
            nacl.secret.SecretBox.KEY_SIZE,
            password.encode('utf-8'),
            salt,
            opslimit=nacl.pwhash.argon2i.OPSLIMIT_INTERACTIVE,
            memlimit=nacl.pwhash.argon2i.MEMLIMIT_INTERACTIVE,
        )
        box = nacl.secret.SecretBox(key)
        try:
            return box.decrypt(ciphertext)
        except _NaClCryptoError:
            continue
            
    raise WrongPasswordError("Incorrect password (both slots failed).")
