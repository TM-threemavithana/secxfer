"""
secxfer.transfer — sender/receiver state machines and nonce cache.

This module owns everything from the protocol flow doc that is not a
crypto primitive: wire framing, metadata header serialisation, chunking
loop, TTL check, nonce cache, .part file lifecycle, and atomic rename.

Imports from secxfer.crypto and secxfer.keystore.
Neither of those modules imports from here.

Wire format (see PROTOCOL_FLOW.md for full diagram)
----------------------------------------------------
Preamble (57 bytes, unauthenticated):
    version       : 1 byte  (0x01)
    sender_key_id : 8 bytes (first 8 of SHA-256(x25519_pubkey))
    stream_salt   : 24 bytes (sender random; HKDF salt for stream_key)
    stream_header : 24 bytes (init_push output; needed by init_pull)

    Why two 24-byte fields?  init_push(state, key) -> header generates the
    header internally — the caller cannot supply one.  stream_salt must be
    chosen BEFORE the key (it IS the HKDF salt); stream_header is produced
    AFTER.  One value cannot serve both roles.

Each subsequent chunk is length-prefixed:
    chunk_len     : 4 bytes (uint32 big-endian)
    ciphertext    : chunk_len bytes

Chunk 0 (TAG_MESSAGE) — metadata header, AEAD-protected:
    transfer_nonce : 16 bytes (random, for replay cache)
    timestamp      : 8 bytes  (uint64 big-endian, Unix epoch seconds)
    ttl            : 4 bytes  (uint32 big-endian, seconds)
    filename_len   : 2 bytes  (uint16 big-endian)
    filename       : filename_len bytes (UTF-8)
    file_size      : 8 bytes  (uint64 big-endian, bytes)
    ed25519_sig    : 64 bytes (Ed25519 over SHA-256(plaintext file))

Chunks 1..N-1 (TAG_MESSAGE): plaintext file data, CHUNK_SIZE each.
Chunk N (TAG_FINAL)        : last plaintext bytes (may be empty if
                             file_size is exact multiple of CHUNK_SIZE).

Known limitation
----------------
The sender performs two sequential passes over the file: one full read
to compute SHA-256(plaintext) for the signature (chunk 0 carries it),
then a second read to stream-encrypt the file data.  For large files
this is 2x disk I/O.  Deferred; fixing requires reopening the
header-placement decision.
"""
from __future__ import annotations

import hashlib
import os
import struct
import time
from collections import deque
from pathlib import Path
import threading
from typing import BinaryIO

from secxfer.crypto import (
    CHUNK_SIZE,
    AuthenticationError,
    SecretstreamPuller,
    SecretstreamPusher,
    SignatureError,
    derive_stream_key,
    generate_ephemeral_keypair,
    sign_digest,
    verify_digest,
)
from secxfer.keystore import Keystore, LocalIdentity, UnknownSenderError, consume_prekey


# ---------------------------------------------------------------------------
# Protocol errors
# ---------------------------------------------------------------------------

class ProtocolError(Exception):
    """Base exception for all protocol-level transfer errors."""
    pass


class PreKeyConsumedError(ProtocolError):
    """Raised when attempting to consume a pre-key that is missing or already burned."""
    pass


class VersionError(ProtocolError):
    """Received a preamble with an unsupported protocol version."""


class TTLError(ProtocolError):
    """Transfer timestamp is outside the acceptable TTL window."""


class ReplayError(ProtocolError):
    """Transfer nonce has been seen before; replay rejected."""


class TruncationError(ProtocolError):
    """Stream ended without a TAG_FINAL chunk; transfer was truncated."""


# ---------------------------------------------------------------------------
# Wire format constants
# ---------------------------------------------------------------------------

_PROTOCOL_VERSION: int = 0x02

# Preamble: version(B) + sender_key(8s) + prekey_id(16s) + ephemeral(32s) + sig(64s) + salt(24s) + header(24s)
_PREAMBLE_FMT: str = ">B8s16s32s64s24s24s"
_PREAMBLE_SIZE: int = struct.calcsize(_PREAMBLE_FMT)   # 169 bytes

_CHUNK_LEN_FMT: str = ">I"                             # uint32 big-endian
_CHUNK_LEN_SIZE: int = 4

# Metadata header fixed prefix: nonce(16s) + timestamp(Q) + ttl(I) + fname_len(H)
_META_FIXED_FMT: str = ">16sQIH"
_META_FIXED_SIZE: int = struct.calcsize(_META_FIXED_FMT)  # 30 bytes

_FILE_SIZE_FMT: str = ">Q"
_FILE_SIZE_SIZE: int = 8
_SIG_SIZE: int = 64


# ---------------------------------------------------------------------------
# Internal framing helpers
# ---------------------------------------------------------------------------

def _write_chunk(out: BinaryIO, ciphertext: bytes) -> None:
    """Write a length-prefixed ciphertext chunk to *out*."""
    out.write(struct.pack(_CHUNK_LEN_FMT, len(ciphertext)))
    out.write(ciphertext)


def _read_exact(inp: BinaryIO, n: int) -> bytes:
    """
    Read exactly *n* bytes from *inp*.

    Raises:
        EOFError: stream ended before *n* bytes were available.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = inp.read(n - len(buf))
        if not chunk:
            raise EOFError(
                f"Stream ended after {len(buf)} bytes; expected {n}"
            )
        buf += chunk
    return bytes(buf)


def _read_chunk(inp: BinaryIO) -> bytes:
    """Read one length-prefixed ciphertext chunk from *inp*."""
    raw_len = _read_exact(inp, _CHUNK_LEN_SIZE)
    (chunk_len,) = struct.unpack(_CHUNK_LEN_FMT, raw_len)
    return _read_exact(inp, chunk_len)


# ---------------------------------------------------------------------------
# Metadata header serialisation / deserialisation
# ---------------------------------------------------------------------------

def _pack_metadata(
    transfer_nonce: bytes,
    timestamp: int,
    ttl: int,
    filename: str,
    file_size: int,
) -> bytes:
    fname_bytes = filename.encode("utf-8")
    return (
        struct.pack(_META_FIXED_FMT, transfer_nonce, timestamp, ttl, len(fname_bytes))
        + fname_bytes
        + struct.pack(_FILE_SIZE_FMT, file_size)
    )


def _unpack_metadata(raw: bytes) -> dict:
    if len(raw) < _META_FIXED_SIZE:
        raise ProtocolError("Metadata header too short")

    transfer_nonce, timestamp, ttl, fname_len = struct.unpack_from(
        _META_FIXED_FMT, raw, 0
    )
    offset = _META_FIXED_SIZE
    required = offset + fname_len + _FILE_SIZE_SIZE

    if len(raw) < required:
        raise ProtocolError(
            f"Metadata header truncated: need {required} bytes, got {len(raw)}"
        )

    filename = raw[offset : offset + fname_len].decode("utf-8")
    offset += fname_len
    (file_size,) = struct.unpack_from(_FILE_SIZE_FMT, raw, offset)

    return {
        "transfer_nonce": transfer_nonce,
        "timestamp": timestamp,
        "ttl": ttl,
        "filename": filename,
        "file_size": file_size,
    }


# ---------------------------------------------------------------------------
# Nonce cache
# ---------------------------------------------------------------------------

class NonceCache:
    """
    Short-lived cache of seen ``(sender_key_id, transfer_nonce)`` pairs.

    Provides replay protection within the TTL window.  The cache is in-memory
    only: it resets on process restart and does not prevent replay across
    separate processes (separate memory spaces, no shared state — not a
    thread-safety issue, a "no shared state exists" issue; fix with an
    external store such as Redis).

    Thread safety
    -------------
    ``check_and_insert`` is protected by a ``threading.Lock``.  The lock
    serialises the eviction pass, the presence check, and the insert as a
    single atomic unit — no thread can observe a partially-updated state.
    This is a concrete guarantee, not an argument about CPython bytecode
    granularity or the GIL.

    Eviction is **automatic and amortised** inside ``check_and_insert``:
    a deque of ``(expiry_time, key)`` pairs is maintained in insertion order
    (which equals expiry order for uniform TTL); expired entries are popped
    from the front in O(1) amortised time.  No external eviction call is
    needed.
    """

    def __init__(self) -> None:
        self._cache: dict[tuple[bytes, bytes], float] = {}
        self._queue: deque[tuple[float, tuple[bytes, bytes]]] = deque()
        self._lock = threading.Lock()

    def check_and_insert(
        self,
        sender_key_id: bytes,
        transfer_nonce: bytes,
        ttl_seconds: int,
    ) -> None:
        """
        Atomically check whether ``(sender_key_id, transfer_nonce)`` has been
        seen and, if not, record it.

        Args:
            sender_key_id:   8-byte key identifier from the wire preamble.
            transfer_nonce:  16-byte nonce from the metadata header.
            ttl_seconds:     How long (seconds) to remember this nonce.

        Raises:
            ReplayError: ``(sender_key_id, transfer_nonce)`` was already seen.
        """
        now = time.monotonic()
        key = (sender_key_id, transfer_nonce)

        with self._lock:
            # Amortised eviction: pop expired entries from the front.
            # Lazy deletion: skip queue entries whose stored expiry no longer
            # matches the cache (defensive guard against future changes).
            while self._queue:
                expiry, queued_key = self._queue[0]
                if expiry > now:
                    break
                self._queue.popleft()
                if self._cache.get(queued_key) == expiry:
                    del self._cache[queued_key]

            if key in self._cache:
                raise ReplayError(
                    f"Replay detected: nonce {transfer_nonce.hex()} "
                    f"from sender {sender_key_id.hex()} already seen."
                )
            expiry = now + ttl_seconds
            self._cache[key] = expiry
            self._queue.append((expiry, key))

    def __len__(self) -> int:
        return len(self._cache)


# ---------------------------------------------------------------------------
# Sender
# ---------------------------------------------------------------------------

def send_file(
    identity: LocalIdentity,
    receiver_key_id: bytes,
    receiver_prekey_id: str,
    receiver_prekey_pubkey: bytes,
    file_path: Path | str,
    out: BinaryIO,
    ttl_seconds: int = 300,
    chunk_size: int = CHUNK_SIZE,
) -> None:
    """
    Encrypt and send a file to *out*.

    Performs two sequential passes over *file_path* (see module docstring
    for the known limitation).  *out* is written sequentially; the caller
    controls what it is backed by (socket, file, pipe, …).

    Protocol flow:
        ① Hash entire file (pass 1) → plaintext_hash
        ② Sign plaintext_hash with Ed25519 → sig
        ③ Generate stream_salt (24 random bytes, HKDF salt)
        ④ Derive stream_key = HKDF(X25519(sender_priv, recv_pub), stream_salt)
        ⑤ Init SecretstreamPusher(stream_key) → pusher.header (stream_header)
        ⑥ Write preamble: version|sender_key_id|stream_salt|stream_header
        ⑦ Push chunk 0 (TAG_MESSAGE): serialised metadata header
        ⑧ Read file in chunk_size blocks, updating hash; push each as TAG_MESSAGE
        ⑨ Push trailer chunk (TAG_FINAL): 64-byte Ed25519 signature
    Args:
        identity:               Sender's ``LocalIdentity`` (from keystore).
        receiver_key_id:        Receiver's 8-byte key ID.
        receiver_prekey_id:     16-char hex string of the receiver's pre-key ID.
        receiver_prekey_pubkey: Receiver's 32-byte Curve25519 pre-key public key.
        file_path:              Path to the plaintext file.
        out:                    Writable binary stream.
        ttl_seconds:            TTL embedded in the metadata header.
        chunk_size:             Plaintext chunk size in bytes.
    """
    file_path = Path(file_path)

    # ① Stat file (no hashing pass needed) -----------------------------------
    file_size = file_path.stat().st_size

    # ③ Stream salt (must exist before key derivation) -----------------------
    stream_salt = os.urandom(24)

    # ④ Generate Ephemeral Key and Derive stream key -----------------------
    ephemeral_priv, ephemeral_pub = generate_ephemeral_keypair()
    stream_key = derive_stream_key(
        ephemeral_priv, receiver_prekey_pubkey, stream_salt
    )

    # ⑤ Init secretstream; stream_header is generated internally by init_push
    pusher = SecretstreamPusher(stream_key)

    # ⑥ Write preamble (with Context-Bound Signature) -----------------------
    prekey_id_bytes = receiver_prekey_id.encode('ascii')
    transcript = ephemeral_pub + receiver_key_id + prekey_id_bytes
    transcript_digest = hashlib.sha256(transcript).digest()
    sig = sign_digest(identity.ed25519_seed, transcript_digest)

    out.write(
        struct.pack(
            _PREAMBLE_FMT,
            _PROTOCOL_VERSION,
            identity.key_id,
            prekey_id_bytes,
            ephemeral_pub,
            sig,
            stream_salt,
            pusher.header,
        )
    )

    # ⑦ Push metadata chunk (chunk 0, TAG_MESSAGE) ---------------------------
    transfer_nonce = os.urandom(16)
    meta_plaintext = _pack_metadata(
        transfer_nonce=transfer_nonce,
        timestamp=int(time.time()),
        ttl=ttl_seconds,
        filename=file_path.name,
        file_size=file_size,
    )
    _write_chunk(out, pusher.push(meta_plaintext))

    # ⑧ Stream file data and hash incrementally (TAG_MESSAGE) ----------------
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
            _write_chunk(out, pusher.push(chunk))

    # ⑨ Trailer Signature (TAG_FINAL) ----------------------------------------
    sig = sign_digest(identity.ed25519_seed, h.digest())
    _write_chunk(out, pusher.push_final(sig))


# ---------------------------------------------------------------------------
def receive_file(
    identity: LocalIdentity,
    keystore: Keystore,
    keystore_dir: Path | str,
    identity_name: str,
    inp: BinaryIO,
    dest_path: Path | str,
    nonce_cache: NonceCache,
) -> None:
    """
    Receive, decrypt, and verify a file from *inp*, writing to *dest_path*.

    *dest_path* is never created in a partial or unverified state:
      - Decrypted bytes are written to ``<dest_path>.part``.
      - ``<dest_path>`` is created only via an atomic ``os.replace()`` call
        after all chunks pass authentication AND the Ed25519 signature verifies.
      - On any failure, ``<dest_path>.part`` is deleted before raising.

    Protocol flow:
        ① Read preamble → version check → keystore lookup
        ② Derive stream_key; init SecretstreamPuller
        ③ Pull chunk 0 → deserialise metadata
        ④ TTL check (stateless, no cache mutation on failure)
        ⑤ Atomic nonce cache check-and-insert
        ⑥ Open <dest_path>.part for writing
        ⑦ Pull data chunks → write to .part; detect TAG_FINAL
        ⑧ Verify Ed25519 sig over SHA-256(<dest_path>.part)
           On success → os.replace(.part, dest_path)
           On failure → delete .part → raise SignatureError

    Args:
        identity:     Receiver's ``LocalIdentity`` (from keystore).
        keystore:     Loaded ``Keystore`` with trusted sender public keys.
        inp:          Readable binary stream.
        dest_path:    Path where the decrypted file will be written on success.
        nonce_cache:  Shared ``NonceCache`` instance for this receiver process.

    Raises:
        VersionError:        Unsupported protocol version in preamble.
        UnknownSenderError:  Sender's key_id not found in keystore.
        AuthenticationError: AEAD tag failed on any chunk.
        TTLError:            Transfer timestamp outside TTL window.
        ReplayError:         Transfer nonce already seen.
        TruncationError:     Stream ended without TAG_FINAL.
        SignatureError:      Ed25519 signature did not verify.
        ProtocolError:       Malformed metadata header.
    """
    dest_path = Path(dest_path)
    part_path = dest_path.with_suffix(dest_path.suffix + ".part")

    # ① Read and validate preamble -------------------------------------------
    try:
        raw_preamble = _read_exact(inp, _PREAMBLE_SIZE)
    except EOFError as exc:
        raise ProtocolError("Preamble truncated") from exc

    version, sender_key_id, prekey_id_bytes, ephemeral_pub, sig, stream_salt, stream_header = struct.unpack(
        _PREAMBLE_FMT, raw_preamble
    )

    if version != _PROTOCOL_VERSION:
        raise VersionError(
            f"Unsupported protocol version: 0x{version:02x} "
            f"(expected 0x{_PROTOCOL_VERSION:02x})"
        )

    # Raises UnknownSenderError if not found
    peer = keystore.get(sender_key_id)

    # ② Verify Sender Authentication over Context-Bound Transcript -----------
    transcript = ephemeral_pub + identity.key_id + prekey_id_bytes
    transcript_digest = hashlib.sha256(transcript).digest()
    try:
        verify_digest(peer.ed25519, sig, transcript_digest)
    except SignatureError as exc:
        raise ProtocolError("Sender authentication failed (invalid signature or context mismatch)") from exc

    # ③ Atomically Consume Pre-Key -------------------------------------------
    prekey_id = prekey_id_bytes.decode('ascii')
    try:
        prekey_priv = consume_prekey(keystore_dir, identity_name, prekey_id)
    except FileNotFoundError:
        raise PreKeyConsumedError(f"Pre-Key {prekey_id} does not exist or was already consumed")

    # ④ Derive stream key and init puller ------------------------------------
    stream_key = derive_stream_key(
        prekey_priv, ephemeral_pub, stream_salt
    )
    puller = SecretstreamPuller(stream_key, stream_header)

    # ⑤ Pull metadata chunk (chunk 0) ----------------------------------------
    try:
        raw_meta_ct = _read_chunk(inp)
        meta_plaintext, is_final = puller.pull(raw_meta_ct)
    except (EOFError, AuthenticationError) as exc:
        raise AuthenticationError("Metadata chunk failed authentication") from exc

    if is_final:
        raise ProtocolError("Stream ended after metadata chunk; no file data")

    meta = _unpack_metadata(meta_plaintext)
    transfer_nonce: bytes = meta["transfer_nonce"]
    timestamp: int = meta["timestamp"]
    ttl: int = meta["ttl"]

    # ⑥ TTL check (stateless — no cache mutation on failure) -----------------
    now = time.time()
    if now - timestamp > ttl:
        raise TTLError(
            f"Transfer expired: timestamp={timestamp}, ttl={ttl}, "
            f"age={int(now - timestamp)}s"
        )

    # ⑦ Atomic nonce cache check-and-insert ---------------------------------
    nonce_cache.check_and_insert(sender_key_id, transfer_nonce, ttl)

    # ⑧ Open .part file for writing ------------------------------------------
    def _cleanup() -> None:
        """Delete .part file if it exists; best-effort."""
        try:
            part_path.unlink(missing_ok=True)
        except OSError:
            pass

    try:
        with part_path.open("wb") as part_f:

            # ⑨ Pull data chunks → write to .part ----------------------------
            got_final = False
            sig = b""
            h = hashlib.sha256()
            while True:
                try:
                    raw_ct = _read_chunk(inp)
                except EOFError as exc:
                    raise TruncationError(
                        "Stream ended before TAG_FINAL"
                    ) from exc

                try:
                    plaintext, is_final = puller.pull(raw_ct)
                except AuthenticationError:
                    raise  # cleanup happens in outer except

                if is_final:
                    if len(plaintext) != 64:
                        raise ProtocolError(f"Trailer signature chunk must be exactly 64 bytes, got {len(plaintext)}")
                    sig = plaintext
                    got_final = True
                    break

                part_f.write(plaintext)
                h.update(plaintext)

        if not got_final:
            # Should not be reachable, but guard defensively
            _cleanup()
            raise TruncationError("Stream ended without TAG_FINAL")

        # ⑩ Verify Ed25519 signature over SHA-256(plaintext) -----------------
        try:
            verify_digest(peer.ed25519, sig, h.digest())
        except SignatureError:
            _cleanup()
            raise

        # All checks passed — atomic move to destination ---------------------
        os.replace(part_path, dest_path)

    except (AuthenticationError, TruncationError, ProtocolError):
        _cleanup()
        raise
