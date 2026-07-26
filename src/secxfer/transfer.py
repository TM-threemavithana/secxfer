"""
secxfer.transfer — sender/receiver state machines and nonce cache.

This module owns everything from the protocol flow doc that is not a
crypto primitive: wire framing, metadata header serialisation, chunking
loop, TTL check, nonce cache, .part file lifecycle, and atomic rename.

Supports both V1 (Peer-to-Peer) and V2 (Forward Secrecy / Server-Assisted).
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

_PROTOCOL_VERSION_V1: int = 0x01
_PREAMBLE_FMT_V1: str = ">8s24s24s" # (version byte read separately)
_PREAMBLE_SIZE_V1: int = struct.calcsize(_PREAMBLE_FMT_V1)

_PROTOCOL_VERSION_V2: int = 0x02
_PREAMBLE_FMT_V2: str = ">8s16s32s64s24s24s" # (version byte read separately)
_PREAMBLE_SIZE_V2: int = struct.calcsize(_PREAMBLE_FMT_V2)

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
        now = time.monotonic()
        key = (sender_key_id, transfer_nonce)

        with self._lock:
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
# Sender (V1)
# ---------------------------------------------------------------------------

def send_file_v1(
    identity: LocalIdentity,
    receiver_pubkey_x25519: bytes,
    file_path: Path | str,
    out: BinaryIO,
    ttl_seconds: int = 300,
    chunk_size: int = CHUNK_SIZE,
) -> None:
    """
    Encrypt and send a file using the V1 (Peer-to-Peer) protocol.
    """
    file_path = Path(file_path)
    file_size = file_path.stat().st_size
    stream_salt = os.urandom(24)

    stream_key = derive_stream_key(
        identity.x25519_privkey, receiver_pubkey_x25519, stream_salt
    )
    pusher = SecretstreamPusher(stream_key)

    out.write(struct.pack(">B", _PROTOCOL_VERSION_V1))
    out.write(
        struct.pack(
            _PREAMBLE_FMT_V1,
            identity.key_id,
            stream_salt,
            pusher.header,
        )
    )

    transfer_nonce = os.urandom(16)
    meta_plaintext = _pack_metadata(
        transfer_nonce=transfer_nonce,
        timestamp=int(time.time()),
        ttl=ttl_seconds,
        filename=file_path.name,
        file_size=file_size,
    )
    _write_chunk(out, pusher.push(meta_plaintext))

    h = hashlib.sha256()
    with file_path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
            _write_chunk(out, pusher.push(chunk))

    sig = sign_digest(identity.ed25519_seed, h.digest())
    _write_chunk(out, pusher.push_final(sig))

# ---------------------------------------------------------------------------
# Sender (V2)
# ---------------------------------------------------------------------------

def send_file_v2(
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
    Encrypt and send a file using the V2 (Forward Secrecy / Server-Assisted) protocol.
    """
    file_path = Path(file_path)
    file_size = file_path.stat().st_size
    stream_salt = os.urandom(24)

    ephemeral_priv, ephemeral_pub = generate_ephemeral_keypair()
    stream_key = derive_stream_key(ephemeral_priv, receiver_prekey_pubkey, stream_salt)
    pusher = SecretstreamPusher(stream_key)

    prekey_id_bytes = receiver_prekey_id.encode('ascii')
    prekey_id_bytes = prekey_id_bytes.ljust(16, b'\x00')

    transcript = ephemeral_pub + receiver_key_id + prekey_id_bytes
    transcript_hash = hashlib.sha256(transcript).digest()
    sig = sign_digest(identity.ed25519_seed, transcript_hash)

    out.write(struct.pack(">B", _PROTOCOL_VERSION_V2))
    out.write(
        struct.pack(
            _PREAMBLE_FMT_V2,
            identity.key_id,
            prekey_id_bytes,
            ephemeral_pub,
            sig,
            stream_salt,
            pusher.header,
        )
    )

    transfer_nonce = os.urandom(16)
    meta_plaintext = _pack_metadata(
        transfer_nonce=transfer_nonce,
        timestamp=int(time.time()),
        ttl=ttl_seconds,
        filename=file_path.name,
        file_size=file_size,
    )
    _write_chunk(out, pusher.push(meta_plaintext))

    h = hashlib.sha256()
    with file_path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
            _write_chunk(out, pusher.push(chunk))

    sig_file = sign_digest(identity.ed25519_seed, h.digest())
    _write_chunk(out, pusher.push_final(sig_file))

# ---------------------------------------------------------------------------
# Receiver (Dynamic)
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
    Dynamically read the version byte and route to the correct receiver.
    """
    try:
        version_byte = _read_exact(inp, 1)
    except EOFError as exc:
        raise ProtocolError("Preamble truncated") from exc

    (version,) = struct.unpack(">B", version_byte)
    
    if version == _PROTOCOL_VERSION_V1:
        _receive_v1(identity, keystore, inp, dest_path, nonce_cache)
    elif version == _PROTOCOL_VERSION_V2:
        _receive_v2(identity, keystore, keystore_dir, identity_name, inp, dest_path, nonce_cache)
    else:
        raise VersionError(
            f"Unsupported protocol version: 0x{version:02x}"
        )


def _receive_v1(
    identity: LocalIdentity,
    keystore: Keystore,
    inp: BinaryIO,
    dest_path: Path | str,
    nonce_cache: NonceCache,
) -> None:
    dest_path = Path(dest_path)
    part_path = dest_path.with_suffix(dest_path.suffix + ".part")

    try:
        raw_preamble = _read_exact(inp, _PREAMBLE_SIZE_V1)
    except EOFError as exc:
        raise ProtocolError("Preamble truncated") from exc

    sender_key_id, stream_salt, stream_header = struct.unpack(
        _PREAMBLE_FMT_V1, raw_preamble
    )

    peer = keystore.get(sender_key_id)

    stream_key = derive_stream_key(
        identity.x25519_privkey, peer.x25519, stream_salt
    )
    puller = SecretstreamPuller(stream_key, stream_header)
    
    _process_payload(peer, puller, inp, part_path, dest_path, nonce_cache, sender_key_id)


def _receive_v2(
    identity: LocalIdentity,
    keystore: Keystore,
    keystore_dir: Path | str,
    identity_name: str,
    inp: BinaryIO,
    dest_path: Path | str,
    nonce_cache: NonceCache,
) -> None:
    dest_path = Path(dest_path)
    part_path = dest_path.with_suffix(dest_path.suffix + ".part")

    try:
        raw_preamble = _read_exact(inp, _PREAMBLE_SIZE_V2)
    except EOFError as exc:
        raise ProtocolError("Preamble truncated") from exc

    sender_key_id, prekey_id_bytes, ephemeral_pub, sig, stream_salt, stream_header = struct.unpack(
        _PREAMBLE_FMT_V2, raw_preamble
    )

    peer = keystore.get(sender_key_id)

    transcript = ephemeral_pub + identity.key_id + prekey_id_bytes
    transcript_hash = hashlib.sha256(transcript).digest()
    try:
        verify_digest(peer.ed25519, sig, transcript_hash)
    except SignatureError as exc:
        raise SignatureError("Sender authentication failed: transcript signature invalid") from exc

    prekey_id = prekey_id_bytes.decode('ascii').rstrip('\x00')
    try:
        prekey_priv = consume_prekey(keystore_dir, identity_name, prekey_id)
    except FileNotFoundError:
        raise PreKeyConsumedError(f"Pre-Key {prekey_id} does not exist or was already consumed")

    stream_key = derive_stream_key(
        prekey_priv, ephemeral_pub, stream_salt
    )
    puller = SecretstreamPuller(stream_key, stream_header)
    
    _process_payload(peer, puller, inp, part_path, dest_path, nonce_cache, sender_key_id)


def _process_payload(
    peer, 
    puller, 
    inp, 
    part_path, 
    dest_path, 
    nonce_cache, 
    sender_key_id
):
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

    now = time.time()
    if now - timestamp > ttl:
        raise TTLError(
            f"Transfer expired: timestamp={timestamp}, ttl={ttl}, "
            f"age={int(now - timestamp)}s"
        )

    nonce_cache.check_and_insert(sender_key_id, transfer_nonce, ttl)

    def _cleanup() -> None:
        try:
            part_path.unlink(missing_ok=True)
        except OSError:
            pass

    try:
        with part_path.open("wb") as part_f:
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
                    raise

                if is_final:
                    if len(plaintext) != 64:
                        raise ProtocolError(f"Trailer signature chunk must be exactly 64 bytes, got {len(plaintext)}")
                    sig = plaintext
                    got_final = True
                    break

                part_f.write(plaintext)
                h.update(plaintext)

        if not got_final:
            _cleanup()
            raise TruncationError("Stream ended without TAG_FINAL")

        try:
            verify_digest(peer.ed25519, sig, h.digest())
        except SignatureError:
            _cleanup()
            raise

        os.replace(part_path, dest_path)

    except (AuthenticationError, TruncationError, ProtocolError):
        _cleanup()
        raise
