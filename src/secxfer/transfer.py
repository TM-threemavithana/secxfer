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
import os
import struct
import time
import sqlite3
from collections import deque
from pathlib import Path
import threading
from typing import BinaryIO, Protocol, Any
import aiofiles

class AsyncReader(Protocol):
    async def read(self, n: int = -1) -> bytes: ...

class AsyncWriter(Protocol):
    async def write(self, data: bytes) -> Any: ...

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

from secxfer.wire import (
    PROTOCOL_VERSION_V1,
    PROTOCOL_VERSION_V2,
    PREAMBLE_SIZE_V1,
    PREAMBLE_SIZE_V2,
    CHUNK_LEN_SIZE,
    WireError,
    MetadataHeader,
    V1Preamble,
    V2Preamble,
    pack_chunk_len,
    unpack_chunk_len,
)


# ---------------------------------------------------------------------------
# Internal framing helpers
# ---------------------------------------------------------------------------

def _write_chunk(out: AsyncWriter, ciphertext: bytes) -> None:
    raise RuntimeError("Use _write_chunk_async")

async def _write_chunk_async(out: AsyncWriter, ciphertext: bytes) -> None:
    """Write a length-prefixed ciphertext chunk to *out*."""
    await out.write(pack_chunk_len(len(ciphertext)))
    await out.write(ciphertext)


def _read_exact(inp: AsyncReader, n: int) -> bytes:
    raise RuntimeError("Use _read_exact_async")

async def _read_exact_async(inp: AsyncReader, n: int) -> bytes:
    """
    Read exactly *n* bytes from *inp*.

    Raises:
        EOFError: stream ended before *n* bytes were available.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = await inp.read(n - len(buf))
        if not chunk:
            raise EOFError(
                f"Stream ended after {len(buf)} bytes; expected {n}"
            )
        buf += chunk
    return bytes(buf)


def _read_chunk(inp: AsyncReader) -> bytes:
    raise RuntimeError("Use _read_chunk_async")

async def _read_chunk_async(inp: AsyncReader) -> bytes:
    """Read one length-prefixed ciphertext chunk from *inp*."""
    raw_len = await _read_exact_async(inp, CHUNK_LEN_SIZE)
    chunk_len = unpack_chunk_len(raw_len)
    return await _read_exact_async(inp, chunk_len)





# ---------------------------------------------------------------------------
# Nonce cache
# ---------------------------------------------------------------------------

class NonceCache:
    """
    Short-lived cache of seen ``(sender_key_id, transfer_nonce)`` pairs.
    Backed by SQLite for persistence across process restarts.
    """

    def __init__(self, db_path: Path | str | None = None) -> None:
        self._lock = threading.Lock()
        if db_path is None:
            self._conn = sqlite3.connect(":memory:", check_same_thread=False)
        else:
            self._conn = sqlite3.connect(db_path, check_same_thread=False)
        
        self._conn.execute(
            '''CREATE TABLE IF NOT EXISTS nonces (
                sender_key_id BLOB,
                transfer_nonce BLOB,
                expiry REAL,
                PRIMARY KEY (sender_key_id, transfer_nonce)
            )'''
        )
        self._conn.execute('CREATE INDEX IF NOT EXISTS idx_expiry ON nonces(expiry)')
        self._conn.commit()

    def check_and_insert(
        self,
        sender_key_id: bytes,
        transfer_nonce: bytes,
        ttl_seconds: int,
    ) -> None:
        now = time.time()
        expiry = now + ttl_seconds

        with self._lock:
            # Evict expired nonces
            self._conn.execute('DELETE FROM nonces WHERE expiry <= ?', (now,))

            try:
                self._conn.execute(
                    'INSERT INTO nonces (sender_key_id, transfer_nonce, expiry) VALUES (?, ?, ?)',
                    (sender_key_id, transfer_nonce, expiry)
                )
                self._conn.commit()
            except sqlite3.IntegrityError:
                self._conn.rollback()
                raise ReplayError(
                    f"Replay detected: nonce {transfer_nonce.hex()} "
                    f"from sender {sender_key_id.hex()} already seen."
                )

    def __len__(self) -> int:
        with self._lock:
            cursor = self._conn.execute('SELECT COUNT(*) FROM nonces')
            return cursor.fetchone()[0]

    def close(self) -> None:
        self._conn.close()

# ---------------------------------------------------------------------------
# Sender (V1)
# ---------------------------------------------------------------------------

async def send_file_v1(
    identity: LocalIdentity,
    receiver_pubkey_x25519: bytes,
    file_path: Path | str,
    out: AsyncWriter,
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

    await out.write(struct.pack(">B", PROTOCOL_VERSION_V1))
    
    preamble = V1Preamble(
        sender_key_id=identity.key_id,
        stream_salt=stream_salt,
        stream_header=pusher.header
    )
    await out.write(preamble.pack())

    transfer_nonce = os.urandom(16)
    meta = MetadataHeader(
        transfer_nonce=transfer_nonce,
        timestamp=int(time.time()),
        ttl=ttl_seconds,
        filename=file_path.name,
        file_size=file_size,
    )
    await _write_chunk_async(out, pusher.push(meta.pack()))

    h = hashlib.sha256()
    async with aiofiles.open(file_path, "rb") as f:
        if file_size == 0:
            chunk = b'\x00' * chunk_size
            h.update(chunk)
            await _write_chunk_async(out, pusher.push(chunk))
        else:
            while True:
                chunk = await f.read(chunk_size)
                if not chunk:
                    break
                
                if len(chunk) < chunk_size:
                    chunk += b'\x00' * (chunk_size - len(chunk))
                
                h.update(chunk)
                await _write_chunk_async(out, pusher.push(chunk))

    sig = sign_digest(identity.ed25519_seed, h.digest())
    await _write_chunk_async(out, pusher.push_final(sig))

# ---------------------------------------------------------------------------
# Sender (V2)
# ---------------------------------------------------------------------------

async def send_file_v2(
    identity: LocalIdentity,
    receiver_key_id: bytes,
    receiver_prekey_id: str,
    receiver_prekey_pubkey: bytes,
    file_path: Path | str,
    out: AsyncWriter,
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

    await out.write(struct.pack(">B", PROTOCOL_VERSION_V2))
    preamble = V2Preamble(
        sender_key_id=identity.key_id,
        prekey_id_bytes=prekey_id_bytes,
        ephemeral_pub=ephemeral_pub,
        sig=sig,
        stream_salt=stream_salt,
        stream_header=pusher.header
    )
    await out.write(preamble.pack())

    transfer_nonce = os.urandom(16)
    meta = MetadataHeader(
        transfer_nonce=transfer_nonce,
        timestamp=int(time.time()),
        ttl=ttl_seconds,
        filename=file_path.name,
        file_size=file_size,
    )
    await _write_chunk_async(out, pusher.push(meta.pack()))

    h = hashlib.sha256()
    async with aiofiles.open(file_path, "rb") as f:
        if file_size == 0:
            chunk = b'\x00' * chunk_size
            h.update(chunk)
            await _write_chunk_async(out, pusher.push(chunk))
        else:
            while True:
                chunk = await f.read(chunk_size)
                if not chunk:
                    break
                
                if len(chunk) < chunk_size:
                    chunk += b'\x00' * (chunk_size - len(chunk))
                
                h.update(chunk)
                await _write_chunk_async(out, pusher.push(chunk))

    sig_file = sign_digest(identity.ed25519_seed, h.digest())
    await _write_chunk_async(out, pusher.push_final(sig_file))

# ---------------------------------------------------------------------------
# Receiver (Dynamic)
# ---------------------------------------------------------------------------

async def receive_file(
    identity: LocalIdentity,
    keystore: Keystore,
    keystore_dir: Path | str,
    identity_name: str,
    inp: AsyncReader,
    dest_path: Path | str,
    nonce_cache: NonceCache,
) -> None:
    """
    Dynamically read the version byte and route to the correct receiver.
    """
    try:
        version_byte = await _read_exact_async(inp, 1)
    except EOFError as exc:
        raise ProtocolError("Preamble truncated") from exc

    (version,) = struct.unpack(">B", version_byte)
    
    if version == PROTOCOL_VERSION_V1:
        await _receive_v1(identity, keystore, inp, dest_path, nonce_cache)
    elif version == PROTOCOL_VERSION_V2:
        await _receive_v2(identity, keystore, keystore_dir, identity_name, inp, dest_path, nonce_cache)
    else:
        raise VersionError(
            f"Unsupported protocol version: 0x{version:02x}"
        )


async def _receive_v1(
    identity: LocalIdentity,
    keystore: Keystore,
    inp: AsyncReader,
    dest_path: Path | str,
    nonce_cache: NonceCache,
) -> None:
    dest_path = Path(dest_path)
    part_path = dest_path.with_suffix(dest_path.suffix + ".part")

    try:
        raw_preamble = await _read_exact_async(inp, PREAMBLE_SIZE_V1)
    except EOFError as exc:
        raise ProtocolError("Preamble truncated") from exc

    try:
        preamble = V1Preamble.unpack(raw_preamble)
    except WireError as exc:
        raise ProtocolError(str(exc)) from exc

    peer = keystore.get(preamble.sender_key_id)

    stream_key = derive_stream_key(
        identity.x25519_privkey, peer.x25519, preamble.stream_salt
    )
    puller = SecretstreamPuller(stream_key, preamble.stream_header)
    
    await _process_payload(peer, puller, inp, part_path, dest_path, nonce_cache, preamble.sender_key_id)


async def _receive_v2(
    identity: LocalIdentity,
    keystore: Keystore,
    keystore_dir: Path | str,
    identity_name: str,
    inp: AsyncReader,
    dest_path: Path | str,
    nonce_cache: NonceCache,
) -> None:
    dest_path = Path(dest_path)
    part_path = dest_path.with_suffix(dest_path.suffix + ".part")

    try:
        raw_preamble = await _read_exact_async(inp, PREAMBLE_SIZE_V2)
    except EOFError as exc:
        raise ProtocolError("Preamble truncated") from exc

    try:
        preamble = V2Preamble.unpack(raw_preamble)
    except WireError as exc:
        raise ProtocolError(str(exc)) from exc

    peer = keystore.get(preamble.sender_key_id)

    transcript = preamble.ephemeral_pub + identity.key_id + preamble.prekey_id_bytes
    transcript_hash = hashlib.sha256(transcript).digest()
    try:
        verify_digest(peer.ed25519, preamble.sig, transcript_hash)
    except SignatureError as exc:
        raise SignatureError("Sender authentication failed: transcript signature invalid") from exc

    prekey_id = preamble.prekey_id_bytes.decode('ascii').rstrip('\x00')
    try:
        prekey_priv = consume_prekey(keystore_dir, identity_name, prekey_id)
    except FileNotFoundError:
        raise PreKeyConsumedError(f"Pre-Key {prekey_id} does not exist or was already consumed")

    stream_key = derive_stream_key(
        prekey_priv, preamble.ephemeral_pub, preamble.stream_salt
    )
    puller = SecretstreamPuller(stream_key, preamble.stream_header)
    await _process_payload(peer, puller, inp, part_path, dest_path, nonce_cache, preamble.sender_key_id)


async def _process_payload(
    peer, 
    puller, 
    inp: AsyncReader, 
    part_path, 
    dest_path, 
    nonce_cache, 
    sender_key_id
):
    try:
        raw_meta_ct = await _read_chunk_async(inp)
        meta_plaintext, is_final = puller.pull(raw_meta_ct)
    except (EOFError, AuthenticationError) as exc:
        raise AuthenticationError("Metadata chunk failed authentication") from exc

    if is_final:
        raise ProtocolError("Stream ended after metadata chunk; no file data")

    try:
        meta = MetadataHeader.unpack(meta_plaintext)
    except WireError as exc:
        raise ProtocolError(str(exc)) from exc
        
    transfer_nonce = meta.transfer_nonce
    timestamp = meta.timestamp
    ttl = meta.ttl

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
        async with aiofiles.open(part_path, "wb") as part_f:
            got_final = False
            sig = b""
            h = hashlib.sha256()
            while True:
                try:
                    raw_ct = await _read_chunk_async(inp)
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

                await part_f.write(plaintext)
                h.update(plaintext)

        if not got_final:
            _cleanup()
            raise TruncationError("Stream ended without TAG_FINAL")

        try:
            verify_digest(peer.ed25519, sig, h.digest())
        except SignatureError:
            _cleanup()
            raise

        async with aiofiles.open(part_path, "a") as f:
            await f.truncate(meta.file_size)

        os.replace(part_path, dest_path)

    except (AuthenticationError, TruncationError, ProtocolError):
        _cleanup()
        raise
