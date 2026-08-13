"""
secxfer.transfer — sender/receiver state machines and nonce cache.

This module handles wire framing, metadata header serialisation, chunking
loop, TTL check, and nonce cache.
Refactored for Store-and-Forward: Operates on bytes/files instead of async sockets.
"""
import hashlib
import os
import struct
import time
import sqlite3
from pathlib import Path
import threading
from typing import AsyncGenerator
import aiofiles

from secxfer.constants import DEFAULT_TTL, CLOCK_SKEW_TOLERANCE, ED25519_SIG_LEN
from secxfer.crypto import (
    CHUNK_SIZE,
    AuthenticationError,
    SecretstreamPuller,
    SecretstreamPusher,
    SignatureError,
    derive_stream_key,
    generate_ephemeral_keypair,
    kyber_encapsulate,
    kyber_decapsulate,
    sign_digest,
    verify_digest,
)
from secxfer.keystore import Keystore, LocalIdentity, UnknownSenderError, consume_prekey
from secxfer.wire import (
    PROTOCOL_VERSION_V2,
    PREAMBLE_SIZE_V2,
    CHUNK_LEN_SIZE,
    WireError,
    MetadataHeader,
    V2Preamble,
    pack_chunk_len,
    unpack_chunk_len,
)

class ProtocolError(Exception): pass
class PreKeyConsumedError(ProtocolError): pass
class VersionError(ProtocolError): pass
class TTLError(ProtocolError): pass
class ReplayError(ProtocolError): pass
class TruncationError(ProtocolError): pass

MAX_CHUNK_SIZE: int = CHUNK_SIZE + 512

class NonceCache:
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
        self._conn.execute('PRAGMA journal_mode=WAL;')
        self._conn.commit()

    def check_and_insert(self, sender_key_id: bytes, transfer_nonce: bytes, ttl_seconds: int) -> None:
        now = time.time()
        expiry = now + ttl_seconds
        with self._lock:
            self._conn.execute('DELETE FROM nonces WHERE expiry <= ?', (now,))
            try:
                self._conn.execute(
                    'INSERT INTO nonces (sender_key_id, transfer_nonce, expiry) VALUES (?, ?, ?)',
                    (sender_key_id, transfer_nonce, expiry)
                )
                self._conn.commit()
            except sqlite3.IntegrityError:
                self._conn.rollback()
                raise ReplayError("Replay detected: nonce already seen.")

    def close(self) -> None:
        self._conn.close()
async def build_file_v2(
    identity: LocalIdentity,
    receiver_key_id: bytes,
    receiver_prekey_id: str,
    receiver_prekey_pubkey: bytes,
    receiver_kyber_pubkey: bytes,
    file_path: Path | str,
    ttl_seconds: int = DEFAULT_TTL,
    chunk_size: int = CHUNK_SIZE,
) -> AsyncGenerator[bytes, None]:
    """Builds the encrypted V2 payload and yields chunks for streaming upload."""
    file_path = Path(file_path)
    file_size = file_path.stat().st_size
    stream_salt = os.urandom(24)

    ephemeral_priv, ephemeral_pub = generate_ephemeral_keypair()
    
    kyber_ct, kyber_ss = kyber_encapsulate(receiver_kyber_pubkey)

    stream_key = derive_stream_key(ephemeral_priv, receiver_prekey_pubkey, stream_salt, kyber_secret=kyber_ss)
    pusher = SecretstreamPusher(stream_key)

    prekey_id_bytes = receiver_prekey_id.encode('ascii').ljust(16, b'\x00')
    transcript = ephemeral_pub + receiver_key_id + prekey_id_bytes
    transcript_hash = hashlib.sha256(transcript).digest()
    sig = sign_digest(identity.ed25519_seed, transcript_hash)

    payload = bytearray()
    payload.extend(struct.pack(">B", PROTOCOL_VERSION_V2))
    preamble = V2Preamble(
        sender_key_id=identity.key_id,
        prekey_id_bytes=prekey_id_bytes,
        ephemeral_pub=ephemeral_pub,
        sig=sig,
        stream_salt=stream_salt,
        stream_header=pusher.header,
        kyber_ciphertext=kyber_ct
    )
    payload.extend(preamble.pack())
    yield bytes(payload)

    transfer_nonce = os.urandom(16)
    meta = MetadataHeader(
        transfer_nonce=transfer_nonce,
        timestamp=int(time.time()),
        ttl=ttl_seconds,
        filename=file_path.name,
        file_size=file_size,
    )
    enc_meta = pusher.push(meta.pack())
    yield pack_chunk_len(len(enc_meta)) + enc_meta

    h = hashlib.sha256()
    async with aiofiles.open(file_path, "rb") as f:
        if file_size == 0:
            enc = pusher.push_final(sign_digest(identity.ed25519_seed, h.digest()))
            yield pack_chunk_len(len(enc)) + enc
        else:
            while True:
                chunk = await f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
                enc = pusher.push(chunk)
                yield pack_chunk_len(len(enc)) + enc
            
            sig_file = sign_digest(identity.ed25519_seed, h.digest())
            enc_final = pusher.push_final(sig_file)
            yield pack_chunk_len(len(enc_final)) + enc_final

def decrypt_file_v2(
    identity: LocalIdentity,
    keystore: Keystore,
    keystore_dir: Path | str,
    ciphertext: bytes,
    dest_path: Path | str,
    nonce_cache: NonceCache,
    identity_name: str = "identity",
) -> None:
    """Decrypts a downloaded V2 payload."""
    if not ciphertext:
        raise EOFError("Empty payload")
    
    version = ciphertext[0]
    if version != PROTOCOL_VERSION_V2:
        raise VersionError(f"Unsupported protocol version: {version}")
        
    offset = 1
    if len(ciphertext) < offset + PREAMBLE_SIZE_V2:
        raise TruncationError("Truncated V2 preamble")
        
    preamble = V2Preamble.unpack(ciphertext[offset : offset + PREAMBLE_SIZE_V2])
    offset += PREAMBLE_SIZE_V2
    
    sender_peer = keystore.get(preamble.sender_key_id)
    prekey_id_str = preamble.prekey_id_bytes.rstrip(b'\x00').decode('ascii')
    
    transcript = preamble.ephemeral_pub + identity.key_id + preamble.prekey_id_bytes
    transcript_hash = hashlib.sha256(transcript).digest()
    verify_digest(sender_peer.ed25519, preamble.sig, transcript_hash)

    try:
        local_priv = consume_prekey(keystore_dir, identity_name, prekey_id_str)
    except FileNotFoundError as exc:
        raise PreKeyConsumedError(f"Pre-key {prekey_id_str} not found or already burned.") from exc

    kyber_ss = kyber_decapsulate(identity.kyber_privkey, preamble.kyber_ciphertext)

    stream_key = derive_stream_key(local_priv, preamble.ephemeral_pub, preamble.stream_salt, kyber_secret=kyber_ss)
    puller = SecretstreamPuller(stream_key, preamble.stream_header)

    # Read Metadata
    raw_len = ciphertext[offset : offset + CHUNK_LEN_SIZE]
    if len(raw_len) != CHUNK_LEN_SIZE:
        raise TruncationError("Truncated metadata length field")
    offset += CHUNK_LEN_SIZE
    chunk_len = unpack_chunk_len(raw_len)
    if chunk_len > MAX_CHUNK_SIZE:
        raise ProtocolError("Metadata chunk exceeds maximum size")
    
    enc_meta = ciphertext[offset : offset + chunk_len]
    if len(enc_meta) != chunk_len:
        raise TruncationError("Truncated metadata chunk")
    offset += chunk_len
    meta_bytes, is_final = puller.pull(enc_meta)
    if is_final:
        raise ProtocolError("Metadata chunk missing TAG_MESSAGE")
        
    meta = MetadataHeader.unpack(meta_bytes)
    now = time.time()
    if now > meta.timestamp + meta.ttl or now < meta.timestamp - CLOCK_SKEW_TOLERANCE:
        raise TTLError("Transfer TTL expired")
    nonce_cache.check_and_insert(preamble.sender_key_id, meta.transfer_nonce, meta.ttl)

    dest_path = Path(dest_path)
    dest_path.mkdir(parents=True, exist_ok=True)
    # A11: Safe filename extraction
    safe_filename = os.path.basename(meta.filename)
    if not safe_filename or safe_filename in ('.', '..'):
        safe_filename = "unnamed_transfer.bin"
        
    out_file = dest_path / safe_filename
    # Handle duplicates
    counter = 1
    while out_file.exists():
        out_file = dest_path / f"{safe_filename}.{counter}"
        counter += 1

    part_file = out_file.with_suffix('.part')
    h = hashlib.sha256()
    bytes_written = 0

    final_seen = False
    try:
        with open(part_file, 'wb') as f:
            while offset < len(ciphertext):
                raw_len = ciphertext[offset : offset + CHUNK_LEN_SIZE]
                offset += CHUNK_LEN_SIZE
                if len(raw_len) != CHUNK_LEN_SIZE:
                    raise TruncationError("Truncated chunk length field")
                chunk_len = unpack_chunk_len(raw_len)
                if chunk_len > MAX_CHUNK_SIZE:
                    raise ProtocolError("Ciphertext chunk exceeds maximum size")
            
                enc_chunk = ciphertext[offset : offset + chunk_len]
                offset += chunk_len
                if len(enc_chunk) != chunk_len:
                    raise TruncationError("Truncated ciphertext chunk")
                plaintext, is_final = puller.pull(enc_chunk)
            
                if is_final:
                    if len(plaintext) != ED25519_SIG_LEN:
                        raise ProtocolError(f"Trailer chunk does not contain exactly a {ED25519_SIG_LEN}-byte Ed25519 signature.")
                    verify_digest(sender_peer.ed25519, plaintext, h.digest())
                    final_seen = True
                    break
                remaining = meta.file_size - bytes_written
                if remaining <= 0 or len(plaintext) > remaining:
                    raise ProtocolError("Payload contains more data than declared in metadata")
                f.write(plaintext)
                h.update(plaintext)
                bytes_written += len(plaintext)
        if not final_seen:
            raise TruncationError("Missing final authenticated trailer")
        if bytes_written != meta.file_size:
            raise TruncationError("Payload ended before the declared file size")
        if offset != len(ciphertext):
            raise ProtocolError("Trailing data after final authenticated trailer")
        part_file.replace(out_file)
    except Exception:
        if part_file.exists():
            part_file.unlink()
        raise


def _decrypt_v2_stream(
    identity: LocalIdentity,
    keystore: Keystore,
    keystore_dir: Path | str,
    fh,  # binary file handle — reads sequentially, never loads full payload
    dest_path: Path | str,
    nonce_cache: NonceCache,
    identity_name: str = "identity",
) -> None:
    """Internal: true streaming decryption from any binary file handle."""
    version_byte = fh.read(1)
    if not version_byte:
        raise EOFError("Empty payload")
    version = version_byte[0]
    if version != PROTOCOL_VERSION_V2:
        raise VersionError(f"Unsupported protocol version: {version}")

    preamble_bytes = fh.read(PREAMBLE_SIZE_V2)
    if len(preamble_bytes) < PREAMBLE_SIZE_V2:
        raise TruncationError("Truncated V2 preamble")
    preamble = V2Preamble.unpack(preamble_bytes)

    sender_peer = keystore.get(preamble.sender_key_id)
    prekey_id_str = preamble.prekey_id_bytes.rstrip(b'\x00').decode('ascii')

    transcript = preamble.ephemeral_pub + identity.key_id + preamble.prekey_id_bytes
    transcript_hash = hashlib.sha256(transcript).digest()
    verify_digest(sender_peer.ed25519, preamble.sig, transcript_hash)

    try:
        local_priv = consume_prekey(keystore_dir, identity_name, prekey_id_str)
    except FileNotFoundError as exc:
        raise PreKeyConsumedError(f"Pre-key {prekey_id_str} not found or already burned.") from exc

    kyber_ss = kyber_decapsulate(identity.kyber_privkey, preamble.kyber_ciphertext)
    stream_key = derive_stream_key(local_priv, preamble.ephemeral_pub, preamble.stream_salt, kyber_secret=kyber_ss)
    puller = SecretstreamPuller(stream_key, preamble.stream_header)

    # Read metadata chunk
    raw_len = fh.read(CHUNK_LEN_SIZE)
    if len(raw_len) < CHUNK_LEN_SIZE:
        raise TruncationError("Truncated metadata length field")
    meta_len = unpack_chunk_len(raw_len)
    if meta_len > MAX_CHUNK_SIZE:
        raise ProtocolError("Metadata chunk exceeds maximum size")
    enc_meta = fh.read(meta_len)
    if len(enc_meta) != meta_len:
        raise TruncationError("Truncated metadata chunk")
    meta_bytes, is_final = puller.pull(enc_meta)
    if is_final:
        raise ProtocolError("Metadata chunk missing TAG_MESSAGE")

    meta = MetadataHeader.unpack(meta_bytes)
    now = time.time()
    if now > meta.timestamp + meta.ttl or now < meta.timestamp - CLOCK_SKEW_TOLERANCE:
        raise TTLError("Transfer TTL expired")
    nonce_cache.check_and_insert(preamble.sender_key_id, meta.transfer_nonce, meta.ttl)

    dest_path = Path(dest_path)
    dest_path.mkdir(parents=True, exist_ok=True)
    safe_filename = os.path.basename(meta.filename)
    if not safe_filename or safe_filename in ('.', '..'):
        safe_filename = "unnamed_transfer.bin"

    out_file = dest_path / safe_filename
    counter = 1
    while out_file.exists():
        out_file = dest_path / f"{safe_filename}.{counter}"
        counter += 1

    part_file = out_file.with_suffix('.part')
    h = hashlib.sha256()
    bytes_written = 0

    final_seen = False
    try:
        with open(part_file, 'wb') as out_f:
            while True:
                raw_len = fh.read(CHUNK_LEN_SIZE)
                if not raw_len:
                    break
                if len(raw_len) < CHUNK_LEN_SIZE:
                    raise TruncationError("Truncated chunk length field")
                chunk_len = unpack_chunk_len(raw_len)
                if chunk_len > MAX_CHUNK_SIZE:
                    raise ProtocolError("Ciphertext chunk exceeds maximum size")
                enc_chunk = fh.read(chunk_len)
                if len(enc_chunk) != chunk_len:
                    raise TruncationError("Truncated ciphertext chunk")
                plaintext, is_final = puller.pull(enc_chunk)

                if is_final:
                    if len(plaintext) != ED25519_SIG_LEN:
                        raise ProtocolError(f"Trailer must be {ED25519_SIG_LEN}-byte Ed25519 signature.")
                    verify_digest(sender_peer.ed25519, plaintext, h.digest())
                    final_seen = True
                    break
                remaining = meta.file_size - bytes_written
                if remaining <= 0 or len(plaintext) > remaining:
                    raise ProtocolError("Payload contains more data than declared in metadata")
                out_f.write(plaintext)
                h.update(plaintext)
                bytes_written += len(plaintext)
        if not final_seen:
            raise TruncationError("Missing final authenticated trailer")
        if bytes_written != meta.file_size:
            raise TruncationError("Payload ended before the declared file size")
        if fh.read(1):
            raise ProtocolError("Trailing data after final authenticated trailer")
        part_file.replace(out_file)
    except Exception:
        if part_file.exists():
            part_file.unlink()
        raise


def decrypt_file_v2_from_path(
    identity: LocalIdentity,
    keystore: Keystore,
    keystore_dir: Path | str,
    ciphertext_path: Path | str,
    dest_path: Path | str,
    nonce_cache: NonceCache,
) -> None:
    """
    Streaming decryption directly from a file on disk.
    Memory usage is O(chunk_size) regardless of file size — no OOM risk.
    """
    with open(Path(ciphertext_path), 'rb') as fh:
        _decrypt_v2_stream(identity, keystore, keystore_dir, fh, dest_path, nonce_cache)
