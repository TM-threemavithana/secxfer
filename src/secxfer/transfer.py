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
from typing import BinaryIO, Iterator

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

def build_file_v2(
    identity: LocalIdentity,
    receiver_key_id: bytes,
    receiver_prekey_id: str,
    receiver_prekey_pubkey: bytes,
    file_path: Path | str,
    ttl_seconds: int = 300,
    chunk_size: int = CHUNK_SIZE,
    pqc_psk: str | None = None,
) -> bytes:
    """Builds the encrypted V2 payload for uploading to the directory server."""
    file_path = Path(file_path)
    file_size = file_path.stat().st_size
    stream_salt = os.urandom(24)

    ephemeral_priv, ephemeral_pub = generate_ephemeral_keypair()
    stream_key = derive_stream_key(ephemeral_priv, receiver_prekey_pubkey, stream_salt, pqc_psk=pqc_psk)
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
        stream_header=pusher.header
    )
    payload.extend(preamble.pack())

    transfer_nonce = os.urandom(16)
    meta = MetadataHeader(
        transfer_nonce=transfer_nonce,
        timestamp=int(time.time()),
        ttl=ttl_seconds,
        filename=file_path.name,
        file_size=file_size,
    )
    enc_meta = pusher.push(meta.pack())
    payload.extend(pack_chunk_len(len(enc_meta)) + enc_meta)

    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        if file_size == 0:
            enc = pusher.push_final(b'')
            payload.extend(pack_chunk_len(len(enc)) + enc)
        else:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                if len(chunk) < chunk_size:
                    chunk += b'\x00' * (chunk_size - len(chunk))
                h.update(chunk)
                enc = pusher.push(chunk)
                payload.extend(pack_chunk_len(len(enc)) + enc)
            
            sig_file = sign_digest(identity.ed25519_seed, h.digest())
            enc_final = pusher.push_final(sig_file)
            payload.extend(pack_chunk_len(len(enc_final)) + enc_final)
            
    return bytes(payload)

def decrypt_file_v2(
    identity: LocalIdentity,
    keystore: Keystore,
    keystore_dir: Path | str,
    ciphertext: bytes,
    dest_path: Path | str,
    nonce_cache: NonceCache,
    pqc_psk: str | None = None,
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
    verify_digest(sender_peer.ed25519, transcript_hash, preamble.sig)

    local_priv = consume_prekey(keystore_dir, identity.key_id, prekey_id_str, identity.x25519_privkey)
    if local_priv is None:
        raise PreKeyConsumedError(f"Pre-key {prekey_id_str} not found or already burned.")

    stream_key = derive_stream_key(local_priv, preamble.ephemeral_pub, preamble.stream_salt, pqc_psk=pqc_psk)
    puller = SecretstreamPuller(stream_key, preamble.stream_header)

    # Read Metadata
    raw_len = ciphertext[offset : offset + CHUNK_LEN_SIZE]
    offset += CHUNK_LEN_SIZE
    chunk_len = unpack_chunk_len(raw_len)
    
    enc_meta = ciphertext[offset : offset + chunk_len]
    offset += chunk_len
    meta_bytes, tag = puller.pull(enc_meta)
    if tag != SecretstreamPuller.TAG_MESSAGE:
        raise ProtocolError("Metadata chunk missing TAG_MESSAGE")
        
    meta = MetadataHeader.unpack(meta_bytes)
    now = time.time()
    if now > meta.timestamp + meta.ttl or now < meta.timestamp - 300:
        raise TTLError("Transfer TTL expired")
    nonce_cache.check_and_insert(preamble.sender_key_id, meta.transfer_nonce, meta.ttl)

    dest_path = Path(dest_path)
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

    with open(part_file, 'wb') as f:
        while offset < len(ciphertext):
            raw_len = ciphertext[offset : offset + CHUNK_LEN_SIZE]
            offset += CHUNK_LEN_SIZE
            chunk_len = unpack_chunk_len(raw_len)
            
            enc_chunk = ciphertext[offset : offset + chunk_len]
            offset += chunk_len
            plaintext, tag = puller.pull(enc_chunk)
            
            if tag == SecretstreamPuller.TAG_FINAL:
                if len(plaintext) != 64:
                    os.remove(part_file)
                    raise ProtocolError("Trailer chunk does not contain exactly a 64-byte Ed25519 signature.")
                verify_digest(sender_peer.ed25519, h.digest(), plaintext)
                break
            else:
                remaining = meta.file_size - bytes_written
                if remaining > 0:
                    to_write = plaintext[:remaining]
                    f.write(to_write)
                    h.update(plaintext)
                    bytes_written += len(to_write)

    part_file.replace(out_file)
