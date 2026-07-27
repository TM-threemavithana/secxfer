import struct
from dataclasses import dataclass
from typing import BinaryIO

PROTOCOL_VERSION_V1: int = 0x01
PROTOCOL_VERSION_V2: int = 0x02

_PREAMBLE_FMT_V1: str = ">16s24s24s" # (version byte read separately)
PREAMBLE_SIZE_V1: int = struct.calcsize(_PREAMBLE_FMT_V1)

_PREAMBLE_FMT_V2: str = ">16s16s32s64s24s24s" # (version byte read separately)
PREAMBLE_SIZE_V2: int = struct.calcsize(_PREAMBLE_FMT_V2)

_CHUNK_LEN_FMT: str = ">I"                             # uint32 big-endian
CHUNK_LEN_SIZE: int = 4

_META_FIXED_FMT: str = ">16sQIH"
_META_FIXED_SIZE: int = struct.calcsize(_META_FIXED_FMT)  # 30 bytes

_FILE_SIZE_FMT: str = ">Q"
_FILE_SIZE_SIZE: int = 8


class WireError(Exception):
    pass


@dataclass
class MetadataHeader:
    transfer_nonce: bytes
    timestamp: int
    ttl: int
    filename: str
    file_size: int

    def pack(self) -> bytes:
        fname_bytes = self.filename.encode("utf-8")
        return (
            struct.pack(_META_FIXED_FMT, self.transfer_nonce, self.timestamp, self.ttl, len(fname_bytes))
            + fname_bytes
            + struct.pack(_FILE_SIZE_FMT, self.file_size)
        )

    @classmethod
    def unpack(cls, raw: bytes) -> "MetadataHeader":
        if len(raw) < _META_FIXED_SIZE:
            raise WireError("Metadata header too short")

        transfer_nonce, timestamp, ttl, fname_len = struct.unpack_from(_META_FIXED_FMT, raw, 0)
        offset = _META_FIXED_SIZE
        required = offset + fname_len + _FILE_SIZE_SIZE

        if len(raw) < required:
            raise WireError(f"Metadata header truncated: need {required} bytes, got {len(raw)}")

        filename = raw[offset : offset + fname_len].decode("utf-8")
        offset += fname_len
        (file_size,) = struct.unpack_from(_FILE_SIZE_FMT, raw, offset)

        return cls(transfer_nonce, timestamp, ttl, filename, file_size)


@dataclass
class V1Preamble:
    sender_key_id: bytes
    stream_salt: bytes
    stream_header: bytes

    def pack(self) -> bytes:
        return struct.pack(
            _PREAMBLE_FMT_V1,
            self.sender_key_id,
            self.stream_salt,
            self.stream_header
        )

    @classmethod
    def unpack(cls, raw: bytes) -> "V1Preamble":
        if len(raw) != PREAMBLE_SIZE_V1:
            raise WireError(f"Expected {PREAMBLE_SIZE_V1} bytes for V1 preamble, got {len(raw)}")
        
        sender_key_id, stream_salt, stream_header = struct.unpack(_PREAMBLE_FMT_V1, raw)
        return cls(sender_key_id, stream_salt, stream_header)


@dataclass
class V2Preamble:
    sender_key_id: bytes
    prekey_id_bytes: bytes
    ephemeral_pub: bytes
    sig: bytes
    stream_salt: bytes
    stream_header: bytes

    def pack(self) -> bytes:
        return struct.pack(
            _PREAMBLE_FMT_V2,
            self.sender_key_id,
            self.prekey_id_bytes,
            self.ephemeral_pub,
            self.sig,
            self.stream_salt,
            self.stream_header
        )

    @classmethod
    def unpack(cls, raw: bytes) -> "V2Preamble":
        if len(raw) != PREAMBLE_SIZE_V2:
            raise WireError(f"Expected {PREAMBLE_SIZE_V2} bytes for V2 preamble, got {len(raw)}")
        
        sender_key_id, prekey_id_bytes, ephemeral_pub, sig, stream_salt, stream_header = struct.unpack(
            _PREAMBLE_FMT_V2, raw
        )
        return cls(sender_key_id, prekey_id_bytes, ephemeral_pub, sig, stream_salt, stream_header)

def pack_chunk_len(chunk_len: int) -> bytes:
    return struct.pack(_CHUNK_LEN_FMT, chunk_len)

def unpack_chunk_len(raw: bytes) -> int:
    (chunk_len,) = struct.unpack(_CHUNK_LEN_FMT, raw)
    return chunk_len
