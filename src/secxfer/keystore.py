"""
secxfer.keystore — pre-shared public key store.

Maps sender_key_id (first 8 bytes of SHA-256(x25519_pubkey)) to the
sender's (x25519_pubkey, ed25519_pubkey) pair.

Key file format
---------------
Public key files (*.pub):
    64 raw bytes: x25519_pubkey (32) || ed25519_pubkey (32)
    Filename is used as a human-readable label only; lookup is by key_id.

Private key files (*.key):
    64 raw bytes: x25519_privkey (32) || ed25519_seed (32)

Directory layout example::

    keystore/
    ├── identity.key    # local private keys — never share
    ├── identity.pub    # local public key   — share with peers
    ├── alice.pub       # alice's public key
    └── bob.pub         # bob's public key

Threat model note
-----------------
Key distribution is explicitly out of scope.  The keystore assumes all
.pub files were obtained through a secure out-of-band channel.  The
library offers no protection if a .pub file has been substituted by an
attacker — that is the key distribution problem this design defers.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

import nacl.bindings as _nb
from nacl.signing import SigningKey

from secxfer.crypto import AuthenticationError


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class UnknownSenderError(Exception):
    """Received a transfer from a sender whose key_id is not in the keystore."""


# ---------------------------------------------------------------------------
# Key layout constants
# ---------------------------------------------------------------------------

_PUBKEY_SIZE = 64   # x25519_pubkey (32) || ed25519_pubkey (32)
_PRIVKEY_SIZE = 64  # x25519_privkey (32) || ed25519_seed (32)
_KEY_ID_LEN = 8     # first 8 bytes of SHA-256(x25519_pubkey)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PeerPublicKey:
    """A peer's two public keys, both required by the receiver."""
    x25519: bytes   # 32 bytes — Curve25519 public key for DH
    ed25519: bytes  # 32 bytes — Ed25519 public key for signature verification


@dataclass(frozen=True)
class LocalIdentity:
    """The local party's private keys and derived public information."""
    x25519_privkey: bytes   # 32 bytes
    ed25519_seed: bytes     # 32 bytes
    x25519_pubkey: bytes    # 32 bytes — derived
    ed25519_pubkey: bytes   # 32 bytes — derived
    key_id: bytes           # 8 bytes — derived; included in wire preamble


# ---------------------------------------------------------------------------
# Key derivation helpers
# ---------------------------------------------------------------------------

def key_id_from_x25519_pubkey(x25519_pubkey: bytes) -> bytes:
    """Compute the 8-byte sender_key_id from a Curve25519 public key."""
    return hashlib.sha256(x25519_pubkey).digest()[:_KEY_ID_LEN]


# ---------------------------------------------------------------------------
# Keystore
# ---------------------------------------------------------------------------

class Keystore:
    """
    In-memory map of ``sender_key_id → PeerPublicKey``, loaded from a directory.

    Peers whose .pub files are present at load time are trusted.  Adding a
    new peer requires placing their .pub file in the directory and reloading
    (or constructing a new Keystore instance).
    """

    def __init__(self, peers: dict[bytes, PeerPublicKey]) -> None:
        self._peers = peers

    @classmethod
    def from_directory(cls, path: Path | str) -> "Keystore":
        """
        Load all ``*.pub`` files from *path* as trusted peer public keys.

        Each file must be exactly 64 bytes (x25519_pubkey || ed25519_pubkey).
        Files that are not 64 bytes are skipped with a warning.

        Args:
            path: Directory containing peer ``.pub`` files.

        Returns:
            A populated ``Keystore`` instance.
        """
        directory = Path(path)
        peers: dict[bytes, PeerPublicKey] = {}
        for pub_file in sorted(directory.glob("*.pub")):
            raw = pub_file.read_bytes()
            if len(raw) != _PUBKEY_SIZE:
                import warnings
                warnings.warn(
                    f"Skipping {pub_file.name}: expected {_PUBKEY_SIZE} bytes, "
                    f"got {len(raw)}"
                )
                continue
            x25519_pub = raw[:32]
            ed25519_pub = raw[32:]
            kid = key_id_from_x25519_pubkey(x25519_pub)
            peers[kid] = PeerPublicKey(x25519=x25519_pub, ed25519=ed25519_pub)
        return cls(peers)

    def get(self, sender_key_id: bytes) -> PeerPublicKey:
        """
        Look up a peer's public keys by their ``sender_key_id``.

        Args:
            sender_key_id: 8-byte key identifier from the wire preamble.

        Returns:
            The peer's ``PeerPublicKey``.

        Raises:
            UnknownSenderError: No peer with this key_id is in the keystore.
        """
        try:
            return self._peers[sender_key_id]
        except KeyError:
            raise UnknownSenderError(
                f"No peer found for key_id {sender_key_id.hex()!r}. "
                "Ensure the sender's .pub file is in the keystore directory."
            )

    def __len__(self) -> int:
        return len(self._peers)


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_keypair(output_dir: Path | str, name: str = "identity") -> LocalIdentity:
    """
    Generate a fresh Curve25519 + Ed25519 keypair and write it to disk.

    Creates two files in *output_dir*:
      - ``<name>.key`` — private keys (keep secret, chmod 600)
      - ``<name>.pub`` — public keys  (share with peers)

    Args:
        output_dir: Directory in which to write the key files.
        name:       Base name for the output files.

    Returns:
        The generated ``LocalIdentity``.

    Raises:
        FileExistsError: if ``<name>.key`` already exists (prevents overwrites).
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    key_path = out / f"{name}.key"
    pub_path = out / f"{name}.pub"

    if key_path.exists():
        raise FileExistsError(
            f"{key_path} already exists. Delete it explicitly to regenerate."
        )

    # Curve25519 keypair
    x25519_priv = os.urandom(32)
    x25519_pub = _nb.crypto_scalarmult_base(x25519_priv)

    # Ed25519 keypair
    signing_key = SigningKey.generate()
    ed25519_seed = bytes(signing_key)
    ed25519_pub = bytes(signing_key.verify_key)

    # Write private key file (owner read-only where supported)
    key_path.write_bytes(x25519_priv + ed25519_seed)
    try:
        key_path.chmod(0o600)
    except NotImplementedError:
        pass  # Windows; best-effort

    # Write public key file
    pub_path.write_bytes(x25519_pub + ed25519_pub)

    kid = key_id_from_x25519_pubkey(x25519_pub)
    return LocalIdentity(
        x25519_privkey=x25519_priv,
        ed25519_seed=ed25519_seed,
        x25519_pubkey=x25519_pub,
        ed25519_pubkey=ed25519_pub,
        key_id=kid,
    )


def load_identity(key_file: Path | str) -> LocalIdentity:
    """
    Load a local identity from a ``*.key`` file.

    Args:
        key_file: Path to a 64-byte private key file.

    Returns:
        The loaded ``LocalIdentity``.

    Raises:
        ValueError: if the file is not exactly 64 bytes.
    """
    raw = Path(key_file).read_bytes()
    if len(raw) != _PRIVKEY_SIZE:
        raise ValueError(
            f"Expected {_PRIVKEY_SIZE}-byte key file, got {len(raw)} bytes: {key_file}"
        )
    x25519_priv = raw[:32]
    ed25519_seed = raw[32:]

    x25519_pub = _nb.crypto_scalarmult_base(x25519_priv)
    signing_key = SigningKey(ed25519_seed)
    ed25519_pub = bytes(signing_key.verify_key)
    kid = key_id_from_x25519_pubkey(x25519_pub)

    return LocalIdentity(
        x25519_privkey=x25519_priv,
        ed25519_seed=ed25519_seed,
        x25519_pubkey=x25519_pub,
        ed25519_pubkey=ed25519_pub,
        key_id=kid,
    )
