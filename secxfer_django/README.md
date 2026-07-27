# SecXfer Django — Central Key Distribution Center (KDC)

> The **blind mailbox** at the heart of SecXfer's Zero-Trust architecture.

This is the **Django REST** central server that replaces the original `server.py`. It manages public pre-keys for X3DH key exchange and stores encrypted file payloads — but it is architecturally incapable of decrypting anything it stores.

---

## What This Server Does

| Endpoint | Method | Description |
|---|---|---|
| `/challenge` | GET | Issues a nonce for Ed25519 Proof-of-Possession |
| `/register` | POST | Registers a user's identity + X3DH pre-key bundle (after PoP verification) |
| `/keys/<key_id>` | GET | Serves a single-use pre-key bundle for X3DH key agreement |
| `/upload` | POST | Accepts an encrypted binary blob — stores it in `server_vault/` |
| `/inbox/<key_id>` | GET | Lists encrypted files waiting for a given recipient |
| `/download/<file_id>` | GET | Serves the encrypted blob to the recipient |
| `/audit/log` | GET | Serves the raw Hash-Chained Audit Log for client-side verification |

---

## Zero-Trust Design

The server **never receives, stores, or processes** any plaintext or private key material. It only handles:
- **Public keys** (X25519 pre-keys, Ed25519 identity keys)
- **Ciphertext blobs** (AES/XChaCha20 encrypted payloads)
- **Signatures** (Ed25519 over challenges and file digests)
- **Audit log entries** (event type, timestamp, hash chain)

---

## Running the Server

```bash
# From the secxfer_django/ directory

# First time setup
python manage.py migrate

# Start server
python manage.py runserver 8001
```

---

## Django Apps

### `kdc/` — Key Distribution Center

**Models:**

| Model | Purpose |
|---|---|
| `UserIdentity` | Stores `key_id` and Ed25519 public identity key |
| `PreKey` | X25519 pre-keys (one-time use, consumed during key exchange) |
| `EncryptedFile` | Metadata for stored ciphertext (path, sender, receiver, size) |
| `AuditLog` | SHA-256 hash-chained event log (REGISTER, UPLOAD, DOWNLOAD) |

**Key logic in `views.py`:**
- `append_audit_log()` — atomically appends a new block to the hash chain using `SHA-256(event | details | timestamp | previous_hash)`
- `_verify_pop()` — verifies Ed25519 proof-of-possession signature before registration
- `_consume_challenge()` — ensures nonces are single-use with a TTL

---

## Hash-Chained Audit Log

```
Block N:
  event_type    : "UPLOAD" | "DOWNLOAD" | "REGISTER"
  details       : JSON string (sort_keys=True for deterministic hashing)
  previous_hash : SHA-256(Block N-1) | "GENESIS_HASH" for Block 0
  current_hash  : SHA-256(event_type + "|" + details + "|" + timestamp + "|" + previous_hash)
```

**Verification is Zero-Trust:** The client browser fetches the raw chain and re-computes every SHA-256 locally via `window.crypto.subtle`. The server cannot lie — if any block is tampered, the computed hash will not match, and the client displays a `SERVER TAMPERING DETECTED` alert.
