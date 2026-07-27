# SecXfer

Cryptographically secure, forward-secret, and quantum-resistant (hybrid) file transfer system. 
It features a modern web dashboard (`secxfer ui`), a robust CLI, and a central Key Directory Server.

See [`threat_model.md`](threat_model.md) and [`protocol_flow.md`](protocol_flow.md) for full design rationale and sequence diagrams.

## Table of Contents
- [Security Properties](#security-properties)
- [Features & Attack Defenses](#features--attack-defenses)
- [Installation](#installation)
- [Quick Start (Web UI)](#quick-start-web-ui)
- [CLI Reference](#cli-reference)
- [Wire Format (V2)](#wire-format-v2)
- [Module Architecture](#module-architecture)
- [Known Limitations](#known-limitations)

---

## Security Properties

| Property | Status |
|---|---|
| Confidentiality | ✅ XChaCha20-Poly1305 (secretstream) |
| Integrity | ✅ AEAD per-chunk; Ed25519 over whole-file SHA-256 |
| Authentication | ✅ Sender is mathematically verified against registered keys |
| Replay protection | ✅ Persistent SQLite nonce cache (TTL-bounded, DoS-resistant) |
| Forward secrecy | ✅ X3DH protocol with dynamic pre-keys |
| Key distribution | ✅ Centralized Key Directory Server (`server.py`) with PoP |

## Features & Attack Defenses

- **X3DH Key Exchange:** Perfect Forward Secrecy using Extended Triple Diffie-Hellman. Even if long-term private keys are compromised, past transfers remain secure.
- **Hybrid Post-Quantum Security:** Optional Pre-Shared Keys (PQC-PSK) mixed securely via `HMAC-SHA256` to protect against future quantum adversaries ("Harvest Now, Decrypt Later" attacks).
- **Memory Exhaustion DoS:** Strict bounds-checking on file chunk sizes (`MAX_CHUNK_SIZE`).
- **Impersonation Protection:** Ed25519 Proof-of-Possession (PoP) challenge-response during key registration.
- **Secure Wipe:** In-memory sensitive material is purged using libsodium's `sodium_memzero`.
- **Pre-Key Exhaustion Mitigation:** Automatically degrades to a "Last Resort Pre-Key" to prevent Denial of Service (DoS) attacks on the key directory.
- **Key Encryption:** Private keys are protected on-disk using `Argon2i`.

---

## Installation

**Stack:** Python 3.11+, PyNaCl, FastAPI, Uvicorn, SQLite3.

```bash
# Install the package and its dependencies in editable mode
pip install -e ".[dev]"
```

---

## Quick Start (Web UI)

### 1. Start the Key Directory Server
The central server hosts public pre-keys for X3DH to allow offline file transfers.
```bash
python -m secxfer.server
# Server listens on http://127.0.0.1:54321
```

### 2. Launch the Web UI
Launch a local dashboard for a user (e.g., Alice).
```bash
secxfer ui --identity alice --keystore ./alice_keys --port 8085
```

### 3. Generate & Register an Identity
1. Open `http://127.0.0.1:8085` in your browser.
2. In the **Identity** tab, generate a new identity and set a strong Argon2 password.
3. In the **Register** tab, register your identity with the Directory Server. This securely uploads your X3DH pre-keys using an Ed25519 PoP handshake.

### 4. Transfer Files
1. Alice and Bob both launch their `secxfer ui` processes (on different ports).
2. Bob registers his keys with the central directory.
3. Alice enters Bob's Key ID in the **Send** tab, selects a file, and points it to Bob's receiving host/port.
4. Bob receives the file securely in his `keystore/downloads` folder.

---

## CLI Reference

While the Web UI is recommended, the core library can be operated entirely via the CLI.

```bash
secxfer ui      [--identity NAME] [--keystore DIR] [--port PORT]
secxfer keygen  --dir DIR [--name NAME]
secxfer show-id --identity KEY
secxfer send    FILE --identity KEY --to PUBKEY [--ttl SECS] [--out FILE]
secxfer receive DEST --identity KEY --keystore DIR [--in FILE]
```

---

## Wire Format (V2)

The V2 wire protocol operates over standard TCP streams. Each chunk is length-prefixed (4-byte big-endian uint32).

```text
Preamble (V2, unauthenticated):
  version         : 1 byte  (0x02)
  sender_key_id   : 16 bytes (first 16 of SHA-256(x25519_pubkey))
  prekey_id_bytes : 16 bytes (null-padded ASCII ID)
  ephemeral_pub   : 32 bytes (X25519 ephemeral public key)
  sig             : 64 bytes (Ed25519 signature over transcript_hash)
  stream_salt     : 24 bytes (HKDF salt; fresh per transfer)
  stream_header   : 24 bytes (secretstream init_push output)

Chunk 0 — Metadata (AEAD-protected, TAG_MESSAGE):
  transfer_nonce, timestamp, ttl, filename, file_size

Chunks 1..N — File Data (AEAD-protected, TAG_MESSAGE)

Chunk N+1 — Trailer (AEAD-protected, TAG_FINAL):
  Ed25519 signature (64 bytes) over SHA-256(file_data)
```

---

## Module Architecture

```text
src/secxfer/
├── ui/              ← FastAPI dashboard and HTML/JS frontend
├── server.py        ← Central Key Directory (X3DH pre-key distribution)
├── client.py        ← High-level SDK (UI backend bridge)
├── transfer.py      ← V1/V2 Wire protocol, chunk handling, NonceCache
├── keystore.py      ← Key lifecycle, Argon2i encryption, Last Resort Pre-Keys
├── crypto.py        ← Primitives (X25519, HKDF, secretstream, sodium_memzero)
├── wire.py          ← Binary protocol framing and padding
└── cli.py           ← Argument parsing
```

Strict dependency DAG: `ui → client → transfer → {crypto, keystore, wire}`.

---

## Known Limitations

1. **Local file permissions:** The `identity.key` file is encrypted with Argon2i, but effective isolation still relies on the host operating system. A compromised host OS can read the unencrypted keys from Python's memory while the UI is unlocked.
2. **SQLite Concurrency:** The central Key Directory Server (`server.py`) uses SQLite. While sufficient for thousands of users, it will experience write-locks if subjected to hundreds of thousands of concurrent registration requests.
3. **Traffic Analysis:** While the payload is fully encrypted, the length of the TCP stream leaks the approximate size of the transferred file (rounded to the nearest 64KB chunk).

---

## Running Tests

SecXfer includes comprehensive cryptographic unit tests and integration tests covering malicious network traffic, truncation, and forgery:
```bash
pytest
pytest tests/test_crypto_v1.py -v   # Run specific test suite
```
