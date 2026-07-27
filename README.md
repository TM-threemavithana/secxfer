# SecXfer

**SecXfer** is a cryptographically secure, forward-secret, and quantum-resistant (hybrid) file transfer system. It consists of a modern web UI, a robust CLI, and a central Key Directory server.

## Features

- **X3DH Key Exchange:** Perfect Forward Secrecy using Extended Triple Diffie-Hellman (X3DH). Even if long-term private keys are compromised, past transfers remain secure.
- **Hybrid Post-Quantum Security:** Optional Pre-Shared Keys (PQC-PSK) mixed securely via `HMAC-SHA256` to protect against future quantum adversaries ("Harvest Now, Decrypt Later" attacks).
- **Modern Web UI:** Launch a local web dashboard (`secxfer ui`) to easily manage identities, register with the directory, and send/receive files seamlessly.
- **Robust Attack Defenses:**
  - **Replay Protection:** Persistent SQLite-backed nonce cache with server-capped TTLs to prevent unbounded memory/disk growth.
  - **Memory Exhaustion DoS:** Strict bounds-checking on file chunk sizes.
  - **Impersonation Protection:** Ed25519 Proof-of-Possession (PoP) challenge-response during key registration.
  - **Secure Wipe:** In-memory sensitive material is purged using libsodium's `sodium_memzero`.
  - **Pre-Key Exhaustion Mitigation:** Automatically degrades to a "Last Resort Pre-Key" to prevent Denial of Service (DoS) attacks on the key directory.
  - **Key Encryption:** Private keys are protected on-disk using `Argon2i`.

## Security Properties

| Property | Status |
|---|---|
| Confidentiality | ✅ XChaCha20-Poly1305 (secretstream) |
| Integrity | ✅ AEAD per-chunk; Ed25519 over whole-file SHA-256 |
| Authentication | ✅ Sender is mathematically verified against registered keys |
| Replay protection | ✅ Persistent SQLite nonce cache (TTL-bounded, DoS-resistant) |
| Forward secrecy | ✅ X3DH protocol with dynamic pre-keys |
| Key distribution | ✅ Centralized Key Directory Server (`server.py`) with PoP |

## Stack

- **Core:** Python 3.11+
- **Cryptography:** `PyNaCl` (libsodium bindings) + X25519, XChaCha20-Poly1305, Ed25519, Argon2i
- **Web UI & Server:** `FastAPI`, `Uvicorn`, HTML/CSS/JS (Vanilla)
- **Database:** `sqlite3`

## Quick Start

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
3. In the **Register** tab, register your identity with the Directory Server (`http://127.0.0.1:54321`). This securely uploads your X3DH pre-keys using an Ed25519 PoP handshake.

### 4. Transfer Files
1. Alice and Bob both launch their `secxfer ui` processes (on different ports).
2. Bob registers his keys with the central directory.
3. Alice enters Bob's Key ID in the **Send** tab, selects a file, and points it to Bob's receiving host/port (e.g., `127.0.0.1:8086`).
4. Bob receives the file securely in his `keystore/downloads` folder.

## Protocol Versions
SecXfer supports two wire protocols seamlessly:
- **V1:** Static pre-shared keys (Out-of-band key exchange, no forward secrecy).
- **V2 (Default):** X3DH key exchange (Centralized directory, perfect forward secrecy).

## Module Architecture

```text
src/secxfer/
├── ui/              ← FastAPI dashboard and HTML/JS frontend
├── server.py        ← Central Key Directory (X3DH pre-key distribution)
├── client.py        ← High-level SDK (UI backend bridge)
├── transfer.py      ← V1/V2 Wire protocol, chunk handling, NonceCache
├── keystore.py      ← Key lifecycle, Argon2i encryption, Last Resort Pre-Keys
├── crypto.py        ← Primitives (X25519, HKDF, secretstream, sodium_memzero)
└── wire.py          ← Binary protocol framing and padding
```

## Running Tests

SecXfer includes comprehensive cryptographic unit tests and integration tests covering malicious network traffic, truncation, and forgery:
```bash
pytest
pytest tests/test_crypto_v1.py -v   # Run specific test suite
```
