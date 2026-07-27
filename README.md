# SecXfer

> **Zero-Trust, Post-Quantum, End-to-End Encrypted Academic File Exchange Platform.**
>
> The server should never be trusted with your data — not even in a full database breach.

SecXfer is a production-grade secure file transfer system built on the **Signal Protocol (X3DH)**, featuring a **Django REST** central server, a **Next.js (React)** dashboard, and a **FastAPI** local cryptography daemon. All cryptography happens client-side in Python — the central server is architecturally blind and only ever handles ciphertext.

See [`threat_model.md`](threat_model.md) and [`protocol_flow.md`](protocol_flow.md) for full design rationale and sequence diagrams.

---

## Table of Contents
- [Security Properties](#security-properties)
- [Architecture Overview](#architecture-overview)
- [Tech Stack](#tech-stack)
- [Features & Attack Defenses](#features--attack-defenses)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Wire Format (V2)](#wire-format-v2)
- [Module Architecture](#module-architecture)
- [Known Limitations](#known-limitations)

---

## Security Properties

| Property | Status | Mechanism |
|---|---|---|
| Confidentiality | ✅ | XChaCha20-Poly1305 (libsodium secretstream) |
| Integrity | ✅ | AEAD per-chunk + Ed25519 over whole-file SHA-256 |
| Authentication | ✅ | Ed25519 Proof-of-Possession challenge-response at registration |
| Forward Secrecy | ✅ | X3DH protocol — ephemeral keys destroyed after each session |
| Replay Protection | ✅ | Persistent SQLite nonce cache (TTL-bounded, DoS-resistant) |
| Post-Quantum Resistance | ✅ | Optional PQC Pre-Shared Keys (PSK) mixed via HMAC-SHA256 |
| Zero-Trust Server | ✅ | Django stores ciphertext only — no keys, no plaintext, ever |
| Audit Integrity | ✅ | Hash-Chained Audit Log verified **client-side** in the browser |

---

## Architecture Overview

SecXfer uses a **three-layer architecture** that cleanly separates UI, cryptography, and storage:

```
┌──────────────────────────────────────────────────┐
│  Layer 1: Next.js UI  (port 3000)                 │
│  React + Tailwind CSS dashboard                   │
│  Tabs: Send | Inbox | Hash-Chained Audit Log      │
└──────────────────┬───────────────────────────────┘
                   │ REST API calls (fetch)
                   ▼
┌──────────────────────────────────────────────────┐
│  Layer 2: FastAPI SDK Daemon  (port 8085/8086)    │  ← 🔐 ALL CRYPTO HERE
│  X3DH · HKDF-SHA256 · XChaCha20-Poly1305         │
│  Ed25519 signatures · Argon2i keystore            │
│  Python + PyNaCl + libsodium                      │
└──────────────────┬───────────────────────────────┘
                   │ HTTP uploads (ciphertext only)
                   ▼
┌──────────────────────────────────────────────────┐
│  Layer 3: Django Central Server  (port 8001)      │  ← 🙈 BLIND MAILBOX
│  Stores ciphertext blobs in server_vault/         │
│  Manages public pre-keys (never private keys)     │
│  Records SHA-256 Hash-Chained Audit Log           │
│  Django ORM + SQLite · django-cors-headers        │
└──────────────────────────────────────────────────┘
```

**Key principle:** The Django server is a mathematically blind mailbox. It stores encrypted blobs but has no mechanism to decrypt them. Even a full database breach exposes zero plaintext.

---

## Tech Stack

| Component | Technology |
|---|---|
| **Central Server** | Django 6 + Django REST Framework + `django-cors-headers` |
| **Cryptography Engine** | Python + PyNaCl (libsodium) + `cryptography` (PyCA) |
| **Local SDK Daemon** | FastAPI + Uvicorn |
| **Frontend** | Next.js 15 (App Router) + React + Tailwind CSS |
| **Key Agreement** | X3DH (Extended Triple Diffie-Hellman) — Signal Protocol |
| **Encryption** | XChaCha20-Poly1305 (libsodium secretstream) |
| **Signing** | Ed25519 |
| **Key Derivation** | HKDF-SHA256 (RFC 5869) |
| **Key Storage** | Argon2i-encrypted keystore files |
| **Audit Log** | SHA-256 Hash Chain (client-verified via Web Crypto API) |
| **Database** | SQLite (Django ORM) |

---

## Features & Attack Defenses

- **X3DH Key Exchange (Signal Protocol):** Extended Triple Diffie-Hellman gives Perfect Forward Secrecy. Each session uses fresh ephemeral X25519 keys. A stolen private key cannot decrypt any past session.
- **Hybrid Post-Quantum Security:** Optional Pre-Shared Keys (PQC-PSK) mixed via `HMAC-SHA256` protects against "Harvest Now, Decrypt Later" quantum attacks.
- **Zero-Trust Central Server:** Django manages user registration and pre-key distribution but is architecturally incapable of decrypting any stored file.
- **Client-Verified Audit Log:** Every REGISTER, UPLOAD, and DOWNLOAD event is recorded in a SHA-256 hash chain on Django. The Next.js dashboard re-computes every hash locally using the browser's Web Crypto API. A malicious server admin cannot silently delete or alter records.
- **Ed25519 Proof-of-Possession:** Registration requires signing a server-issued challenge nonce, preventing key impersonation.
- **Replay Attack Prevention:** A persistent SQLite nonce cache with TTL prevents an attacker from replaying captured ciphertext.
- **Memory-Safe Key Wipe:** Sensitive key material in memory is zeroed using libsodium's `sodium_memzero` (immune to compiler dead-store elimination).
- **Argon2i Keystore Encryption:** Private keys at rest are protected by `Argon2i` password hashing.
- **Pre-Key Exhaustion DoS Mitigation:** Automatically falls back to a "Last Resort Pre-Key" if the pre-key bundle is exhausted.
- **Memory Exhaustion DoS:** Strict `MAX_CHUNK_SIZE` bounds-checking prevents malicious oversized chunks.

---

## Installation

**Requirements:** Python 3.11+, Node.js 18+

### 1. Python Dependencies
```bash
# Install secxfer core + FastAPI daemon
pip install -e ".[dev]"

# Install Django central server
pip install django django-cors-headers
```

### 2. Next.js Frontend
```bash
cd secxfer_nextjs
npm install
```

---

## Quick Start

### Step 1: Start the Django Central Server
```bash
cd secxfer_django
python manage.py migrate   # first time only
python manage.py runserver 8001
# Django KDC listening on http://127.0.0.1:8001
```

### Step 2: Launch Alice's FastAPI SDK Daemon
```bash
# From the secxfer/ root directory
python -m secxfer.cli ui --identity alice.key --keystore ./alice_keys --port 8085
# Alice's daemon on http://127.0.0.1:8085
```

### Step 3: Launch Bob's FastAPI SDK Daemon
```bash
python -m secxfer.cli ui --identity bob.key --keystore ./bob_keys --port 8086
# Bob's daemon on http://127.0.0.1:8086
```

### Step 4: Start the Next.js Frontend
```bash
cd secxfer_nextjs
npm run dev
# Dashboard at http://localhost:3000
```

### Step 5: Use the Dashboard
1. Open `http://localhost:3000` in your browser
2. Enter your password to unlock your Argon2i-encrypted keystore
3. **Send tab** → enter Bob's identity name → choose a file → click **Encrypt & Send**
4. Bob opens his own Next.js instance → **Inbox tab** → click **Decrypt**
5. Click **Verify Server Integrity** to cryptographically audit the Django server's event log

> **Note:** The Next.js UI defaults to communicating with Alice's daemon on port `8085`. For Bob's separate session, update `API_BASE` in `page.tsx` to `http://127.0.0.1:8086`.

---

## CLI Reference

The core library can also be operated entirely from the terminal:

```bash
secxfer ui      [--identity NAME] [--keystore DIR] [--port PORT]
secxfer keygen  --dir DIR [--name NAME]
secxfer show-id --identity KEY
secxfer send    FILE --identity KEY --to PUBKEY [--ttl SECS] [--out FILE]
secxfer receive DEST --identity KEY --keystore DIR [--in FILE]
```

---

## Wire Format (V2)

Each file transfer is a self-contained binary stream. Chunks are 4-byte big-endian length-prefixed.

```text
Preamble (V2, unauthenticated header):
  version         : 1 byte  (0x02)
  sender_key_id   : 16 bytes (first 16 of SHA-256(x25519_pubkey))
  prekey_id_bytes : 16 bytes (null-padded ASCII ID)
  ephemeral_pub   : 32 bytes (X25519 ephemeral public key — destroyed after KDF)
  sig             : 64 bytes (Ed25519 signature over transcript_hash)
  stream_salt     : 24 bytes (HKDF salt; fresh per transfer)
  stream_header   : 24 bytes (secretstream init_push output)

Chunk 0 — Metadata (AEAD-protected, TAG_MESSAGE):
  transfer_nonce, timestamp, ttl, filename, file_size

Chunks 1..N — File Data (AEAD-protected, TAG_MESSAGE)

Chunk N+1 — Trailer (AEAD-protected, TAG_FINAL):
  Ed25519 signature (64 bytes) over SHA-256(plaintext_file_data)
```

---

## Module Architecture

```text
secxfer/                        ← Root project
├── secxfer_django/             ← Django Central Server (KDC / Blind Mailbox)
│   ├── kdc/
│   │   ├── models.py           ← UserIdentity, PreKey, EncryptedFile, AuditLog
│   │   └── views.py            ← /register, /upload, /inbox, /download, /audit/log
│   ├── secxfer_django/
│   │   ├── settings.py         ← CORS, installed apps
│   │   └── urls.py             ← URL routing
│   └── manage.py
│
├── secxfer_nextjs/             ← Next.js Frontend (React + Tailwind)
│   └── src/app/
│       ├── page.tsx            ← Main dashboard (Send / Inbox / Audit Log tabs)
│       ├── layout.tsx          ← Root layout (Inter font, metadata)
│       └── globals.css
│
└── src/secxfer/                ← Python Cryptography Engine (FastAPI SDK Daemon)
    ├── ui/
    │   ├── app.py              ← FastAPI daemon + CORS (SDK bridge for Next.js)
    │   └── static/             ← Legacy vanilla JS dashboard (kept for reference)
    ├── server.py               ← Legacy http.server KDC (superseded by Django)
    ├── client.py               ← High-level SDK (HTTP client to Django KDC)
    ├── transfer.py             ← V2 Wire protocol, chunk state machine, NonceCache
    ├── keystore.py             ← Key lifecycle, Argon2i encryption, Last Resort Pre-Keys
    ├── crypto.py               ← Primitives: X25519, HKDF, secretstream, sodium_memzero
    ├── wire.py                 ← Binary protocol framing and padding
    └── cli.py                  ← CLI entry point
```

**Dependency DAG:** `Next.js → FastAPI daemon → client → transfer → {crypto, keystore, wire}` → **Django KDC**

---

## Hash-Chained Audit Log

Every server event (REGISTER, UPLOAD, DOWNLOAD) is appended to a tamper-evident ledger:

```
Block N:
  event_type    : "UPLOAD"
  details       : {"sender": "...", "receiver": "...", "size": 1024}
  previous_hash : SHA-256(Block N-1)
  current_hash  : SHA-256(event_type | details | timestamp | previous_hash)
  timestamp     : Unix epoch float
```

**Verification is Zero-Trust:** The Next.js dashboard fetches the raw chain from Django and re-computes every SHA-256 hash locally using `window.crypto.subtle`. The server cannot forge a valid chain. If even one block is deleted, modified, or re-ordered, the client immediately detects it and displays a `SERVER TAMPERING DETECTED` alert.

---

## Known Limitations

1. **Local host trust:** The `*.key` file is Argon2i-encrypted at rest, but a compromised OS can read unencrypted keys from Python memory while the UI daemon is unlocked.
2. **Single Django instance:** The Django server uses SQLite, which is sufficient for thousands of users but will experience write contention under extreme concurrent load. Swap for PostgreSQL for production.
3. **Traffic Analysis:** File sizes are padded to 64KB chunks, but the total ciphertext length still approximates the file size. A network observer can infer approximate file size.
4. **Next.js daemon binding:** The `API_BASE` URL in `page.tsx` is hardcoded per-user session. A production deployment would use session cookies or JWTs to identify which daemon to route to.

---

## Running Tests

SecXfer includes comprehensive cryptographic unit tests and integration tests covering malicious traffic, chunk truncation, and signature forgery:

```bash
pytest
pytest tests/test_crypto_v1.py -v   # Cryptographic primitives
pytest tests/test_transfer_v1.py -v  # Wire protocol & replay protection
pytest tests/test_cli_v1.py -v       # CLI integration
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for our Git Flow branching strategy, commit message conventions, and development setup guide.

---

## Security Disclosure

**Do not open a public GitHub issue for security vulnerabilities.**

See [SECURITY.md](SECURITY.md) for our responsible disclosure policy. We acknowledge reports within 48 hours and aim to patch critical issues within 14 days.

