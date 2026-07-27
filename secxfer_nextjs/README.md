# SecXfer — Next.js Dashboard

> The **premium React frontend** for SecXfer's Zero-Trust file transfer system.

This is the Next.js 15 (App Router) frontend that replaces the legacy vanilla HTML/JS dashboard. It communicates with the local **FastAPI SDK Daemon** for cryptographic operations and never touches keys or plaintext directly.

---

## Tech Stack

| Technology | Purpose |
|---|---|
| **Next.js 15** (App Router) | React framework, server-side rendering |
| **React** | Component-based UI |
| **Tailwind CSS** | Utility-first styling |
| **TypeScript** | Type safety |
| **Web Crypto API** | Client-side SHA-256 for audit log verification |

---

## Running

```bash
npm install   # first time
npm run dev   # starts at http://localhost:3000
```

---

## Architecture

```
Next.js (browser) ──fetch()──► FastAPI SDK Daemon (localhost:8085)
                                        │
                                        ▼
                              X3DH · AES-256-GCM · Ed25519
                                        │
                                        ▼
                              Django Central Server (localhost:8001)
                              [stores ciphertext only — BLIND]
```

The Next.js app itself contains **zero cryptography**. All encryption, decryption, key exchange, and signing happens in the Python FastAPI daemon. The frontend is purely a presentation layer.

---

## Key Features

- **Dark glassmorphism design** with animated grid background
- **Tabbed navigation:** Send · Inbox · Hash-Chained Audit Log
- **Real-time inbox polling** every 5 seconds
- **Color-coded terminal log** (info / success / error / warning)
- **Live audit chain verification** — re-computes SHA-256 hashes locally in the browser using `window.crypto.subtle`
- **Integrity status badge** — shows ✅ / 🚨 on the status bar

---

## Environment Configuration

Update `API_BASE` in `src/app/page.tsx` to match your FastAPI daemon port:

```typescript
const API_BASE = "http://127.0.0.1:8085/api";  // Alice
// or
const API_BASE = "http://127.0.0.1:8086/api";  // Bob

const SERVER_URL = "http://127.0.0.1:8001";     // Django KDC
```
