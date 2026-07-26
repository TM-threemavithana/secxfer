# secxfer

Cryptographically secure file transfer library using pre-shared keys.

See [`threat_model.md`](threat_model.md) and [`protocol_flow.md`](protocol_flow.md) for full design rationale.

## Security properties

| Property | Status |
|---|---|
| Confidentiality | ✅ XChaCha20-Poly1305 (secretstream) |
| Integrity | ✅ AEAD per-chunk; Ed25519 over whole-file SHA-256 |
| Authentication | ✅ Sender is verified against pre-shared public key |
| Replay protection | ✅ Seen-nonce cache (in-memory, TTL-bounded) |
| Ordering/truncation | ✅ secretstream TAG_FINAL; truncated stream → error |
| Forward secrecy | ❌ Static keys; no forward secrecy (documented in threat model §5) |
| Key distribution | ❌ Out of scope; keys must be exchanged out-of-band |

## Stack

- Python 3.11+
- [PyNaCl](https://pynacl.readthedocs.io/) (libsodium bindings)
- Primitives: X25519 + HKDF-SHA256, XChaCha20-Poly1305 (secretstream), Ed25519
- Zero runtime dependencies beyond PyNaCl

## Install

```
pip install -e ".[dev]"
```

## Quick start

### 1. Generate keypairs

Each party generates their own keypair. Private keys never leave their machine.

```
secxfer keygen --dir ./alice-keys
secxfer keygen --dir ./bob-keys
```

Output:
```
Generated keypair in C:\...\alice-keys\
  Private key : alice-keys\identity.key  (keep secret)
  Public key  : alice-keys\identity.pub  (share with peers)
  Key ID      : a3f2c7d1b09e4512
```

### 2. Exchange public keys (out-of-band)

Copy `.pub` files over any trusted channel (USB, secure email, etc.):

```
copy alice-keys\identity.pub bob-keys\alice.pub
copy bob-keys\identity.pub   alice-keys\bob.pub
```

The keystore directory for each party is the directory containing their
trusted peers' `.pub` files.

### 3. Send a file

```
secxfer send secret.txt ^
    --identity alice-keys\identity.key ^
    --to alice-keys\bob.pub ^
    --out transfer.bin
```

Or pipe directly:

```
secxfer send secret.txt --identity alice-keys\identity.key --to alice-keys\bob.pub | ^
    secxfer receive received.txt --identity bob-keys\identity.key --keystore bob-keys
```

### 4. Receive a file

```
secxfer receive received.txt ^
    --identity bob-keys\identity.key ^
    --keystore bob-keys ^
    --in transfer.bin
```

`received.txt` is created only after all authentication and signature checks pass.
Partial or unauthenticated output is never written to the destination path.

## CLI reference

```
secxfer keygen  --dir DIR [--name NAME]
secxfer show-id --identity KEY
secxfer send    FILE --identity KEY --to PUBKEY [--ttl SECS] [--out FILE]
secxfer receive DEST --identity KEY --keystore DIR [--in FILE]
```

| Flag | Description |
|---|---|
| `--dir` | Directory to write key files |
| `--name` | Key file base name (default: `identity`) |
| `--identity` | Path to your `.key` file |
| `--to` | Path to the receiver's `.pub` file |
| `--keystore` | Directory containing trusted sender `.pub` files |
| `--ttl` | Transfer time-to-live in seconds (default: 300) |
| `--out` | Write encrypted output to a file (default: stdout) |
| `--in` | Read encrypted input from a file (default: stdin) |

## Wire format (summary)

```
Preamble (57 bytes, unauthenticated):
  version       : 1 byte  (0x01)
  sender_key_id : 8 bytes (first 8 of SHA-256(x25519_pubkey))
  stream_salt   : 24 bytes (HKDF salt; fresh per transfer)
  stream_header : 24 bytes (secretstream init_push output)

Chunk 0 — metadata (AEAD-protected, TAG_MESSAGE):
  transfer_nonce, timestamp, ttl, filename, file_size

Chunks 1..N — file data (AEAD-protected, TAG_MESSAGE)

Chunk N+1 — trailer (AEAD-protected, TAG_FINAL):
  Ed25519 signature (64 bytes)
```

Each chunk is length-prefixed (4-byte big-endian uint32 before the ciphertext).

## Module architecture

```
cli.py          ← argument parsing only; no business logic
  └── transfer.py  ← state machines, nonce cache, .part lifecycle
        ├── crypto.py    ← stateless primitives (X25519, HKDF, secretstream, Ed25519)
        └── keystore.py  ← key lookup, key generation, key loading
```

Strict dependency DAG: `cli → transfer → {crypto, keystore}`. `crypto` and
`keystore` do not import from each other or from `transfer`.

## Known limitations

1. **No forward secrecy.** Static pre-shared keys mean the shared secret
   `X25519(alice_priv, bob_pub)` is the same for every transfer between a pair.
   Compromise of either party's private key exposes all past transfers.

2. **In-memory nonce cache.** Replay protection resets on process restart.
   A long-running receiver service should persist the cache externally.

3. **No cross-process replay protection.** Each process has its own `NonceCache`
   instance in its own memory space.  Two receiver processes do not share the
   same cache, so a replay sent to a second process is not rejected.  This is
   not a thread-safety issue (within a single process, `NonceCache` is
   protected by a `threading.Lock`); it is a "no shared state exists" issue.
   Fix by using an external store (e.g. Redis) as the nonce cache backend.

4. **Local file permissions.** The `identity.key` file is written using
   `chmod 600` on a best-effort basis. However, effective isolation relies
   on the host operating system (POSIX permissions or Windows ACLs). If
   a compromised or malicious process runs under the same user account,
   or if OS-level isolation fails, the private key can be stolen. A stolen
   private key compromises all future transfers (no forward secrecy) and
   allows the attacker to forge signatures.

## Test

```
pytest
pytest --tb=short -q   # compact output
pytest tests/test_crypto.py -v   # crypto layer only
```

51 tests covering happy paths and named negative tests for every attack
in the threat model's §6.
