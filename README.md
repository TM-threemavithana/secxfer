# SecXfer

> Client-side encrypted file-transfer security engineering project.

SecXfer explores a three-layer file-transfer architecture in which cryptographic operations occur in a local client service while the central Django server primarily stores and transports ciphertext.

The implementation uses established cryptographic primitives through maintained libraries such as PyNaCl/libsodium and PyCA rather than implementing encryption algorithms from scratch.

The surrounding **protocol composition, session-establishment flow, replay-handling design, key-management workflow, and application integration are project-designed and have not undergone an independent cryptographic audit or formal verification**.

SecXfer should therefore be treated as a security-engineering and academic project, **not as audited production cryptographic software**.

---

## Security Properties

| Property | Mechanism | Status / Qualification |
|---|---|---|
| Confidentiality | XChaCha20-Poly1305 | Implemented using libsodium |
| Integrity | AEAD + Ed25519 | Implemented; application integration not independently audited |
| Authentication | Ed25519 proof of possession | Implemented at application level |
| Forward secrecy | Ephemeral X25519 session material | Intended property; depends on correct protocol implementation and key lifecycle |
| Replay mitigation | Persistent nonce tracking | Depends on integrity and persistence of local replay state |
| Optional PSK hardening | HMAC-SHA256 PSK mixing | Experimental additional secret-key hardening; **not claimed as verified general post-quantum security** |
| Server-side confidentiality | Client-side encryption | Designed so the central server stores ciphertext rather than private keys/plaintext |
| Audit tamper evidence | SHA-256 hash chain | Detects modification when compared against trusted state |

---

## Threat Model

The project primarily explores protection against:

- plaintext disclosure following compromise of central storage
- unauthorized modification of ciphertext
- replay of previously observed transfers
- accidental server-side storage of private encryption keys
- misuse of identity material during transfer workflows

It does not claim complete protection against:

- compromised client operating systems
- malware reading plaintext or key material from process memory
- traffic analysis
- denial-of-service
- compromised cryptographic dependencies
- weaknesses in project-designed protocol composition

---

## Optional PSK Hardening

SecXfer can mix a pre-shared secret into session-derived key material using HMAC-SHA256.

If a sufficiently strong PSK is generated, distributed, and stored independently of the asymmetric exchange, it may provide additional secret material unavailable to an attacker who compromises only the public-key mechanism.

However:

- the construction has not undergone independent cryptographic review
- secure PSK provisioning is an external assumption
- the mechanism is not a replacement for standardized post-quantum key-establishment algorithms
- the project does not claim formal or independently verified post-quantum security

For this reason, the feature is described as **optional PSK hardening**, not simply “Post-Quantum Resistance ✅”.

---

## Audit Status

SecXfer has **not undergone an independent cryptographic or security audit**.

Security statements in this repository describe intended properties and observed implementation behavior. They should not be interpreted as formal guarantees suitable for production deployment.

Independent review would be especially valuable for:

- session establishment
- identity binding
- key lifecycle management
- replay-state handling
- protocol message construction
- error handling
- local-daemon trust assumptions

## Known Limitations

Important limitations include:

- a compromised client OS may access decrypted key material while the cryptographic service is running
- plaintext remains accessible before encryption and after decryption
- encrypted file sizes can leak approximate size information
- traffic analysis remains possible
- denial-of-service protection is limited
- SQLite-based development deployments can encounter write contention
- replay protection depends on persistent local state
- the protocol composition has not been independently audited

Security issues and protocol concerns are welcome through the repository's security-reporting process.

---
