# SecXfer

> Client-side encrypted file-transfer security engineering project.

SecXfer explores a three-layer architecture in which cryptographic operations occur in a local client service while a central Django server primarily stores and transports ciphertext.

The project uses established cryptographic primitives through maintained libraries such as PyNaCl/libsodium and PyCA rather than implementing encryption algorithms from scratch.

However, the surrounding **protocol composition, session-establishment flow, replay-handling design, key-management workflow, and application integration are project-designed and have not undergone an independent cryptographic audit or formal verification**.

SecXfer should therefore be treated as an engineering and academic security project, **not as audited production cryptographic software**.

---

## Security Scope

SecXfer primarily explores protection against:

- disclosure of plaintext after compromise of central file storage
- unauthorized modification of encrypted file contents
- replay of previously observed transfers
- accidental storage of private encryption keys on the central server
- misuse of identity information during transfer workflows

It does **not** claim complete protection against:

- compromised client operating systems
- malware reading plaintext or keys from process memory
- traffic analysis
- denial-of-service attacks
- compromised cryptographic dependencies
- weaknesses in project-designed protocol composition
- implementation errors outside the underlying cryptographic primitives

---

## Security Mechanisms

| Property | Mechanism | Qualification |
|---|---|---|
| Confidentiality | XChaCha20-Poly1305 | Authenticated encryption provided through libsodium |
| Integrity | AEAD + Ed25519 | Protects encrypted content and signed metadata |
| Authentication | Ed25519 proof of possession | Application-level identity mechanism |
| Session establishment | X25519 / X3DH-style flow | Project implementation; not independently audited |
| Forward secrecy | Ephemeral X25519 keys | Depends on correct session implementation and key destruction |
| Replay mitigation | Persistent nonce tracking | Depends on integrity and persistence of local replay state |
| Optional PSK mixing | HMAC-SHA256 | Additional protection when a strong PSK is securely provisioned; **not claimed as general post-quantum security** |
| Audit tamper evidence | SHA-256 hash chain | Detects modification when checked against trusted state |
| Central-server confidentiality | Client-side encryption | Server is designed to store ciphertext rather than private keys/plaintext |

---

## Cryptographic Building Blocks

The implementation uses:

- X25519-based key agreement
- XChaCha20-Poly1305 authenticated encryption
- Ed25519 signatures
- HKDF-SHA256 key derivation
- password-protected local key storage
- persistent replay-nonce tracking
- SHA-256 hash-chain audit verification

These primitives are provided through established cryptographic libraries.

SecXfer does **not** implement its own encryption cipher.

---

## Optional PSK Mixing

SecXfer supports mixing a pre-shared secret into session-derived key material using HMAC-SHA256.

A sufficiently strong PSK that is generated, exchanged, stored, and protected independently of the public-key exchange may provide an additional secret unavailable to an attacker who later breaks the asymmetric key exchange.

However:

- this mechanism has not undergone independent cryptographic analysis
- secure PSK provisioning remains an external requirement
- the design should not be described as general-purpose or formally validated post-quantum cryptography
- no NIST-standard post-quantum KEM is currently being claimed here

For that reason, the project describes this as **optional PSK hardening**, not verified “post-quantum resistance.”

---

## Audit Status

SecXfer has **not undergone an independent security or cryptographic audit**.

Security statements in this repository describe the intended behavior and threat model of the implementation. They should not be interpreted as guarantees suitable for production deployment.

Independent review of the following would be particularly valuable:

- session establishment
- key lifecycle management
- replay-state handling
- identity binding
- protocol message construction
- error handling
- local daemon trust assumptions

---

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
