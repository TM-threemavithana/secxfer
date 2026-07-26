# secxfer: Future Roadmap & Cryptographic Challenges

This document outlines the architectural and cryptographic challenges involved in expanding `secxfer` beyond its current scope of a zero-trust, peer-to-peer utility using pre-shared keys. It specifically details why Key Distribution and Forward Secrecy were explicitly scoped out, and what a rigorous implementation of those features would require.

## 1. The Key Distribution & Trust Bootstrap Problem

**Current State:** `secxfer` uses an out-of-band (OOB) key distribution model. Alice and Bob must physically or digitally exchange `.pub` files over a pre-existing trusted channel (e.g., USB drive, Signal message, in-person QR code).

**The Naive Solution:** A central "Key Server" where users upload their public keys (e.g., mapped to an email address) and the CLI automatically fetches them (`GET /keys/bob@example.com`).

**Why the Naive Solution is Flawed:**
A central Key Server without robust authentication introduces a catastrophic Man-In-The-Middle (MITM) vulnerability. If the server is compromised, or if an attacker registers "bob@example.com" before the real Bob does, the server can serve attacker-controlled public keys. Alice would silently encrypt her files for the attacker, completely defeating the purpose of end-to-end encryption. The naive Key Server simply relocates the trust anchor from "out-of-band exchange" to "blind trust in a central database," which is strictly worse security.

**The Rigorous Solution:**
To securely automate key distribution without blindly trusting a central server, `secxfer` would need to implement one of the following:
1. **Public Key Infrastructure (PKI):** A system of trusted Certificate Authorities (CAs) that sign users' public keys. This requires managing certificate revocation lists (CRLs) and establishing a trusted root hierarchy.
2. **Web of Trust (PGP-style):** A decentralized model where users sign each other's keys to build a graph of trust.
3. **Key Transparency (e.g., CONIKS):** A verifiable, append-only cryptographic ledger (Merkle tree) that allows users to independently audit the Key Server and detect if their public key has been maliciously altered.

## 2. Forward Secrecy & X3DH

**Current State:** `secxfer` uses static X25519 keys. The derived shared secret `X25519(alice_priv, bob_pub)` is identical for every transfer between Alice and Bob. If either party's private key is compromised today, an attacker who captured network traffic in the past can retroactively decrypt all previous transfers.

**The Naive Solution:** Generate an ephemeral X25519 key for every transfer.
While this provides *Sender Forward Secrecy*, it does not provide true asynchronous Forward Secrecy for offline receivers. If Bob is offline, Alice must still use Bob's static key to encrypt the file, meaning compromise of Bob's static key still breaks past ciphertexts.

**The Rigorous Solution (X3DH):**
To achieve full asynchronous Forward Secrecy, `secxfer` would need to implement a protocol similar to the Signal Protocol's **Extended Triple Diffie-Hellman (X3DH)**.
- **Pre-Keys:** Bob generates a batch of one-time-use Ephemeral Pre-Keys and uploads them to a central server.
- **The Handshake:** When Alice wants to send a file, she fetches Bob's Identity Key and *one* of his Pre-Keys. She performs ECDH operations combining her ephemeral key, her static key, Bob's static key, and Bob's ephemeral Pre-Key.
- **Protection Boundaries:** Once Bob decrypts the file, he deletes the Pre-Key. If his static Identity Key is compromised later, past ciphertexts remain safe because the mathematical derivation required the now-deleted Pre-Key. 
- **Limitations:** It is critical to note that even with X3DH, if an Identity Key is compromised, the attacker can impersonate that user *going forward* (active attack). Forward secrecy only protects the *past*.

## Conclusion
Implementing Automated Key Distribution and Forward Secrecy in an asynchronous context requires transforming `secxfer` from a stateless CLI into a complex distributed system backed by verifiable ledgers and pre-key servers. The current design deliberately prioritizes a minimal attack surface, stateless execution, and absolute zero-trust infrastructure over convenience.
