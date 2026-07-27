# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 2.x (Django + Next.js) | ✅ |
| 1.x (P2P) | ❌ End of Life |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability, please send an email to the project maintainers with:

1. A description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Any suggested mitigation

We will acknowledge receipt within **48 hours** and aim to provide a fix within **14 days** for critical vulnerabilities.

## Scope

The following are in scope for security reports:

- Cryptographic protocol weaknesses (X3DH implementation, key derivation)
- Authentication bypass on the Django KDC
- Hash-chain audit log manipulation vulnerabilities
- Key material leakage through any channel
- Replay attack vulnerabilities

The following are **out of scope**:

- Vulnerabilities in third-party libraries (report to them directly)
- Denial of Service attacks on the local development server
- Issues requiring physical access to the host machine
