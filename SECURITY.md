# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `0.1.x` | Yes |

## Reporting a Vulnerability

**Do not open a public GitHub issue for suspected cryptographic, authentication, or remote code execution vulnerabilities.**

Please report security vulnerabilities privately via GitHub Security Advisories on `https://github.com/PelleNybe/qaegis/security/advisories/new` or by contacting the maintainers directly. Include:

1. A clear description of the vulnerability and affected subsystem (`core`, `reality_stamp`, `chameleon_fw`, `qubit_compiler`, `quantum_dreamer`, `quantum_entropy`, or `adapters`).
2. Steps to reproduce or a minimal proof-of-concept.
3. Output of `qaegis version` and `qaegis doctor` (redacting any private keys or cloud tokens).

We aim to acknowledge reports within 48 hours and provide a coordinated remediation timeline within 7 days.

## Security Architecture & Threat Model Summary

Q-Aegis is designed to defend autonomous edge nodes against:

- **Harvest-Now-Decrypt-Later (HNDL) Adversaries:** Mitigated by hybrid X25519 + NIST FIPS 203 (`ML-KEM-768`) key establishment with HKDF-SHA384 domain separation and AES-256-GCM authenticated encryption.
- **Quantum Signature Forgery:** Mitigated by NIST FIPS 204 (`ML-DSA-65`) primary signatures with NIST FIPS 205 (`SLH-DSA-SHA2-128f`) stateless hash-based fallback signatures.
- **Entropy Starvation & Biased RNG Attacks:** Mitigated by multi-source XOR mixing (HTTP QRNG + local Qiskit Hadamard QRNG + Linux kernel CSPRNG) gated by NIST SP 800-22 and SP 800-90B continuous health tests.
- **Audit Log & Perception Tampering:** Mitigated by RFC 6962 domain-separated SHA-256 Merkle trees and hash-chained SQLite WAL audit tables.
- **Local Privilege Escalation / Key Exposure:** Mitigated by strict `0o600` secret file permissions, `0o700` key directories, non-root Docker execution, and systemd capability stripping (`CapabilityBoundingSet=`, `NoNewPrivileges=yes`, `ProtectSystem=strict`).

See [docs/cryptography-threat-model.md](docs/cryptography-threat-model.md) for the complete cryptographic specification.
