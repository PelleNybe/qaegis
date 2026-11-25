# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `0.6.x` | Yes |
| `0.5.x` | Security fixes only |
| `< 0.5.0` | No |

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
- **Audit Log & Perception Tampering:** Mitigated by RFC 6962 domain-separated SHA-256 Merkle trees with strict leaf-to-stamp binding, hash-chained SQLite WAL audit tables, row/snapshot integrity checks, and multi-node ML-DSA-65 Merkle root gossiping with split-view equivocation detection.
- **Replay & Downgrade Attacks:** Mitigated by HKDF-SHA384 tier/epoch/counter domain separation, cipher-suite header verification, recipient binding, and bounded authenticated replay-cache enforcement in Quantum Chameleon.
- **Local Privilege Escalation / Key Exposure:** Mitigated by PKCS#11 HSM/SoftHSM2 and Linux TPM 2.0 PCR-bound key sealing, zero-downtime key rotation with in-memory secret zeroization, strict `0o600` secret file permissions, `0o700` key directories, CurveZMQ ZAP allowlist authentication, non-root Docker execution, and systemd capability stripping (`CapabilityBoundingSet=`, `NoNewPrivileges=yes`, `ProtectSystem=strict`).

See [docs/cryptography-threat-model.md](docs/cryptography-threat-model.md) for the complete cryptographic specification.
