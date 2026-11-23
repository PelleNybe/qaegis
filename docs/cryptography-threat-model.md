# Cryptography & Threat Model

Q-Aegis executes 100% real cryptographic primitives backed by **Open Quantum Safe (`liboqs`)** and **Python `cryptography` (OpenSSL)**. No cryptographic operation is ever stubbed or simulated.

## Standardized Algorithms

| Role | Algorithm | Standard | Quantum Safe | Public Key | Artifact Size |
| :--- | :--- | :--- | :---: | ---: | ---: |
| **Primary Digital Signature** | `ML-DSA-65` | NIST FIPS 204 | Yes | 1,952 B | 3,309 B sig |
| **Stateless Hash Signature Backup** | `SLH-DSA-SHA2-128f` (`SLH_DSA_PURE_SHA2_128F`) | NIST FIPS 205 | Yes | 32 B | 17,088 B sig |
| **Post-Quantum KEM** | `ML-KEM-768` | NIST FIPS 203 | Yes | 1,184 B | 1,088 B ct |
| **Classical Hybrid KEX** | `X25519` | RFC 7748 | No | 32 B | 32 B pub |
| **Symmetric AEAD** | `AES-256-GCM` | NIST SP 800-38D | Yes (128-bit PQ) | 256-bit key | 12 B nonce + 16 B tag |
| **Key Derivation** | `HKDF-SHA384` | RFC 5869 / FIPS 180-4 | Yes | — | 32 B derived key |

## Hybrid Key Establishment (Quantum Chameleon)

In `ELEVATED` and `QUANTUM_CRITICAL` tiers, Q-Aegis implements defense-in-depth hybrid key exchange:

1. Generate an ephemeral `X25519` keypair $(sk_e, pk_e)$ and compute $ss_{\text{classical}} = \text{X25519}(sk_e, pk_{\text{peer}})$.
2. Encapsulate against the peer's `ML-KEM-768` public key to obtain $(ct_{\text{pq}}, ss_{\text{pq}})$.
3. Compute transcript salt $S = \text{SHA-384}(pk_e \parallel pk_{\text{peer}} \parallel ct_{\text{pq}})$.
4. Derive the 256-bit AES-GCM key via $\text{HKDF-SHA384}(\text{IKM} = ss_{\text{classical}} \parallel ss_{\text{pq}}, \text{salt} = S, \text{info} = \text{tier} \parallel \text{epoch} \parallel \text{counter})$.
5. Bind AAD to `associated_data | tier | sender_id | recipient_id | epoch | counter` to prevent cross-tier downgrade or replay attacks.
6. In `QUANTUM_CRITICAL` mode, sign the entire canonical envelope transcript with `ML-DSA-65` (or `SLH-DSA`) and force an epoch advance for forward secrecy.

## Entropy Integrity & NIST Validation

Every `MultiSourceQrng.harvest()` call XOR-mixes independent sources (optional HTTP QRNG $\oplus$ Qiskit Hadamard QRNG $\oplus$ Linux CSPRNG). By the XOR mixing lemma, the output remains indistinguishable from uniform random as long as at least one independent source is uncompromised. Every batch is validated against:

- **NIST SP 800-90B:** Repetition Count Test and Adaptive Proportion Test.
- **NIST SP 800-22:** Frequency (Monobit), Block Frequency, Runs, and Longest Run of Ones tests.

Batches failing validation trigger a `qaegis_qrng_health_checks_total{passed="false"}` metric increment and raise `EntropyHealthError`.

## Key Storage & Cryptographic Hygiene

- Secret key bundles (`device_identity.secret.json`) are written via atomic `mkstemp` + `fchmod(0o600)` + `fsync` + `os.replace`.
- `IdentityManager.load()` refuses to read any secret file whose POSIX mode grants group or world access (`mode & 0o077 != 0`).
- All hash, fingerprint, and shared-secret checks use constant-time `hmac.compare_digest`.
- Run `qaegis cbom --output cbom.json` to emit a machine-readable Cryptographic Bill of Materials for compliance auditing.
