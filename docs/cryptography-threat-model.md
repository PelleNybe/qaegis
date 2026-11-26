# Cryptography & Threat Model

Q-Aegis executes 100% real cryptographic primitives backed by **Open Quantum Safe (`liboqs`)**, **Python `cryptography` (OpenSSL)**, **PKCS#11 (`python-pkcs11`)**, **Linux TPM 2.0 (`tpm2-tools`)**, and **CurveZMQ (`pyzmq`)**. No cryptographic primitive is ever mocked or simulated.

---

## Standardized Algorithms & Wire Sizes

| Role | Algorithm | Standard | Quantum Safe | Public Key | Artifact / Ciphertext Size |
| :--- | :--- | :--- | :---: | ---: | ---: |
| **Primary Digital Signature** | `ML-DSA-65` | NIST FIPS 204 | Yes (Cat. 3) | 1,952 B | 3,309 B signature |
| **Stateless Hash Backup Signature** | `SLH-DSA-SHA2-128f` (`SLH_DSA_PURE_SHA2_128F`) | NIST FIPS 205 | Yes (Cat. 1) | 32 B | 17,088 B signature |
| **Post-Quantum KEM** | `ML-KEM-768` | NIST FIPS 203 | Yes (Cat. 3) | 1,184 B | 1,088 B ciphertext |
| **Classical Hybrid KEX** | `X25519` | RFC 7748 | Classical | 32 B | 32 B ephemeral pubkey |
| **Fleet Transport Auth** | `Curve25519` (`CurveZMQ`) | CurveCP / ZAP | Classical transport + PQC payload | 40-char Z85 | Authenticated framing |
| **Symmetric AEAD & Envelope Seal** | `AES-256-GCM` | NIST SP 800-38D | Yes (128-bit PQ) | 256-bit key | 12 B nonce + 16 B tag |
| **Key Derivation** | `HKDF-SHA384` | RFC 5869 / FIPS 180-4 | Yes | — | 32 B derived key |

---

## 1. Hybrid Key Establishment & Replay Defense (Quantum Chameleon)

In `ELEVATED` and `QUANTUM_CRITICAL` tiers (`qaegis encrypt`, `QAegisClient.encrypt`, and `ChameleonFirewallService`), Q-Aegis executes defense-in-depth hybrid key establishment:

1. Generate an ephemeral `X25519` keypair $(sk_e, pk_e)$ and compute $ss_{\text{classical}} = \text{X25519}(sk_e, pk_{\text{peer}})$.
2. Encapsulate against the recipient's `ML-KEM-768` public key to obtain $(ct_{\text{pq}}, ss_{\text{pq}})$.
3. Compute transcript salt $S = \text{SHA-384}(pk_e \parallel pk_{\text{peer}} \parallel ct_{\text{pq}})$.
4. Derive the 256-bit AES-GCM key via $\text{HKDF-SHA384}(\text{IKM} = ss_{\text{classical}} \parallel ss_{\text{pq}}, \text{salt} = S, \text{info} = \text{tier} \parallel \text{epoch} \parallel \text{counter})$.
5. Bind AEAD Additional Authenticated Data (AAD) to `associated_data | tier | cipher_suite | sender_id | recipient_id | epoch | counter`.
6. Enforce strict cipher-suite header matching, recipient node-ID binding, constant-time sender key / `TrustKeyring` verification, and bounded `(sender_id, envelope_id, epoch, counter)` replay-cache rejection.
7. In `QUANTUM_CRITICAL` mode, sign the canonical envelope transcript with `ML-DSA-65` (or `SLH-DSA`) and force an immediate epoch advance for forward secrecy.

---

## 2. Proof of Reality, Detached File Signing & Split-View Defense

- **Perception Stamps (`RealityStamp`):** Canonicalized JSON payloads incorporate a verified QRNG nonce and are signed with `ML-DSA-65` or `SLH-DSA`. `verify_reality_stamp()` enforces constant-time payload digest checks, historical `TrustKeyring` lineage checks, PQC signature verification, and **leaf-bound RFC 6962 Merkle proof verification** (`compute_stamp_leaf_hash()`) to defeat proof-grafting substitution attacks.
- **Supply-Chain File Bundles (`ArtifactSignatureBundle`):** `qaegis sign-file` streams arbitrary files in 64 KiB chunks, computing dual **SHA-256 + SHA3-256** digests to hedge against single-hash structural weaknesses, binds a 256-bit QRNG nonce, and signs the canonical transcript with `ML-DSA-65` or `SLH-DSA`.
- **P2P Merkle Root Gossip (`MerkleGossipNode`):** Fleet nodes exchange `ML-DSA-65` signed `(node_id, tree_size, merkle_root)` checkpoints over CurveZMQ. Any peer presenting two distinct valid roots for the same `tree_size` immediately triggers a `gossip.equivocation_detected` alert and increments `qaegis_gossip_equivocation_total`.

---

## 3. Multi-Source QRNG & NIST Statistical Health Gating

Every `MultiSourceQrng.harvest()` batch XOR-mixes independent streams (optional HTTP QRNG $\oplus$ local Qiskit Hadamard circuit QRNG $\oplus$ Linux kernel CSPRNG). By the XOR mixing lemma, output bias remains bounded by the strongest independent source. Every batch is tested against:

- **NIST SP 800-90B:** Repetition Count Test and Adaptive Proportion Test.
- **NIST SP 800-22:** Frequency (Monobit), Block Frequency, Runs, and Longest Run of Ones tests.

Failing batches increment `qaegis_qrng_health_checks_total{passed="false"}` and raise `EntropyHealthError` before any signature or key operation proceeds.

---

## 4. Hardware Key Sealing, Zero-Downtime Rotation & CBOM

- **PKCS#11 HSM / SoftHSM2 (`PKCS11Sealer`):** Generates or locates a non-extractable `CKK_AES` 256-bit KEK inside the HSM token (`CKA_SENSITIVE=True, CKA_EXTRACTABLE=False`), wraps an ephemeral 256-bit DEK via `CKM_AES_CBC_PAD`, and seals the node's PQC key bundle under `AES-256-GCM` bound to `node_id` and `key_id`.
- **Linux TPM 2.0 (`TPM2Sealer`):** Seals the 256-bit DEK against configurable PCR banks (default `sha256:0,7`) on `/dev/tpmrm0` via `tpm2_createprimary`, `tpm2_create`, `tpm2_load`, and `tpm2_unseal`, securely overwriting temporary files prior to deletion.
- **Zero-Downtime Key Rotation (`qaegis rotate-keys`):** Generates fresh `v(N+1)` PQC + X25519 keys, archives retired public keys into `keys/keyring.json` (`0o600`), zeroizes retired in-memory private buffers (`bytearray` overwrite + use-after-retire guard), and keeps all historical `v1..vN` signatures offline-verifiable.
- **Cryptographic Bill of Materials (`qaegis cbom --format cyclonedx`):** Exports a standards-compliant **CycloneDX 1.6 CBOM** enumerating NIST algorithm OIDs, parameter sets, key fingerprints, and NIST post-quantum security categories.
