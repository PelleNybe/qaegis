# Module 1: Proof of Reality (`qaegis.modules.reality_stamp`)

**Proof of Reality** cryptographically binds both **Edge-AI perception outputs** and **arbitrary software/ML artifacts** to verified quantum randomness, NIST FIPS 204/205 Post-Quantum Cryptography signatures, RFC 6962 Merkle audit logs, and distributed fleet cross-witnessing.

## Capabilities

- **Multi-Source QRNG (`qrng.py`):** Harvests entropy from optional network QRNG APIs, a local Qiskit Hadamard superposition circuit (`QiskitHadamardQrngSource`), and Linux kernel CSPRNG (`os.urandom`), combining streams via vectorized NumPy cryptographic XOR mixing.
- **NIST Statistical Health Gating (`nist_tests.py`):** Runs genuine **NIST SP 800-22** (Frequency/Monobit, Block Frequency, Runs, Longest Run of Ones) and **NIST SP 800-90B** (Repetition Count, Adaptive Proportion) health checks on every entropy batch. Failing batches raise `EntropyHealthError` and are never signed.
- **Perception Stamps & Supply-Chain File Signing (`signer.py`):**
  - `RealityStamp`: Signs canonicalized JSON perception frames (`orjson.OPT_SORT_KEYS`) using **ML-DSA-65 (NIST FIPS 204)** or stateless hash-based **SLH-DSA-SHA2-128f (NIST FIPS 205)** with historical `TrustKeyring` verification.
  - `ArtifactSignatureBundle`: Stream-hashes arbitrary files in 64 KiB chunks (`SHA-256` + `SHA3-256` dual digests), binds a 256-bit QRNG nonce, and produces detached PQC signature bundles for ML models, firmware, containers, and SBOMs.
- **Leaf-Bound RFC 6962 Merkle Log (`merkle.py`):** Anchors every stamp in an append-only domain-separated SHA-256 Merkle tree (`0x00 || leaf`, `0x01 || left || right`) persisted in SQLite WAL, enforcing `compute_stamp_leaf_hash()` leaf binding during verification to prevent proof-grafting attacks.
- **Distributed Merkle Root Gossip (`gossip.py`):** Cross-witnesses `ML-DSA-65` signed Merkle roots across edge fleets over CurveZMQ, hydrating state across restarts and raising immediate `gossip.equivocation_detected` alerts if any peer signs conflicting roots at the same tree size.

## Python SDK & Module Usage

```python
import asyncio
from pathlib import Path
from qaegis import QAegisClient


async def main() -> None:
    async with QAegisClient("./state") as client:
        stamp = await client.stamp("cam-front-01", "pedestrian_crossing", confidence=0.98)
        assert client.verify_stamp(stamp).valid

        artifact = Path("model.onnx")
        artifact.write_bytes(b"serialized-onnx-graph")
        sig = await client.sign_file(artifact)
        assert client.verify_file(artifact, sig).valid


asyncio.run(main())
```

## CLI Usage

```bash
# Edge-AI perception stamp + offline verification
qaegis stamp --sensor cam0 --label obstacle --confidence 0.96 --output stamp.json
qaegis verify-stamp stamp.json --keyring ./keys/keyring.json

# Detached post-quantum supply-chain file signing & verification
qaegis sign-file model.onnx -o model.onnx.sig.json
qaegis verify-file model.onnx model.onnx.sig.json --keyring ./keys/keyring.json

# Multi-node Merkle gossip inspection
qaegis gossip status
qaegis gossip verify-peer checkpoint.json peer_identity.public.json
```
