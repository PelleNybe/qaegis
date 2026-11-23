# Module 1: Proof of Reality (`qaegis.modules.reality_stamp`)

**Proof of Reality** cryptographically binds Edge-AI perception outputs to verified quantum randomness, NIST Post-Quantum Cryptography signatures, and an append-only Merkle Tree audit log.

## Capabilities

- **Multi-Source QRNG (`qrng.py`):** Harvests entropy from optional network QRNG APIs, a local Qiskit Hadamard superposition circuit (`QiskitHadamardQrngSource`), and Linux kernel CSPRNG (`os.urandom`), combining streams via cryptographic XOR mixing.
- **NIST Statistical Validation (`nist_tests.py`):** Runs genuine **NIST SP 800-22** (Frequency/Monobit, Block Frequency, Runs, Longest Run of Ones) and **NIST SP 800-90B** (Repetition Count, Adaptive Proportion) health checks on every entropy batch. Failing batches raise `EntropyHealthError` and are never signed.
- **Post-Quantum Signatures (`signer.py`):** Signs canonicalized JSON payloads (`orjson.OPT_SORT_KEYS`) using **ML-DSA-65 (NIST FIPS 204)** or stateless hash-based **SLH-DSA-SHA2-128f (NIST FIPS 205)** via `liboqs-python`.
- **Tamper-Evident Merkle Log (`merkle.py`):** Anchors every stamp in an RFC 6962 domain-separated SHA-256 Merkle tree (`0x00 || leaf`, `0x01 || left || right`) persisted in SQLite WAL with offline inclusion proof verification.
- **Distributed Merkle Root Gossip (`gossip.py`):** Cross-witnesses ML-DSA-65 signed Merkle roots across edge fleets over CurveZMQ, persisting verified peer checkpoints and raising immediate `gossip.equivocation_detected` alerts + `qaegis_gossip_equivocation_total` metrics if a peer signs conflicting roots at the same tree size.

## Standalone Python Usage

```python
import asyncio
from pathlib import Path
from qaegis.core.bus import EventBus
from qaegis.core.identity import IdentityManager
from qaegis.core.storage import StorageEngine
from qaegis.modules.reality_stamp import RealityStampService, verify_reality_stamp


async def main() -> None:
    bus = EventBus()
    storage = StorageEngine(Path("./data/stamps.db"))
    identity = IdentityManager(Path("./keys"), "edge-cam-01").load_or_create()
    await bus.start()
    await storage.initialize()

    svc = RealityStampService(bus=bus, identity=identity, storage=storage)
    await svc.start()

    stamp = await svc.stamp_perception(
        sensor_id="cam-front-01",
        perception_label="pedestrian_crossing",
        confidence=0.97,
        metadata={"frame_id": 4012},
    )
    verification = verify_reality_stamp(stamp)
    print("Valid:", verification.valid, "Algorithm:", verification.algorithm)

    await svc.stop()
    await storage.close()
    await bus.stop()


asyncio.run(main())
```

## CLI Usage

```bash
qaegis stamp --sensor cam0 --label obstacle --confidence 0.96 --output stamp.json
qaegis verify-stamp stamp.json
qaegis gossip status
qaegis gossip verify-peer checkpoint.json peer_identity.public.json
```
