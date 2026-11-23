# Module 2: Quantum Chameleon (`qaegis.modules.chameleon_fw`)

**Quantum Chameleon** is a real-time AI-driven adaptive firewall and dynamic crypto-agility engine that defends edge telemetry links against **Harvest Now, Decrypt Later (HNDL)** adversaries without incurring unnecessary post-quantum overhead on benign LAN traffic.

## Dynamic Security Tiers

| Tier | Trigger Conditions | Cryptographic Suite |
| :--- | :--- | :--- |
| `STANDARD` | Routine low-risk LAN traffic | Ephemeral **X25519** + HKDF-SHA384 + **AES-256-GCM** |
| `ELEVATED` | Confidential payloads, multi-year retention, or elevated anomaly score | Hybrid **X25519 + ML-KEM-768 (FIPS 203)** + HKDF-SHA384 + **AES-256-GCM** |
| `QUANTUM_CRITICAL` | Secret/top-secret telemetry, untrusted WAN/satellite links, or high HNDL risk | Hybrid **X25519 + ML-KEM-768** + **AES-256-GCM** + **ML-DSA-65 / SLH-DSA** transcript signature + forced ephemeral rekeying |

## Architecture

- **`features.py`:** Computes an 8-dimensional real-time traffic feature vector (log payload size, Shannon entropy, non-printable byte ratio, sliding-window burst rate, inter-arrival rate, sensitivity weight, retention risk, and network exposure).
- **`detector.py`:** Combines an unsupervised `scikit-learn` `IsolationForest` anomaly detector with a trainable PyTorch/ONNX Runtime HNDL risk classifier (`CPUExecutionProvider`).
- **`crypto_agility.py`:** Performs real `liboqs` ML-KEM-768 key encapsulation, `cryptography` X25519 key agreement, HKDF-SHA384 key derivation bound to tier/epoch/counter, AES-256-GCM AEAD, and ML-DSA-65/SLH-DSA envelope signing.

## Standalone Python Usage

```python
import asyncio
from pathlib import Path
from qaegis.core.bus import EventBus
from qaegis.core.identity import IdentityManager
from qaegis.modules.chameleon_fw import ChameleonFirewallService, TrafficObservation


async def main() -> None:
    bus = EventBus()
    await bus.start()
    alice = IdentityManager(Path("./keys_a"), "drone-01").load_or_create()
    bob = IdentityManager(Path("./keys_b"), "ground-01").load_or_create()

    fw_alice = ChameleonFirewallService(bus, alice)
    fw_bob = ChameleonFirewallService(bus, bob)

    obs = TrafficObservation(
        source="drone-01",
        destination="ground-01",
        protocol="satellite",
        sensitivity="top_secret",
        payload_bytes=b"classified-flight-plan",
        long_term_retention_years=20.0,
    )
    packet = await fw_alice.protect(obs, recipient=bob.public_bundle())
    print("Assigned Tier:", packet.envelope.tier, "Suite:", packet.envelope.cipher_suite)

    recovered = fw_bob.unprotect(packet.envelope, expected_sender=alice.public_bundle())
    assert recovered == b"classified-flight-plan"
    await bus.stop()


asyncio.run(main())
```
