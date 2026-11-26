# Module 2: Quantum Chameleon (`qaegis.modules.chameleon_fw`)

**Quantum Chameleon** is a real-time AI-driven adaptive firewall and dynamic post-quantum crypto-agility engine that defends edge telemetry, API secrets, and stored files against **Harvest Now, Decrypt Later (HNDL)** adversaries without imposing unnecessary latency on low-risk local links.

## Dynamic Security Tiers

| Tier | Trigger Conditions | Cryptographic Suite |
| :--- | :--- | :--- |
| `STANDARD` | Routine low-risk LAN traffic | Ephemeral **X25519** + HKDF-SHA384 + **AES-256-GCM** |
| `ELEVATED` | Confidential payloads, multi-year retention, or elevated anomaly score | Hybrid **X25519 + ML-KEM-768 (FIPS 203)** + HKDF-SHA384 + **AES-256-GCM** |
| `QUANTUM_CRITICAL` | Secret/top-secret telemetry, untrusted WAN/satellite links, or high HNDL risk | Hybrid **X25519 + ML-KEM-768** + **AES-256-GCM** + **ML-DSA-65 / SLH-DSA** transcript signature + forced ephemeral rekeying |

## Architecture & Security Defenses

- **`features.py`:** Extracts an 8-dimensional real-time traffic vector (log payload size, Shannon byte entropy, non-printable ratio, sliding-window burst rate, inter-arrival rate, sensitivity weight, retention horizon, and link exposure).
- **`detector.py`:** Fuses an unsupervised `scikit-learn` `IsolationForest` anomaly detector with a trainable PyTorch/ONNX Runtime HNDL risk classifier (`CPUExecutionProvider`).
- **`crypto_agility.py`:** Executes real `liboqs` `ML-KEM-768` encapsulation, `cryptography` `X25519` ECDH, `HKDF-SHA384` domain-separated key derivation, `AES-256-GCM` AEAD, cipher-suite & recipient binding, `TrustKeyring` historical sender verification, and bounded replay-cache enforcement.

## Python Usage

```python
import asyncio
from qaegis import QAegisClient


async def main() -> None:
    async with QAegisClient("./state") as client:
        packet = await client.protect(
            b"classified-flight-plan",
            protocol="satellite",
            sensitivity="top_secret",
            retention_years=20.0,
        )
        print("Selected Tier:", packet.envelope.tier, "Suite:", packet.envelope.cipher_suite)
        recovered = client.decrypt(packet.envelope, use_local_keyring=True)
        assert recovered == b"classified-flight-plan"


asyncio.run(main())
```

## CLI Usage

```bash
qaegis encrypt secrets.env -o secrets.env.enc.json --tier QUANTUM_CRITICAL
qaegis decrypt secrets.env.enc.json -o secrets.env.restored
```
