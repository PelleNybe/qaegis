# Developer SDK & Plugin Guide

Q-Aegis is architected for both **zero-boilerplate application embedding** via `QAegisClient` and **clean extensibility** via strictly typed protocols, ABCs, and Pydantic v2 contracts.

---

## 1. Embedding Q-Aegis with `QAegisClient` (`qaegis.sdk`)

For backend services, FastAPI microservices, robotics nodes, or ML pipelines, `QAegisClient` manages the PQC identity, SQLite WAL database, `EventBus`, and all five subsystems behind an async context manager:

```python
import asyncio
from pathlib import Path
from qaegis import QAegisClient
from qaegis.modules.chameleon_fw.features import ThreatTier


async def main() -> None:
    async with QAegisClient("./app_qaegis_state") as client:
        # 1. Perception provenance stamp + leaf-bound Merkle verification
        stamp = await client.stamp("cam-01", "forklift_detected", confidence=0.97)
        assert client.verify_stamp(stamp).valid

        # 2. Post-quantum detached signing for ML weights or release artifacts
        model_file = Path("weights.bin")
        model_file.write_bytes(b"onnx-weights-payload")
        sig_bundle = await client.sign_file(model_file)
        assert client.verify_file(model_file, sig_bundle).valid

        # 3. Direct or AI-adaptive hybrid post-quantum encryption
        envelope = client.encrypt(b"database-master-key", tier=ThreatTier.QUANTUM_CRITICAL)
        recovered = client.decrypt(envelope, use_local_keyring=True)
        assert recovered == b"database-master-key"

        # 4. Quantum-verified randomness & QAOA combinatorial solver
        rand = await client.random_bytes(32)
        sol = await client.solve_maxcut(4, [(0, 1, 1.0), (1, 2, 1.0), (2, 3, 1.0), (3, 0, 1.0)])
        print(len(rand), sol.optimal_bitstring, sol.approximation_ratio)


asyncio.run(main())
```

---

## 2. Registering a Custom Quantum Backend (`QuantumBackendRegistry`)

Subclass `QuantumBackend` and register your factory on the global `QuantumBackendRegistry` so `QaoaSolver`, `qaegis dream --backend <name>`, and the Web Mission-Control Dashboard automatically discover it:

```python
from qaegis.core.config import QuantumDreamerConfig
from qaegis.modules.qubit_compiler.qubo_mapper import IsingHamiltonian
from qaegis.modules.quantum_dreamer.solvers import (
    QuantumBackend,
    build_qaoa_circuit,
    get_backend_registry,
)


class CustomTensorNetworkBackend(QuantumBackend):
    @property
    def name(self) -> str:
        return "custom_tensor_net"

    def sample_distribution(
        self,
        hamiltonian: IsingHamiltonian,
        gammas: list[float],
        betas: list[float],
        shots: int,
    ) -> dict[str, float]:
        qc = build_qaoa_circuit(hamiltonian, gammas, betas, measure=True)
        # Execute `qc` (or qiskit.qasm3.dumps(qc)) on your target runtime
        # and return canonical {bitstring_x0_to_xn: probability}.
        counts = {"0101": shots // 2, "1010": shots - (shots // 2)}
        total = float(sum(counts.values()))
        return {bs: c / total for bs, c in counts.items()}


get_backend_registry().register(
    "custom_tensor_net",
    lambda _cfg: CustomTensorNetworkBackend(),
)
```

---

## 3. Implementing a Hardware QRNG Entropy Source (`EntropySource`)

Attach a PCIe or USB optical quantum RNG (e.g., ID Quantique Quantis) by subclassing `EntropySource`:

```python
from pathlib import Path
from qaegis.modules.reality_stamp.qrng import EntropySource, MultiSourceQrng, OsCsprngSource


class OpticalUsbQrngSource(EntropySource):
    def __init__(self, device_path: Path = Path("/dev/qrandom0")) -> None:
        self._device_path = device_path

    @property
    def name(self) -> str:
        return f"hw_qrng:{self._device_path}"

    async def fetch_bytes(self, num_bytes: int) -> bytes:
        with self._device_path.open("rb") as handle:
            data = handle.read(num_bytes)
        if len(data) != num_bytes:
            raise OSError(f"Short read from {self._device_path}")
        return data


qrng = MultiSourceQrng(sources=[OpticalUsbQrngSource(), OsCsprngSource()])
```

Every harvested batch is automatically XOR-mixed and gated by NIST SP 800-22 & SP 800-90B continuous health tests.

---

## 4. Implementing a Custom Hardware Key Sealer (`HardwareSealer`)

Implement the `HardwareSealer` protocol (`qaegis.core.hardware_seal`) to seal node PQC keys into Cloud KMS, Apple Secure Enclave, or YubiHSM:

```python
from qaegis.core.hardware_seal import HardwareSealer, SealedKeyBlob


class CustomKmsSealer(HardwareSealer):
    @property
    def backend_name(self) -> str:
        return "custom_kms"

    def is_available(self) -> bool:
        return True

    def seal(self, plaintext: bytes, associated_data: bytes = b"") -> SealedKeyBlob:
        ...

    def unseal(self, blob: SealedKeyBlob, associated_data: bytes | None = None) -> bytes:
        ...
```

---

## 5. Writing an EventBus Edge-AI Plugin

Because `RealityStampService` subscribes to `perception.*`, publishing any validated `EventEnvelope` onto `perception.<modality>` automatically triggers QRNG noncing, `ML-DSA-65` signing, Merkle anchoring, and live SSE streaming to the Web Mission-Control Dashboard:

```python
from qaegis.core.bus import EventBus


class RadarPerceptionPlugin:
    def __init__(self, bus: EventBus) -> None:
        self._bus = bus

    async def publish_detection(self, sensor_id: str, label: str, confidence: float) -> None:
        await self._bus.publish(
            topic="perception.mmwave_radar",
            source="plugins.radar",
            payload={
                "sensor_id": sensor_id,
                "label": label,
                "confidence": confidence,
                "metadata": {"modality": "4d_imaging_radar"},
            },
        )
```

---

## 6. Contributor Quality Gate Checklist

```bash
ruff format --check src tests benchmarks
ruff check src tests benchmarks
ruff check --select S src
mypy --strict src
pytest --cov=qaegis --cov-fail-under=90
mkdocs build --strict
```
