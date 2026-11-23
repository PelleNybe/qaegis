# Developer Plugin Guide

Q-Aegis is engineered around clean Python ABCs, Pydantic v2 contracts, and an asynchronous EventBus so external contributors can add new quantum backends, entropy sources, PQC schemes, or Edge-AI adapters without modifying core internals.

---

## 1. Implementing a Custom Quantum Backend

Subclass `qaegis.modules.quantum_dreamer.solvers.QuantumBackend` to integrate AWS Braket, IonQ, Rigetti, or custom HPC tensor-network simulators:

```python
from qaegis.modules.qubit_compiler.qubo_mapper import IsingHamiltonian
from qaegis.modules.quantum_dreamer.solvers import QuantumBackend, build_qaoa_circuit


class CustomQpuBackend(QuantumBackend):
    @property
    def name(self) -> str:
        return "custom_qpu_v1"

    def sample_distribution(
        self,
        hamiltonian: IsingHamiltonian,
        gammas: list[float],
        betas: list[float],
        shots: int,
    ) -> dict[str, float]:
        qc = build_qaoa_circuit(hamiltonian, gammas, betas, measure=True)
        # Submit `qc` (or qiskit.qasm3.dumps(qc)) to your target hardware SDK
        # and normalize measurement counts to {bitstring_x0_to_xn: probability}.
        counts = submit_to_custom_sdk(qc, shots=shots)
        total = float(sum(counts.values()))
        return {bitstring: count / total for bitstring, count in counts.items()}
```

Inject your backend directly into `QaoaSolver(backend=CustomQpuBackend())` or `QuantumDreamerService(..., backend=CustomQpuBackend())`.

---

## 2. Implementing a Hardware QRNG Entropy Source

To attach a USB quantum RNG device (e.g., ID Quantique Quantis or PCIe optical QRNG), subclass `qaegis.modules.reality_stamp.qrng.EntropySource`:

```python
from pathlib import Path
from qaegis.modules.reality_stamp.qrng import EntropySource, MultiSourceQrng, OsCsprngSource


class HardwareDeviceQrngSource(EntropySource):
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

qrng = MultiSourceQrng(sources=[HardwareDeviceQrngSource(), OsCsprngSource()])
```

Every batch harvested from your plugin is automatically XOR-mixed and gated by NIST SP 800-22 & SP 800-90B validation.

---

## 3. Writing an EventBus Edge-AI Plugin Service

Every module communicates using validated `EventEnvelope` messages. Follow this template for a new Edge-AI sensor or inference plugin:

```python
from qaegis.core.bus import EventBus, EventEnvelope


class CustomPerceptionPlugin:
    def __init__(self, bus: EventBus) -> None:
        self._bus = bus

    async def publish_detection(self, sensor_id: str, label: str, confidence: float) -> None:
        await self._bus.publish(
            topic="perception.custom_radar",
            source="plugins.custom_radar",
            payload={
                "sensor_id": sensor_id,
                "label": label,
                "confidence": confidence,
                "metadata": {"modality": "mmwave_radar"},
            },
        )
```

Because `RealityStampService` subscribes to `perception.*`, publishing onto `perception.custom_radar` automatically triggers QRNG noncing, ML-DSA-65 signing, and Merkle Tree anchoring with zero extra glue code.

---

## 4. Verification Checklist for Plugins

Before opening a pull request:

```bash
ruff check src tests
ruff format --check src tests
mypy --strict src
pytest -v
```
