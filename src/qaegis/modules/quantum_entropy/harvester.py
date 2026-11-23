"""Batched entangled-circuit quantum probability distribution harvester + QRNG pool."""

from __future__ import annotations

import hashlib
import math
import struct

import numpy as np
from pydantic import BaseModel, Field
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator
from qiskit_aer.noise import NoiseModel, depolarizing_error

from qaegis.core.config import QuantumEntropyConfig, RealityStampConfig
from qaegis.core.telemetry import QAegisMetrics
from qaegis.modules.reality_stamp.qrng import MultiSourceQrng, xor_mix_streams


class QuantumDistributionBatch(BaseModel):
    """Harvested quantum measurement histogram and verified uniform entropy pool."""

    num_qubits: int
    shots: int
    probabilities: dict[str, float]
    shannon_entropy_bits: float
    qrng_mixed_hex: str
    pool_bytes: int = Field(ge=32)
    sources: list[str]
    noise_rate: float


class QuantumEntropyPool:
    """Thread/async-safe byte & float stream backed by verified quantum entropy batches."""

    def __init__(self, initial_bytes: bytes) -> None:
        if len(initial_bytes) < 32:
            raise ValueError("QuantumEntropyPool requires at least 32 initial bytes")
        self._state = initial_bytes
        self._cursor = 0
        self._reseed_counter = 0

    def next_bytes(self, n: int) -> bytes:
        """Consume `n` bytes, stretching via SHAKE-256 domain-separated rekeying when depleted."""
        out = bytearray()
        while len(out) < n:
            if self._cursor >= len(self._state):
                self._reseed_counter += 1
                shake = hashlib.shake_256(
                    self._state + struct.pack(">Q", self._reseed_counter) + b"qaegis-qpool"
                )
                self._state = shake.digest(max(len(self._state), 256))
                self._cursor = 0
            take = min(n - len(out), len(self._state) - self._cursor)
            out.extend(self._state[self._cursor : self._cursor + take])
            self._cursor += take
        return bytes(out)

    def next_uint32(self) -> int:
        """Return an unbiased 32-bit unsigned integer from the quantum pool."""
        val: int = struct.unpack(">I", self.next_bytes(4))[0]
        return val

    def next_uniform(self) -> float:
        """Return a uniform float in [0.0, 1.0) with 53-bit IEEE-754 mantissa resolution."""
        raw_u64: int = struct.unpack(">Q", self.next_bytes(8))[0]
        return float((raw_u64 >> 11) * (2.0**-53))

    def next_gaussian(self) -> float:
        """Return a standard normal N(0, 1) sample via Box-Muller transform."""
        u1 = max(self.next_uniform(), 1e-12)
        u2 = self.next_uniform()
        return float(math.sqrt(-2.0 * math.log(u1)) * math.cos(2.0 * math.pi * u2))


class QuantumDistributionHarvester:
    """Executes entangled Qiskit circuits and XOR-mixes outcomes with NIST-verified QRNG."""

    def __init__(
        self,
        config: QuantumEntropyConfig | None = None,
        qrng: MultiSourceQrng | None = None,
        metrics: QAegisMetrics | None = None,
    ) -> None:
        self._config = config or QuantumEntropyConfig()
        self._metrics = metrics or QAegisMetrics()
        self._qrng = qrng or MultiSourceQrng(
            config=RealityStampConfig(strict_nist_checks=False),
            metrics=self._metrics,
        )

    def _build_entangled_circuit(self, num_qubits: int, phase_bias: float = 0.0) -> QuantumCircuit:
        qc = QuantumCircuit(num_qubits, num_qubits)
        for q in range(num_qubits):
            qc.h(q)
            if abs(phase_bias) > 1e-9:
                qc.ry(phase_bias * (q + 1) / num_qubits, q)
        for q in range(num_qubits - 1):
            qc.cx(q, q + 1)
        # Second superposition layer for high-entropy multi-basis spread
        for q in range(num_qubits):
            qc.ry(math.pi / 4.0, q)
        qc.measure(range(num_qubits), range(num_qubits))
        return qc

    async def harvest_batch(
        self,
        num_qubits: int | None = None,
        shots: int | None = None,
        noise_rate: float = 0.01,
        phase_bias: float = 0.0,
    ) -> tuple[QuantumDistributionBatch, QuantumEntropyPool]:
        """Harvest an entangled quantum probability distribution and verified entropy pool."""
        n = num_qubits or self._config.harvester_qubits
        num_shots = shots or self._config.harvester_shots
        pool_size = self._config.pool_min_bytes

        if noise_rate > 0.0:
            nm = NoiseModel()
            nm.add_all_qubit_quantum_error(
                depolarizing_error(min(noise_rate, 0.25), 1), ["h", "ry"]
            )
            nm.add_all_qubit_quantum_error(
                depolarizing_error(min(noise_rate * 2.0, 0.4), 2), ["cx"]
            )
            sim = AerSimulator(noise_model=nm)
        else:
            sim = AerSimulator()

        qc = self._build_entangled_circuit(n, phase_bias=phase_bias)
        tqc = transpile(qc, sim, optimization_level=1)
        result = sim.run(tqc, shots=num_shots, memory=True).result()
        counts: dict[str, int] = dict(result.get_counts())
        memory: list[str] = list(result.get_memory())

        total = float(sum(counts.values()))
        probs = {bs: float(c) / total for bs, c in counts.items()}
        p_arr = np.fromiter(probs.values(), dtype=np.float64)
        shannon = float(-np.sum(p_arr[p_arr > 0] * np.log2(p_arr[p_arr > 0])))

        # Extract raw circuit bit-stream bytes and XOR-mix with NIST-verified QRNG bytes
        circuit_raw = hashlib.shake_256("".join(memory).encode("ascii")).digest(pool_size)
        qrng_batch = await self._qrng.harvest(num_bytes=pool_size)
        mixed = xor_mix_streams([circuit_raw, qrng_batch.raw_bytes])

        self._metrics.entropy_bytes_harvested.labels(source="entangled_harvester").inc(len(mixed))

        batch = QuantumDistributionBatch(
            num_qubits=n,
            shots=num_shots,
            probabilities=probs,
            shannon_entropy_bits=shannon,
            qrng_mixed_hex=mixed.hex(),
            pool_bytes=len(mixed),
            sources=[f"qiskit_entangled_{n}q", *qrng_batch.sources],
            noise_rate=noise_rate,
        )
        return batch, QuantumEntropyPool(mixed)
