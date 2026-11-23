"""Multi-source Quantum Random Number Generator (HTTP QRNG + Qiskit H-gate + OS CSPRNG)."""

from __future__ import annotations

import hashlib
import math
import os
from abc import ABC, abstractmethod

import httpx
from pydantic import BaseModel
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator

from qaegis.core.config import RealityStampConfig
from qaegis.core.telemetry import QAegisMetrics, get_logger
from qaegis.modules.reality_stamp.nist_tests import EntropyHealthReport, validate_entropy_batch

logger = get_logger(__name__)


class EntropyHealthError(RuntimeError):
    """Raised when harvested quantum entropy fails NIST SP 800-22 / SP 800-90B checks."""

    def __init__(self, message: str, report: EntropyHealthReport) -> None:
        super().__init__(message)
        self.report = report


class HarvestedEntropy(BaseModel):
    """Verified quantum-mixed entropy batch with provenance and NIST health report."""

    raw_hex: str
    num_bytes: int
    sources: list[str]
    health_report: EntropyHealthReport

    @property
    def raw_bytes(self) -> bytes:
        return bytes.fromhex(self.raw_hex)


class EntropySource(ABC):
    """Abstract base class for a hardware, network, or quantum-circuit entropy provider."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this entropy source."""

    @abstractmethod
    async def fetch_bytes(self, num_bytes: int) -> bytes:
        """Generate or retrieve `num_bytes` of raw entropy."""


class OsCsprngSource(EntropySource):
    """Linux kernel CSPRNG (`os.urandom` / `getrandom(2)`)."""

    @property
    def name(self) -> str:
        return "linux_csprng"

    async def fetch_bytes(self, num_bytes: int) -> bytes:
        return os.urandom(num_bytes)


class QiskitHadamardQrngSource(EntropySource):
    """Local Qiskit quantum circuit entropy source using Hadamard superposition measurement."""

    def __init__(self, num_qubits: int = 8) -> None:
        if num_qubits < 4 or num_qubits > 16:
            raise ValueError("num_qubits must be between 4 and 16")
        self._num_qubits = num_qubits
        self._simulator = AerSimulator()
        qc = QuantumCircuit(num_qubits, num_qubits)
        for idx in range(num_qubits):
            qc.h(idx)
        qc.measure(range(num_qubits), range(num_qubits))
        self._compiled_circuit = transpile(qc, self._simulator)

    @property
    def name(self) -> str:
        return f"qiskit_hadamard_{self._num_qubits}q"

    async def fetch_bytes(self, num_bytes: int) -> bytes:
        total_bits = num_bytes * 8
        shots = math.ceil(total_bits / self._num_qubits)
        job = self._simulator.run(self._compiled_circuit, shots=shots, memory=True)
        bitstrings: list[str] = list(job.result().get_memory())
        joined = "".join(bitstrings)[:total_bits]
        out = bytearray(num_bytes)
        for i in range(num_bytes):
            out[i] = int(joined[i * 8 : (i + 1) * 8], 2)
        return bytes(out)


class HttpQrngSource(EntropySource):
    """Network QRNG source supporting ANU-style JSON responses or raw binary endpoints."""

    def __init__(self, endpoint_url: str, timeout_s: float = 3.0) -> None:
        self._url = endpoint_url
        self._timeout_s = timeout_s

    @property
    def name(self) -> str:
        return f"http_qrng:{self._url}"

    async def fetch_bytes(self, num_bytes: int) -> bytes:
        async with httpx.AsyncClient(timeout=self._timeout_s) as client:
            resp = await client.get(
                self._url,
                params={"length": num_bytes, "type": "uint8"},
            )
            resp.raise_for_status()
            content_type = resp.headers.get("content-type", "")
            if "application/json" in content_type:
                body = resp.json()
                data = body.get("data")
                if isinstance(data, list) and len(data) >= num_bytes:
                    if all(isinstance(v, int) for v in data[:num_bytes]):
                        return bytes(int(v) & 0xFF for v in data[:num_bytes])
                    if all(isinstance(v, str) for v in data):
                        raw = bytes.fromhex("".join(str(v) for v in data))
                        if len(raw) >= num_bytes:
                            return raw[:num_bytes]
                raise ValueError("Unexpected JSON format from HTTP QRNG endpoint")
            raw_bytes = resp.content
            if len(raw_bytes) < num_bytes:
                raise ValueError(
                    f"HTTP QRNG returned {len(raw_bytes)} bytes, expected at least {num_bytes}"
                )
            return raw_bytes[:num_bytes]


def xor_mix_streams(streams: list[bytes]) -> bytes:
    """Cryptographically XOR-mix multiple equal-length byte streams.

    Security guarantee: the output is computationally indistinguishable from uniform random
    provided at least one independent input stream is uniform random.
    """
    if not streams:
        raise ValueError("At least one entropy stream is required for XOR mixing")
    length = len(streams[0])
    if length == 0:
        raise ValueError("Entropy streams cannot be empty")
    for s in streams[1:]:
        if len(s) != length:
            raise ValueError("All entropy streams must have identical byte lengths")
    mixed = bytearray(streams[0])
    for stream in streams[1:]:
        for i in range(length):
            mixed[i] ^= stream[i]
    return bytes(mixed)


class MultiSourceQrng:
    """Combines multiple QRNG/CSPRNG sources via XOR mixing and enforces NIST validation."""

    def __init__(
        self,
        config: RealityStampConfig | None = None,
        sources: list[EntropySource] | None = None,
        metrics: QAegisMetrics | None = None,
    ) -> None:
        self._config = config or RealityStampConfig()
        self._metrics = metrics or QAegisMetrics()
        if sources is not None:
            self._sources = list(sources)
        else:
            self._sources = [
                QiskitHadamardQrngSource(num_qubits=self._config.qiskit_qrng_qubits),
                OsCsprngSource(),
            ]
            if self._config.qrng_http_url:
                self._sources.insert(
                    0,
                    HttpQrngSource(
                        endpoint_url=self._config.qrng_http_url,
                        timeout_s=self._config.qrng_http_timeout_s,
                    ),
                )

    async def harvest(
        self,
        num_bytes: int | None = None,
        max_retries: int = 3,
    ) -> HarvestedEntropy:
        """Harvest, XOR-mix, and validate an entropy batch against NIST SP 800-22 & 800-90B."""
        requested = num_bytes or self._config.entropy_sample_bytes
        # Ensure we collect at least 64 bytes (512 bits) for full NIST validation
        sample_size = max(requested, 64)

        last_report: EntropyHealthReport | None = None
        for attempt in range(1, max_retries + 1):
            streams: list[bytes] = []
            used_sources: list[str] = []
            for src in self._sources:
                try:
                    chunk = await src.fetch_bytes(sample_size)
                    streams.append(chunk)
                    used_sources.append(src.name)
                except Exception as exc:
                    logger.warning(
                        "entropy_source_unavailable",
                        source=src.name,
                        error=str(exc),
                    )
            if not streams:
                raise RuntimeError("No entropy sources succeeded during QRNG harvest")

            mixed = xor_mix_streams(streams)
            report = validate_entropy_batch(
                mixed,
                strict=self._config.strict_nist_checks,
            )
            self._metrics.qrng_health_checks.labels(passed=str(report.passed).lower()).inc()
            if report.passed:
                for src_name in used_sources:
                    self._metrics.entropy_bytes_harvested.labels(source=src_name).inc(requested)
                output_bytes = mixed[:requested]
                return HarvestedEntropy(
                    raw_hex=output_bytes.hex(),
                    num_bytes=len(output_bytes),
                    sources=used_sources,
                    health_report=report,
                )

            last_report = report
            logger.warning(
                "qrng_batch_failed_nist_validation",
                attempt=attempt,
                sources=used_sources,
                digest=hashlib.sha256(mixed).hexdigest()[:16],
            )

        assert last_report is not None
        raise EntropyHealthError(
            "Harvested entropy failed NIST SP 800-22 / SP 800-90B validation across all retries",
            report=last_report,
        )
