"""Event-bus integrated Quantum-Noise Evolution Engine Service."""

from __future__ import annotations

from typing import Any

from qaegis.core.bus import EventBus, EventEnvelope
from qaegis.core.config import QuantumEntropyConfig
from qaegis.core.telemetry import QAegisMetrics, get_logger
from qaegis.modules.quantum_entropy.harvester import (
    QuantumDistributionBatch,
    QuantumDistributionHarvester,
    QuantumEntropyPool,
)
from qaegis.modules.quantum_entropy.ollama_bridge import OllamaQuantumBridge
from qaegis.modules.quantum_entropy.sampler import QuantumLogitSampler, TokenSampleResult

logger = get_logger(__name__)


class QuantumEntropyService:
    """Provides batched quantum probability distributions and sampling RPCs over the EventBus."""

    def __init__(
        self,
        bus: EventBus,
        config: QuantumEntropyConfig | None = None,
        metrics: QAegisMetrics | None = None,
    ) -> None:
        self._bus = bus
        self._config = config or QuantumEntropyConfig()
        self._metrics = metrics or QAegisMetrics()
        self._harvester = QuantumDistributionHarvester(config=self._config, metrics=self._metrics)
        self._ollama = OllamaQuantumBridge(config=self._config)
        self._pool: QuantumEntropyPool | None = None

    @property
    def harvester(self) -> QuantumDistributionHarvester:
        return self._harvester

    @property
    def ollama(self) -> OllamaQuantumBridge:
        return self._ollama

    async def start(self) -> None:
        """Harvest an initial verified quantum entropy pool and register EventBus responders."""
        _batch, self._pool = await self._harvester.harvest_batch()
        self._bus.register_responder("entropy.harvest", self._handle_harvest_rpc)
        self._bus.register_responder("entropy.sample_logits", self._handle_sample_logits_rpc)
        logger.info("quantum_entropy_service_started", qubits=self._config.harvester_qubits)

    async def harvest(
        self,
        num_qubits: int | None = None,
        shots: int | None = None,
        noise_rate: float = 0.01,
    ) -> tuple[QuantumDistributionBatch, QuantumEntropyPool]:
        """Harvest a fresh entangled quantum distribution and refresh the active pool."""
        batch, pool = await self._harvester.harvest_batch(
            num_qubits=num_qubits,
            shots=shots,
            noise_rate=noise_rate,
        )
        self._pool = pool
        await self._bus.publish(
            topic="entropy.batch_harvested",
            source="modules.quantum_entropy",
            payload={
                "num_qubits": batch.num_qubits,
                "shots": batch.shots,
                "shannon_entropy_bits": batch.shannon_entropy_bits,
                "pool_bytes": batch.pool_bytes,
            },
        )
        return batch, pool

    async def sample_logits(
        self,
        logits: list[float],
        temperature: float = 0.8,
        top_k: int = 40,
        top_p: float = 0.9,
    ) -> TokenSampleResult:
        """Sample a token index using the active verified quantum entropy pool."""
        if self._pool is None:
            _batch, self._pool = await self._harvester.harvest_batch()
        sampler = QuantumLogitSampler(self._pool)
        return sampler.sample_token(
            logits=logits, temperature=temperature, top_k=top_k, top_p=top_p
        )

    async def _handle_harvest_rpc(self, envelope: EventEnvelope) -> dict[str, Any]:
        p = envelope.payload
        batch, _pool = await self.harvest(
            num_qubits=int(p["num_qubits"]) if "num_qubits" in p else None,
            shots=int(p["shots"]) if "shots" in p else None,
            noise_rate=float(p.get("noise_rate", 0.01)),
        )
        return batch.model_dump(mode="json")

    async def _handle_sample_logits_rpc(self, envelope: EventEnvelope) -> dict[str, Any]:
        p = envelope.payload
        res = await self.sample_logits(
            logits=[float(v) for v in p["logits"]],
            temperature=float(p.get("temperature", 0.8)),
            top_k=int(p.get("top_k", 40)),
            top_p=float(p.get("top_p", 0.9)),
        )
        return res.model_dump(mode="json")
