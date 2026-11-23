"""Module 5: Quantum-Noise Evolution Engine (Harvester, MCTS, Mutator, Ollama Bridge)."""

from __future__ import annotations

from qaegis.modules.quantum_entropy.harvester import (
    QuantumDistributionBatch,
    QuantumDistributionHarvester,
    QuantumEntropyPool,
)
from qaegis.modules.quantum_entropy.ollama_bridge import (
    OllamaGenerationResult,
    OllamaQuantumBridge,
    QuantumBranchSamplingParams,
)
from qaegis.modules.quantum_entropy.sampler import (
    EvolutionResult,
    QuantumEvolutionaryMutator,
    QuantumLogitSampler,
    QuantumMCTS,
    TokenSampleResult,
)
from qaegis.modules.quantum_entropy.service import QuantumEntropyService

__all__ = [
    "EvolutionResult",
    "OllamaGenerationResult",
    "OllamaQuantumBridge",
    "QuantumBranchSamplingParams",
    "QuantumDistributionBatch",
    "QuantumDistributionHarvester",
    "QuantumEntropyPool",
    "QuantumEntropyService",
    "QuantumEvolutionaryMutator",
    "QuantumLogitSampler",
    "QuantumMCTS",
    "TokenSampleResult",
]
