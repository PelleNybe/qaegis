"""Module 1: Proof of Reality (Edge-AI + QRNG + NIST PQC Signatures + Merkle Log + Gossip)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from qaegis.modules.reality_stamp.gossip import (
    EquivocationAlert,
    GossipVerificationOutcome,
    MerkleGossipEnvelope,
    MerkleGossipNode,
)
from qaegis.modules.reality_stamp.merkle import (
    MerkleProof,
    MerkleProofStep,
    MerkleTree,
    hash_leaf,
    verify_merkle_proof,
)
from qaegis.modules.reality_stamp.signer import (
    ArtifactSignatureBundle,
    ArtifactVerificationResult,
    RealityPayload,
    RealitySigner,
    RealityStamp,
    StampVerificationResult,
    sign_artifact_bytes,
    sign_artifact_file,
    verify_artifact_bytes,
    verify_artifact_file,
    verify_reality_stamp,
)

if TYPE_CHECKING:
    from qaegis.modules.reality_stamp.nist_tests import (
        EntropyHealthReport,
        StatisticalTestResult,
        adaptive_proportion_test,
        block_frequency_test,
        frequency_monobit_test,
        longest_run_of_ones_test,
        repetition_count_test,
        runs_test,
        validate_entropy_batch,
    )
    from qaegis.modules.reality_stamp.qrng import (
        EntropyHealthError,
        EntropySource,
        HarvestedEntropy,
        HttpQrngSource,
        MultiSourceQrng,
        OsCsprngSource,
        QiskitHadamardQrngSource,
        xor_mix_streams,
    )
    from qaegis.modules.reality_stamp.service import RealityStampService

__all__ = [
    "ArtifactSignatureBundle",
    "ArtifactVerificationResult",
    "EntropyHealthError",
    "EntropyHealthReport",
    "EntropySource",
    "EquivocationAlert",
    "GossipVerificationOutcome",
    "HarvestedEntropy",
    "HttpQrngSource",
    "MerkleGossipEnvelope",
    "MerkleGossipNode",
    "MerkleProof",
    "MerkleProofStep",
    "MerkleTree",
    "MultiSourceQrng",
    "OsCsprngSource",
    "QiskitHadamardQrngSource",
    "RealityPayload",
    "RealitySigner",
    "RealityStamp",
    "RealityStampService",
    "StampVerificationResult",
    "StatisticalTestResult",
    "adaptive_proportion_test",
    "block_frequency_test",
    "frequency_monobit_test",
    "hash_leaf",
    "longest_run_of_ones_test",
    "repetition_count_test",
    "runs_test",
    "sign_artifact_bytes",
    "sign_artifact_file",
    "validate_entropy_batch",
    "verify_artifact_bytes",
    "verify_artifact_file",
    "verify_merkle_proof",
    "verify_reality_stamp",
    "xor_mix_streams",
]

_NIST_EXPORTS = frozenset(
    {
        "EntropyHealthReport",
        "StatisticalTestResult",
        "adaptive_proportion_test",
        "block_frequency_test",
        "frequency_monobit_test",
        "longest_run_of_ones_test",
        "repetition_count_test",
        "runs_test",
        "validate_entropy_batch",
    }
)
_QRNG_EXPORTS = frozenset(
    {
        "EntropyHealthError",
        "EntropySource",
        "HarvestedEntropy",
        "HttpQrngSource",
        "MultiSourceQrng",
        "OsCsprngSource",
        "QiskitHadamardQrngSource",
        "xor_mix_streams",
    }
)


def __getattr__(name: str) -> Any:
    if name in _NIST_EXPORTS:
        from qaegis.modules.reality_stamp import nist_tests

        return getattr(nist_tests, name)
    if name in _QRNG_EXPORTS:
        from qaegis.modules.reality_stamp import qrng

        return getattr(qrng, name)
    if name == "RealityStampService":
        from qaegis.modules.reality_stamp.service import RealityStampService

        return RealityStampService
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
