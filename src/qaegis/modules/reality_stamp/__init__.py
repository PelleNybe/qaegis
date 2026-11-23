"""Module 1: Proof of Reality (Edge-AI + QRNG + NIST PQC Signatures + Merkle Log)."""

from __future__ import annotations

from qaegis.modules.reality_stamp.merkle import (
    MerkleProof,
    MerkleProofStep,
    MerkleTree,
    hash_leaf,
    verify_merkle_proof,
)
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
from qaegis.modules.reality_stamp.signer import (
    RealityPayload,
    RealitySigner,
    RealityStamp,
    StampVerificationResult,
    verify_reality_stamp,
)

__all__ = [
    "EntropyHealthError",
    "EntropyHealthReport",
    "EntropySource",
    "HarvestedEntropy",
    "HttpQrngSource",
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
    "validate_entropy_batch",
    "verify_merkle_proof",
    "verify_reality_stamp",
    "xor_mix_streams",
]
