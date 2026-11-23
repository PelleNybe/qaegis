"""Real NIST SP 800-22 and SP 800-90B statistical entropy validation tests."""

from __future__ import annotations

import math

import numpy as np
from numpy.typing import NDArray
from pydantic import BaseModel
from scipy.special import erfc, gammaincc
from scipy.stats import binom


class StatisticalTestResult(BaseModel):
    """Outcome of a single NIST statistical or continuous health test."""

    name: str
    passed: bool
    statistic: float
    p_value: float | None = None
    threshold: float
    detail: str = ""


class EntropyHealthReport(BaseModel):
    """Aggregated NIST SP 800-22 & SP 800-90B validation report for an entropy batch."""

    num_bytes: int
    num_bits: int
    passed: bool
    tests: list[StatisticalTestResult]


def bytes_to_bits(data: bytes) -> NDArray[np.uint8]:
    """Unpack raw bytes into a 1D uint8 array of individual bits (MSB first)."""
    arr = np.frombuffer(data, dtype=np.uint8)
    bits: NDArray[np.uint8] = np.unpackbits(arr)
    return bits


def frequency_monobit_test(
    bits: NDArray[np.uint8],
    alpha: float = 0.01,
) -> StatisticalTestResult:
    """NIST SP 800-22 Section 2.1: Frequency (Monobit) Test."""
    n = int(bits.size)
    if n < 100:
        raise ValueError("Frequency (Monobit) test requires at least 100 bits")
    signed = bits.astype(np.int64) * 2 - 1
    s_obs = abs(float(np.sum(signed))) / math.sqrt(n)
    p_value = float(erfc(s_obs / math.sqrt(2.0)))
    return StatisticalTestResult(
        name="nist_800_22_frequency_monobit",
        passed=p_value >= alpha,
        statistic=s_obs,
        p_value=p_value,
        threshold=alpha,
        detail=f"ones_ratio={float(np.mean(bits)):.4f}",
    )


def block_frequency_test(
    bits: NDArray[np.uint8],
    block_size: int = 16,
    alpha: float = 0.01,
) -> StatisticalTestResult:
    """NIST SP 800-22 Section 2.2: Frequency Test within a Block."""
    n = int(bits.size)
    num_blocks = n // block_size
    if num_blocks < 1:
        raise ValueError(f"Insufficient bits ({n}) for block_size={block_size}")
    trimmed = bits[: num_blocks * block_size].reshape((num_blocks, block_size))
    proportions = np.mean(trimmed, axis=1)
    chi_sq = float(4.0 * block_size * np.sum((proportions - 0.5) ** 2))
    p_value = float(gammaincc(num_blocks / 2.0, chi_sq / 2.0))
    return StatisticalTestResult(
        name="nist_800_22_block_frequency",
        passed=p_value >= alpha,
        statistic=chi_sq,
        p_value=p_value,
        threshold=alpha,
        detail=f"blocks={num_blocks}, M={block_size}",
    )


def runs_test(
    bits: NDArray[np.uint8],
    alpha: float = 0.01,
) -> StatisticalTestResult:
    """NIST SP 800-22 Section 2.3: Runs Test."""
    n = int(bits.size)
    if n < 100:
        raise ValueError("Runs test requires at least 100 bits")
    pi = float(np.mean(bits))
    tau = 2.0 / math.sqrt(n)
    if abs(pi - 0.5) >= tau:
        return StatisticalTestResult(
            name="nist_800_22_runs",
            passed=False,
            statistic=abs(pi - 0.5),
            p_value=0.0,
            threshold=alpha,
            detail=f"prerequisite_failed: |pi-0.5|={abs(pi - 0.5):.4f} >= tau={tau:.4f}",
        )
    v_obs = float(1 + np.sum(bits[:-1] != bits[1:]))
    denom = 2.0 * math.sqrt(2.0 * n) * pi * (1.0 - pi)
    p_value = float(erfc(abs(v_obs - 2.0 * n * pi * (1.0 - pi)) / denom))
    return StatisticalTestResult(
        name="nist_800_22_runs",
        passed=p_value >= alpha,
        statistic=v_obs,
        p_value=p_value,
        threshold=alpha,
        detail=f"runs={int(v_obs)}, pi={pi:.4f}",
    )


def longest_run_of_ones_test(
    bits: NDArray[np.uint8],
    alpha: float = 0.01,
) -> StatisticalTestResult:
    """NIST SP 800-22 Section 2.4: Test for the Longest Run of Ones in a Block."""
    n = int(bits.size)
    if n < 128:
        raise ValueError("Longest Run of Ones test requires at least 128 bits")

    if n < 6272:
        m = 8
        k = 3
        v_min = 1
        probs = np.array([0.2148, 0.3672, 0.2305, 0.1875], dtype=np.float64)
    elif n < 750_000:
        m = 128
        k = 5
        v_min = 4
        probs = np.array([0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124], dtype=np.float64)
    else:
        m = 10_000
        k = 6
        v_min = 10
        probs = np.array(
            [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727],
            dtype=np.float64,
        )

    num_blocks = n // m
    counts = np.zeros(k + 1, dtype=np.float64)
    blocks = bits[: num_blocks * m].reshape((num_blocks, m))

    for blk in blocks:
        max_run = 0
        curr_run = 0
        for bit in blk:
            if bit == 1:
                curr_run += 1
                if curr_run > max_run:
                    max_run = curr_run
            else:
                curr_run = 0
        if max_run <= v_min:
            counts[0] += 1.0
        elif max_run >= v_min + k:
            counts[k] += 1.0
        else:
            counts[max_run - v_min] += 1.0

    expected = num_blocks * probs
    chi_sq = float(np.sum(((counts - expected) ** 2) / expected))
    p_value = float(gammaincc(k / 2.0, chi_sq / 2.0))
    return StatisticalTestResult(
        name="nist_800_22_longest_run_of_ones",
        passed=p_value >= alpha,
        statistic=chi_sq,
        p_value=p_value,
        threshold=alpha,
        detail=f"blocks={num_blocks}, M={m}",
    )


def repetition_count_test(
    data: bytes,
    min_entropy_h: float = 4.0,
    alpha: float = 2.0**-20,
) -> StatisticalTestResult:
    """NIST SP 800-90B Section 4.4.1: Repetition Count Test (byte-level symbols)."""
    if len(data) < 2:
        raise ValueError("Repetition Count Test requires at least 2 bytes")
    if min_entropy_h <= 0.0:
        raise ValueError("min_entropy_h must be positive")
    cutoff = 1 + math.ceil(-math.log2(alpha) / min_entropy_h)

    max_consecutive = 1
    current_run = 1
    prev = data[0]
    for byte in data[1:]:
        if byte == prev:
            current_run += 1
            if current_run > max_consecutive:
                max_consecutive = current_run
        else:
            prev = byte
            current_run = 1

    return StatisticalTestResult(
        name="nist_800_90b_repetition_count",
        passed=max_consecutive < cutoff,
        statistic=float(max_consecutive),
        p_value=None,
        threshold=float(cutoff),
        detail=f"max_repeat={max_consecutive}, cutoff={cutoff}",
    )


def adaptive_proportion_test(
    data: bytes,
    window_size: int = 512,
    min_entropy_h: float = 4.0,
    alpha: float = 2.0**-20,
) -> StatisticalTestResult:
    """NIST SP 800-90B Section 4.4.2: Adaptive Proportion Test (non-binary 8-bit symbols)."""
    if len(data) < 16:
        raise ValueError("Adaptive Proportion Test requires at least 16 bytes")
    w = min(window_size, len(data))
    p_sym = 2.0 ** (-min_entropy_h)
    # Cutoff C: smallest integer such that Pr[Binom(W-1, p) >= C - 1] <= alpha
    cutoff = int(binom.ppf(1.0 - alpha, w - 1, p_sym)) + 2

    max_matches = 1
    for start in range(0, len(data) - w + 1, w):
        window = data[start : start + w]
        target = window[0]
        matches = 1 + sum(1 for b in window[1:] if b == target)
        if matches > max_matches:
            max_matches = matches

    return StatisticalTestResult(
        name="nist_800_90b_adaptive_proportion",
        passed=max_matches < cutoff,
        statistic=float(max_matches),
        p_value=None,
        threshold=float(cutoff),
        detail=f"max_matches={max_matches}, window={w}, cutoff={cutoff}",
    )


def validate_entropy_batch(
    data: bytes,
    strict: bool = True,
    alpha_800_22: float = 0.01,
) -> EntropyHealthReport:
    """Run full NIST SP 800-22 & SP 800-90B statistical validation on an entropy buffer."""
    bits = bytes_to_bits(data)
    results: list[StatisticalTestResult] = [
        repetition_count_test(data),
        adaptive_proportion_test(data),
        frequency_monobit_test(bits, alpha=alpha_800_22),
        block_frequency_test(bits, block_size=16, alpha=alpha_800_22),
        runs_test(bits, alpha=alpha_800_22),
        longest_run_of_ones_test(bits, alpha=alpha_800_22),
    ]
    if strict:
        overall = all(r.passed for r in results)
    else:
        # Non-strict mode still requires 800-90B continuous health checks and >=3 of 4 800-22 checks
        health_ok = results[0].passed and results[1].passed
        stat_passes = sum(1 for r in results[2:] if r.passed)
        overall = health_ok and stat_passes >= 3

    return EntropyHealthReport(
        num_bytes=len(data),
        num_bits=int(bits.size),
        passed=overall,
        tests=results,
    )
