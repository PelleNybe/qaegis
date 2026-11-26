"""Real-time traffic & payload sensitivity feature extractor for Quantum Chameleon."""

from __future__ import annotations

import math
from collections import deque
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

import numpy as np
from numpy.typing import NDArray
from pydantic import BaseModel, Field

SensitivityTag = Literal["public", "internal", "confidential", "secret", "top_secret"]


class ThreatTier(StrEnum):
    """Dynamic cryptographic protection tiers enforced by Quantum Chameleon."""

    STANDARD = "STANDARD"
    ELEVATED = "ELEVATED"
    QUANTUM_CRITICAL = "QUANTUM_CRITICAL"


_SENSITIVITY_WEIGHTS: dict[SensitivityTag, float] = {
    "public": 0.0,
    "internal": 0.25,
    "confidential": 0.60,
    "secret": 0.85,
    "top_secret": 1.0,
}

_HIGH_RISK_PROTOCOLS: frozenset[str] = frozenset({"wan", "satellite", "cellular", "untrusted_mesh"})


class TrafficObservation(BaseModel):
    """Metadata and raw payload characteristics for a single outbound or inbound message."""

    source: str
    destination: str
    topic: str = "telemetry"
    protocol: str = "lan"
    sensitivity: SensitivityTag = "internal"
    payload_bytes: bytes
    long_term_retention_years: float = Field(default=1.0, ge=0.0, le=100.0)
    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))


def shannon_entropy_bytes(data: bytes) -> float:
    """Compute Shannon entropy in bits per byte (range [0.0, 8.0])."""
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probs = counts[counts > 0] / float(len(data))
    return float(-np.sum(probs * np.log2(probs)))


def printable_ascii_ratio(data: bytes) -> float:
    """Compute fraction of bytes that are printable ASCII characters."""
    if not data:
        return 1.0
    arr = np.frombuffer(data, dtype=np.uint8)
    printable = np.sum((arr >= 32) & (arr <= 126))
    return float(printable) / float(len(data))


class TrafficFeatureExtractor:
    """Extracts an 8-dimensional numeric feature vector for anomaly & HNDL risk classification."""

    FEATURE_NAMES: tuple[str, ...] = (
        "log_payload_size",
        "shannon_entropy_norm",
        "non_printable_ratio",
        "burst_rate_norm",
        "inter_arrival_inv",
        "sensitivity_weight",
        "retention_risk",
        "network_exposure",
    )

    def __init__(self, window_size: int = 64) -> None:
        self._timestamps: deque[float] = deque(maxlen=window_size)
        self._sizes: deque[int] = deque(maxlen=window_size)

    @property
    def mean_window_payload_bytes(self) -> float:
        """Return rolling average payload byte length across the active sliding window."""
        if not self._sizes:
            return 0.0
        return float(sum(self._sizes)) / float(len(self._sizes))

    def extract(self, obs: TrafficObservation) -> NDArray[np.float32]:
        """Compute normalized 8-float feature vector from a `TrafficObservation`."""
        ts = obs.timestamp_utc.timestamp()
        prev_ts = self._timestamps[-1] if self._timestamps else ts - 1.0
        self._timestamps.append(ts)
        self._sizes.append(len(obs.payload_bytes))

        inter_arrival_s = max(ts - prev_ts, 1e-4)
        inter_arrival_inv = min(1.0 / inter_arrival_s, 100.0) / 100.0

        # Messages per second inside sliding window
        if len(self._timestamps) >= 2:
            span = max(self._timestamps[-1] - self._timestamps[0], 1e-3)
            burst_rate = float(len(self._timestamps)) / span
        else:
            burst_rate = 1.0
        burst_rate_norm = min(burst_rate / 200.0, 1.0)

        payload_len = len(obs.payload_bytes)
        log_size = min(math.log1p(payload_len) / 16.0, 1.0)
        entropy_norm = shannon_entropy_bytes(obs.payload_bytes) / 8.0
        non_printable = 1.0 - printable_ascii_ratio(obs.payload_bytes)
        sensitivity = _SENSITIVITY_WEIGHTS[obs.sensitivity]
        # HNDL (Harvest Now, Decrypt Later): data staying sensitive > 5 years needs PQC today
        retention_risk = min(obs.long_term_retention_years / 10.0, 1.0)
        network_exposure = 1.0 if obs.protocol.lower() in _HIGH_RISK_PROTOCOLS else 0.15

        return np.array(
            [
                log_size,
                entropy_norm,
                non_printable,
                burst_rate_norm,
                inter_arrival_inv,
                sensitivity,
                retention_risk,
                network_exposure,
            ],
            dtype=np.float32,
        )
