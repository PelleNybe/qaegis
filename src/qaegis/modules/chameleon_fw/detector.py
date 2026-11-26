"""Trainable IsolationForest + ONNX Runtime anomaly and HNDL threat tier classifier."""

from __future__ import annotations

import warnings
from pathlib import Path

import numpy as np
import onnxruntime as ort
import torch
from numpy.typing import NDArray
from pydantic import BaseModel, Field
from sklearn.ensemble import IsolationForest

from qaegis.core.config import ChameleonConfig
from qaegis.modules.chameleon_fw.features import (
    ThreatTier as ThreatTier,
)
from qaegis.modules.chameleon_fw.features import (
    TrafficFeatureExtractor,
    TrafficObservation,
)


class ThreatAssessment(BaseModel):
    """Result of real-time anomaly detection and HNDL risk classification."""

    tier: ThreatTier
    risk_score: float = Field(ge=0.0, le=1.0)
    anomaly_score: float = Field(ge=0.0, le=1.0)
    onnx_hndl_score: float = Field(ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)


class _HndlRiskNet(torch.nn.Module):
    """Compact neural classifier estimating Harvest-Now-Decrypt-Later (HNDL) exposure."""

    def __init__(self, input_dim: int = 8) -> None:
        super().__init__()
        self.net = torch.nn.Sequential(
            torch.nn.Linear(input_dim, 16),
            torch.nn.ReLU(),
            torch.nn.Linear(16, 1),
            torch.nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        out: torch.Tensor = self.net(x)
        return out


def _generate_baseline_and_hndl_dataset(
    seed: int = 42,
) -> tuple[NDArray[np.float32], NDArray[np.float32], NDArray[np.float32]]:
    """Create realistic normal-traffic baseline and labeled HNDL training samples."""
    rng = np.random.default_rng(seed)

    # Normal low-risk LAN traffic
    n_normal = 240
    normal = np.column_stack(
        [
            rng.uniform(0.10, 0.45, n_normal),  # log_payload_size
            rng.uniform(0.25, 0.65, n_normal),  # shannon_entropy_norm
            rng.uniform(0.00, 0.15, n_normal),  # non_printable_ratio
            rng.uniform(0.01, 0.20, n_normal),  # burst_rate_norm
            rng.uniform(0.01, 0.20, n_normal),  # inter_arrival_inv
            rng.uniform(0.00, 0.25, n_normal),  # sensitivity_weight
            rng.uniform(0.00, 0.20, n_normal),  # retention_risk
            np.full(n_normal, 0.15),  # network_exposure (LAN)
        ]
    ).astype(np.float32)

    # High-risk / HNDL traffic (confidential/secret, long retention, WAN/satellite, high burst)
    n_high = 240
    high_risk = np.column_stack(
        [
            rng.uniform(0.35, 0.95, n_high),
            rng.uniform(0.55, 1.00, n_high),
            rng.uniform(0.15, 0.95, n_high),
            rng.uniform(0.35, 1.00, n_high),
            rng.uniform(0.35, 1.00, n_high),
            rng.uniform(0.60, 1.00, n_high),
            rng.uniform(0.50, 1.00, n_high),
            rng.uniform(0.60, 1.00, n_high),
        ]
    ).astype(np.float32)

    x_all = np.vstack([normal, high_risk]).astype(np.float32)
    y_all = np.concatenate(
        [np.zeros((n_normal, 1), dtype=np.float32), np.ones((n_high, 1), dtype=np.float32)]
    )
    return normal, x_all, y_all


class AdaptiveThreatDetector:
    """Combines scikit-learn IsolationForest anomaly scoring with ONNX Runtime HNDL inference."""

    def __init__(
        self,
        config: ChameleonConfig | None = None,
        onnx_model_path: Path | None = None,
        seed: int = 42,
    ) -> None:
        self._config = config or ChameleonConfig()
        self._extractor = TrafficFeatureExtractor()
        self._seed = seed
        self._iso_forest = IsolationForest(
            n_estimators=64,
            contamination=self._config.anomaly_contamination,
            random_state=seed,
        )
        self._torch_model = _HndlRiskNet(input_dim=len(TrafficFeatureExtractor.FEATURE_NAMES))
        self._onnx_session: ort.InferenceSession | None = None

        baseline, x_train, y_train = _generate_baseline_and_hndl_dataset(seed=seed)
        self.fit(baseline_features=baseline, hndl_x=x_train, hndl_y=y_train, epochs=40)

        if onnx_model_path is not None:
            self.export_onnx(onnx_model_path)
            self.load_onnx(onnx_model_path)

    def fit(
        self,
        baseline_features: NDArray[np.float32],
        hndl_x: NDArray[np.float32] | None = None,
        hndl_y: NDArray[np.float32] | None = None,
        epochs: int = 40,
    ) -> None:
        """Fit the IsolationForest on normal traffic and train the HNDL neural risk scorer."""
        self._iso_forest.fit(baseline_features)
        if hndl_x is not None and hndl_y is not None:
            torch.manual_seed(self._seed)
            self._torch_model.train()
            optimizer = torch.optim.Adam(self._torch_model.parameters(), lr=0.03)
            loss_fn = torch.nn.BCELoss()
            x_tensor = torch.from_numpy(hndl_x)
            y_tensor = torch.from_numpy(hndl_y)
            for _ in range(epochs):
                optimizer.zero_grad()
                preds = self._torch_model(x_tensor)
                loss = loss_fn(preds, y_tensor)
                loss.backward()
                optimizer.step()
            self._torch_model.eval()

    def export_onnx(self, output_path: Path) -> Path:
        """Export the trained HNDL neural risk classifier to ONNX format."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        self._torch_model.eval()
        dummy = torch.zeros((1, len(TrafficFeatureExtractor.FEATURE_NAMES)), dtype=torch.float32)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            torch.onnx.export(
                self._torch_model,
                (dummy,),
                str(output_path),
                input_names=["features"],
                output_names=["hndl_risk"],
                opset_version=17,
                dynamo=False,
            )
        return output_path

    def load_onnx(self, model_path: Path) -> None:
        """Load an exported ONNX HNDL risk classifier into ONNX Runtime."""
        self._onnx_session = ort.InferenceSession(
            str(model_path),
            providers=["CPUExecutionProvider"],
        )

    def assess(self, observation: TrafficObservation) -> ThreatAssessment:
        """Score a live TrafficObservation and assign a dynamic ThreatTier."""
        features = self._extractor.extract(observation)
        feat_2d = features.reshape(1, -1)

        # IsolationForest decision_function: >0 normal, <0 anomalous; map smoothly to [0, 1]
        raw_df = float(self._iso_forest.decision_function(feat_2d)[0])
        anomaly_score = float(1.0 / (1.0 + np.exp(6.0 * raw_df)))

        # ONNX Runtime inference if loaded, else CPU PyTorch inference
        if self._onnx_session is not None:
            onnx_out = self._onnx_session.run(None, {"features": feat_2d})
            hndl_score = float(np.asarray(onnx_out[0]).reshape(-1)[0])
        else:
            with torch.no_grad():
                hndl_score = float(self._torch_model(torch.from_numpy(feat_2d)).item())

        reasons: list[str] = []
        if observation.sensitivity in ("secret", "top_secret"):
            reasons.append(f"sensitivity={observation.sensitivity}")
        if observation.long_term_retention_years >= 5.0:
            reasons.append(f"hndl_retention_years={observation.long_term_retention_years:.1f}")
        if features[7] >= 0.9:
            reasons.append(f"exposed_protocol={observation.protocol}")
        if anomaly_score >= 0.65:
            reasons.append(f"isolation_forest_anomaly={anomaly_score:.2f}")

        # Combine unsupervised anomaly + supervised HNDL risk + deterministic policy floor
        combined = float(np.clip(0.40 * anomaly_score + 0.60 * hndl_score, 0.0, 1.0))

        # Mandatory policy floors so classified/long-retention data is never downgraded
        if observation.sensitivity == "top_secret" or (
            observation.sensitivity == "secret" and observation.long_term_retention_years >= 5.0
        ):
            combined = max(combined, self._config.critical_risk_threshold + 0.05)
        elif (
            observation.sensitivity == "confidential"
            or observation.long_term_retention_years >= 5.0
        ):
            combined = max(combined, self._config.elevated_risk_threshold + 0.05)

        if combined >= self._config.critical_risk_threshold:
            tier = ThreatTier.QUANTUM_CRITICAL
        elif combined >= self._config.elevated_risk_threshold:
            tier = ThreatTier.ELEVATED
        else:
            tier = ThreatTier.STANDARD

        return ThreatAssessment(
            tier=tier,
            risk_score=combined,
            anomaly_score=anomaly_score,
            onnx_hndl_score=hndl_score,
            reasons=reasons,
        )
