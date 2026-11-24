"""PyTorch neural autoencoder compressing sensor tensors into bounded [-pi, pi] qubit angles."""

from __future__ import annotations

import math
import warnings
from pathlib import Path

import numpy as np
import onnxruntime as ort
import torch
from numpy.typing import NDArray
from pydantic import BaseModel, Field


class QuantumAnglePayload(BaseModel):
    """Compiled quantum rotation angles (Rx, Ry, Rz) in radians strictly bounded to [-pi, pi]."""

    num_qubits: int = Field(ge=1)
    angles_rad: list[list[float]]  # shape: [num_qubits, 3] -> (Rx, Ry, Rz)
    source_dim: int
    encoder_backend: str


class SensorToAngleAutoencoder(torch.nn.Module):
    """Autoencoder whose latent bottleneck emits exact bounded [-pi, pi] (Rx, Ry, Rz) angles."""

    def __init__(self, input_dim: int, num_qubits: int, hidden_dim: int = 32) -> None:
        super().__init__()
        self.input_dim = input_dim
        self.num_qubits = num_qubits
        self.latent_dim = num_qubits * 3

        self.encoder = torch.nn.Sequential(
            torch.nn.Linear(input_dim, hidden_dim),
            torch.nn.GELU(),
            torch.nn.Linear(hidden_dim, hidden_dim),
            torch.nn.GELU(),
            torch.nn.Linear(hidden_dim, self.latent_dim),
            torch.nn.Tanh(),
        )
        self.decoder = torch.nn.Sequential(
            torch.nn.Linear(self.latent_dim, hidden_dim),
            torch.nn.GELU(),
            torch.nn.Linear(hidden_dim, input_dim),
        )

    def encode(self, x: torch.Tensor) -> torch.Tensor:
        """Map input feature tensor to bounded [-pi, pi] angles of shape [batch, num_qubits, 3]."""
        raw: torch.Tensor = self.encoder(x) * math.pi
        return raw.view(-1, self.num_qubits, 3)

    def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        """Return (reconstructed_input, rotation_angles)."""
        angles = self.encode(x)
        flat_angles = angles.view(-1, self.latent_dim)
        reconstructed: torch.Tensor = self.decoder(flat_angles / math.pi)
        return reconstructed, angles


class _EncoderExportWrapper(torch.nn.Module):
    """Self-contained export wrapper fusing standardization and bounded [-pi, pi] encoder."""

    input_mean: torch.Tensor
    input_std: torch.Tensor

    def __init__(
        self,
        autoencoder: SensorToAngleAutoencoder,
        mean: NDArray[np.float32],
        std: NDArray[np.float32],
    ) -> None:
        super().__init__()
        self.encoder = autoencoder.encoder
        self.num_qubits = autoencoder.num_qubits
        self.register_buffer("input_mean", torch.from_numpy(mean.astype(np.float32)).view(1, -1))
        self.register_buffer("input_std", torch.from_numpy(std.astype(np.float32)).view(1, -1))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        normed = (x - self.input_mean) / self.input_std
        angles: torch.Tensor = self.encoder(normed) * math.pi
        return angles.view(-1, self.num_qubits, 3)


class AngleEncoderPipeline:
    """Trains, exports (ONNX), and executes the AI-to-Qubit rotation-angle encoder."""

    def __init__(
        self,
        input_dim: int,
        num_qubits: int = 4,
        hidden_dim: int = 32,
        seed: int = 42,
    ) -> None:
        torch.manual_seed(seed)
        self.input_dim = input_dim
        self.num_qubits = num_qubits
        self.model = SensorToAngleAutoencoder(
            input_dim=input_dim,
            num_qubits=num_qubits,
            hidden_dim=hidden_dim,
        )
        self._onnx_session: ort.InferenceSession | None = None
        self._mean: NDArray[np.float32] = np.zeros(input_dim, dtype=np.float32)
        self._std: NDArray[np.float32] = np.ones(input_dim, dtype=np.float32)

    def train(
        self,
        samples: NDArray[np.float32],
        epochs: int = 60,
        lr: float = 0.01,
    ) -> list[float]:
        """Train the autoencoder on sensor/telemetry feature batches and return MSE loss history."""
        if samples.ndim != 2 or samples.shape[1] != self.input_dim:
            raise ValueError(
                f"Expected samples of shape (N, {self.input_dim}), got {samples.shape}"
            )

        self._mean = samples.mean(axis=0).astype(np.float32)
        std = samples.std(axis=0).astype(np.float32)
        self._std = np.where(std < 1e-6, 1.0, std).astype(np.float32)
        normed = (samples - self._mean) / self._std

        x_tensor = torch.from_numpy(normed.astype(np.float32))
        optimizer = torch.optim.Adam(self.model.parameters(), lr=lr)
        criterion = torch.nn.MSELoss()

        losses: list[float] = []
        self.model.train()
        for _ in range(epochs):
            optimizer.zero_grad()
            recon, _angles = self.model(x_tensor)
            loss = criterion(recon, x_tensor)
            loss.backward()
            optimizer.step()
            losses.append(float(loss.item()))
        self.model.eval()
        return losses

    def export_onnx(self, output_path: Path) -> Path:
        """Export a self-contained ONNX angle encoder (including standardization stats)."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        wrapper = _EncoderExportWrapper(self.model, mean=self._mean, std=self._std)
        wrapper.eval()
        dummy = torch.zeros((1, self.input_dim), dtype=torch.float32)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            torch.onnx.export(
                wrapper,
                (dummy,),
                str(output_path),
                input_names=["sensor_tensor"],
                output_names=["rotation_angles"],
                opset_version=17,
                dynamo=False,
            )
        return output_path

    def load_onnx(self, model_path: Path) -> None:
        """Load an exported ONNX angle encoder into ONNX Runtime."""
        self._onnx_session = ort.InferenceSession(
            str(model_path),
            providers=["CPUExecutionProvider"],
        )

    def encode_to_angles(self, vector: NDArray[np.float32] | list[float]) -> QuantumAnglePayload:
        """Compress a single numeric sensor vector into bounded [-pi, pi] (Rx, Ry, Rz) angles."""
        arr = np.asarray(vector, dtype=np.float32).reshape(1, self.input_dim)

        if self._onnx_session is not None:
            # Standardization (mean/std) is fused inside the exported ONNX graph
            out = self._onnx_session.run(None, {"sensor_tensor": arr})
            angles_np = np.asarray(out[0], dtype=np.float64)[0]
            backend = "onnxruntime_cpu"
        else:
            normed = ((arr - self._mean) / self._std).astype(np.float32)
            self.model.eval()
            with torch.no_grad():
                angles_t = self.model.encode(torch.from_numpy(normed))
            angles_np = angles_t.cpu().numpy().astype(np.float64)[0]
            backend = "pytorch_cpu"

        clipped = np.clip(angles_np, -math.pi, math.pi)
        return QuantumAnglePayload(
            num_qubits=self.num_qubits,
            angles_rad=[[float(v) for v in row] for row in clipped],
            source_dim=self.input_dim,
            encoder_backend=backend,
        )
