"""Hierarchical Pydantic v2 configuration loader (YAML + Environment Variables)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class BusConfig(BaseModel):
    """Configuration for the typed asynchronous event bus."""

    transport: Literal["inproc", "zmq"] = "inproc"
    zmq_pub_endpoint: str = "ipc:///tmp/qaegis-bus-pub.ipc"
    zmq_sub_endpoint: str = "ipc:///tmp/qaegis-bus-pub.ipc"
    zmq_bind_pub: bool = True
    zmq_connect_sub: bool = True
    zmq_security: Literal["none", "curve"] = "none"
    zmq_curve_key_dir: Path | None = None
    zmq_allowed_peer_keys: list[str] = Field(default_factory=list)
    zmq_server_public_key: str | None = None
    max_queue_size: int = Field(default=1024, ge=1, le=1_000_000)
    backpressure_policy: Literal["block", "drop_oldest", "reject"] = "block"
    request_timeout_s: float = Field(default=10.0, gt=0.0)


class IdentityConfig(BaseModel):
    """Post-quantum device identity and key lifecycle settings."""

    primary_sig_alg: str = "ML-DSA-65"
    fallback_sig_alg: str = "SLH-DSA-SHA2-128f"
    kem_alg: str = "ML-KEM-768"
    rotation_interval_hours: int = Field(default=720, ge=1)
    hardware_seal_backend: Literal["none", "pkcs11", "tpm2"] = "none"
    pkcs11_library: str | None = None
    pkcs11_token_label: str = "qaegis"  # noqa: S105
    pkcs11_key_label: str = "qaegis-pqc-kek"
    tpm2_device: str = "/dev/tpmrm0"
    tpm2_pcr_spec: str = "sha256:0,7"


class LifecycleConfig(BaseModel):
    """Day-Mode (real-time) vs Night-Mode (batch quantum) state machine configuration."""

    default_mode: Literal["DAY", "NIGHT"] = "DAY"
    night_window_start_hour: int = Field(default=1, ge=0, le=23)
    night_window_end_hour: int = Field(default=5, ge=0, le=23)
    idle_cpu_threshold_pct: float = Field(default=25.0, ge=0.0, le=100.0)
    idle_duration_seconds: float = Field(default=300.0, ge=1.0)
    max_night_batch_size: int = Field(default=16, ge=1, le=1024)


class TelemetryConfig(BaseModel):
    """Structured logging and Prometheus metrics configuration."""

    enabled: bool = True
    metrics_host: str = "127.0.0.1"
    metrics_port: int = Field(default=9108, ge=1, le=65535)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_json: bool = True


class RealityStampConfig(BaseModel):
    """Configuration for Module 1: Proof of Reality."""

    qrng_http_url: str | None = None
    qrng_http_timeout_s: float = Field(default=3.0, gt=0.0)
    qiskit_qrng_qubits: int = Field(default=8, ge=4, le=16)
    entropy_sample_bytes: int = Field(default=128, ge=32, le=8192)
    strict_nist_checks: bool = True
    default_sig_alg: str = "ML-DSA-65"


class ChameleonConfig(BaseModel):
    """Configuration for Module 2: Quantum Chameleon adaptive PQC firewall."""

    anomaly_contamination: float = Field(default=0.05, gt=0.0, lt=0.5)
    elevated_risk_threshold: float = Field(default=0.45, ge=0.0, le=1.0)
    critical_risk_threshold: float = Field(default=0.75, ge=0.0, le=1.0)
    rekey_after_messages: int = Field(default=100, ge=1)
    kem_alg: str = "ML-KEM-768"
    sig_alg: str = "ML-DSA-65"

    @model_validator(mode="after")
    def _validate_thresholds(self) -> ChameleonConfig:
        if self.elevated_risk_threshold >= self.critical_risk_threshold:
            raise ValueError(
                "elevated_risk_threshold must be strictly less than critical_risk_threshold"
            )
        return self


class QubitCompilerConfig(BaseModel):
    """Configuration for Module 3: AI-to-Qubit Compiler."""

    default_num_qubits: int = Field(default=4, ge=2, le=20)
    encoder_hidden_dim: int = Field(default=32, ge=4, le=1024)
    backend_noise_level: float = Field(default=0.01, ge=0.0, le=0.5)
    optimization_level: int = Field(default=2, ge=0, le=3)


class QuantumDreamerConfig(BaseModel):
    """Configuration for Module 4: Quantum Dreaming asynchronous optimizer."""

    backend_type: Literal["aer_statevector", "aer_noisy", "ibm_runtime", "aws_braket", "ionq"] = (
        "aer_statevector"
    )
    ibm_backend_name: str = "ibm_brisbane"
    ibm_channel: Literal["ibm_quantum", "ibm_cloud"] = "ibm_quantum"
    braket_device_arn: str | None = None
    ionq_target: str = "simulator"
    ionq_api_url: str = "https://api.ionq.co/v0.3/jobs"
    qaoa_reps: int = Field(default=2, ge=1, le=8)
    qaoa_shots: int = Field(default=1024, ge=64, le=100_000)
    max_optimizer_iters: int = Field(default=60, ge=5, le=1000)
    min_policy_improvement: float = Field(default=0.01, ge=0.0)
    mitigation_mode: Literal["none", "zne", "trex", "both"] = "none"
    zne_scale_factors: list[int] = Field(default_factory=lambda: [1, 3, 5])
    zne_extrapolation: Literal["linear", "richardson", "exponential"] = "richardson"
    max_qpu_seconds_per_night: float = Field(default=300.0, gt=0.0)

    @model_validator(mode="after")
    def _validate_zne_scale_factors(self) -> QuantumDreamerConfig:
        if any(s < 1 or s % 2 == 0 for s in self.zne_scale_factors):
            raise ValueError("zne_scale_factors must contain only odd positive integers")
        if len(set(self.zne_scale_factors)) != len(self.zne_scale_factors):
            raise ValueError("zne_scale_factors must contain unique values")
        if self.mitigation_mode in ("zne", "both") and len(self.zne_scale_factors) < 2:
            raise ValueError("ZNE mitigation requires at least 2 distinct odd scale factors")
        return self


class QuantumEntropyConfig(BaseModel):
    """Configuration for Module 5: Quantum-Noise Evolution Engine."""

    harvester_qubits: int = Field(default=6, ge=2, le=16)
    harvester_shots: int = Field(default=512, ge=64, le=65_536)
    pool_min_bytes: int = Field(default=256, ge=32, le=65_536)
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.2"
    ollama_timeout_s: float = Field(default=30.0, gt=0.0)


class QAegisConfig(BaseSettings):
    """Root configuration model for the Q-Aegis microkernel and all five modules."""

    model_config = SettingsConfigDict(
        env_prefix="QAEGIS_",
        env_nested_delimiter="__",
        extra="forbid",
    )

    node_id: str = Field(default="qaegis-edge-01", min_length=1, max_length=128)
    data_dir: Path = Field(default=Path("./data"))
    keys_dir: Path = Field(default=Path("./keys"))
    db_path: Path = Field(default=Path("./data/qaegis.db"))

    bus: BusConfig = Field(default_factory=BusConfig)
    identity: IdentityConfig = Field(default_factory=IdentityConfig)
    lifecycle: LifecycleConfig = Field(default_factory=LifecycleConfig)
    telemetry: TelemetryConfig = Field(default_factory=TelemetryConfig)
    reality_stamp: RealityStampConfig = Field(default_factory=RealityStampConfig)
    chameleon_fw: ChameleonConfig = Field(default_factory=ChameleonConfig)
    qubit_compiler: QubitCompilerConfig = Field(default_factory=QubitCompilerConfig)
    quantum_dreamer: QuantumDreamerConfig = Field(default_factory=QuantumDreamerConfig)
    quantum_entropy: QuantumEntropyConfig = Field(default_factory=QuantumEntropyConfig)

    @field_validator("data_dir", "keys_dir", "db_path", mode="before")
    @classmethod
    def _expand_path(cls, value: Any) -> Any:
        if isinstance(value, str):
            return Path(os.path.expandvars(value)).expanduser()
        return value

    def ensure_directories(self) -> None:
        """Create required runtime directories with safe permissions."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.keys_dir, 0o700)


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = dict(base)
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(
    config_path: Path | str | None = None,
    overrides: dict[str, Any] | None = None,
) -> QAegisConfig:
    """Load Q-Aegis configuration from YAML file, environment variables, and explicit overrides.

    Precedence (highest to lowest):
      1. Explicit `overrides` dict
      2. Environment variables (`QAEGIS_*`)
      3. YAML configuration file (`config_path` or `QAEGIS_CONFIG`)
      4. Model defaults
    """
    yaml_data: dict[str, Any] = {}
    resolved_path: Path | None = None

    if config_path is not None:
        resolved_path = Path(config_path)
    elif env_path := os.environ.get("QAEGIS_CONFIG"):
        resolved_path = Path(env_path)

    if resolved_path is not None:
        if not resolved_path.is_file():
            raise FileNotFoundError(f"Configuration file not found: {resolved_path}")
        raw = yaml.safe_load(resolved_path.read_text(encoding="utf-8"))
        if raw is not None:
            if not isinstance(raw, dict):
                raise ValueError(f"Configuration YAML root must be a mapping: {resolved_path}")
            yaml_data = raw

    if overrides:
        yaml_data = _deep_merge(yaml_data, overrides)

    # Apply YAML defaults first, then let environment variables (BaseSettings) override YAML
    base_from_yaml = QAegisConfig.model_validate(yaml_data) if yaml_data else QAegisConfig()

    # Re-apply explicit env vars if YAML was provided so env takes precedence over YAML
    if yaml_data:
        env_overrides: dict[str, Any] = {}
        for env_key, env_val in os.environ.items():
            if not env_key.startswith("QAEGIS_") or env_key == "QAEGIS_CONFIG":
                continue
            parts = env_key[len("QAEGIS_") :].lower().split("__")
            cursor = env_overrides
            for part in parts[:-1]:
                cursor = cursor.setdefault(part, {})
            parsed_val: Any = env_val
            stripped = env_val.strip()
            if stripped.startswith(("[", "{")):
                try:
                    parsed_val = json.loads(stripped)
                except json.JSONDecodeError:
                    parsed_val = env_val
            cursor[parts[-1]] = parsed_val
        if env_overrides:
            merged = _deep_merge(base_from_yaml.model_dump(mode="python"), env_overrides)
            if overrides:
                merged = _deep_merge(merged, overrides)
            return QAegisConfig.model_validate(merged)

    return base_from_yaml
