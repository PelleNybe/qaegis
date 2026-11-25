"""Live microkernel orchestrator, telemetry aggregator, and hot-config manager for Web UI."""

from __future__ import annotations

import asyncio
import contextlib
import os
import platform
import sys
import tempfile
import time
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import oqs
import orjson
import pennylane as qml
import psutil
import qiskit
import torch
import yaml

from qaegis import __version__
from qaegis.adapters.ros2_bridge import is_ros2_available
from qaegis.core.bus import EventBus, EventEnvelope, Subscription
from qaegis.core.config import QAegisConfig, _deep_merge
from qaegis.core.hardware_seal import (
    HardwareSealer,
    PKCS11Sealer,
    TPM2Sealer,
    create_sealer_from_config,
    detect_pkcs11_library,
)
from qaegis.core.identity import DeviceIdentity, IdentityManager
from qaegis.core.lifecycle import LifecycleManager
from qaegis.core.storage import StorageEngine
from qaegis.core.telemetry import QAegisMetrics, configure_logging, get_logger
from qaegis.modules.chameleon_fw.crypto_agility import CryptoAgilityEngine
from qaegis.modules.chameleon_fw.detector import AdaptiveThreatDetector, ThreatTier
from qaegis.modules.chameleon_fw.features import SensitivityTag, TrafficObservation
from qaegis.modules.chameleon_fw.service import ChameleonFirewallService
from qaegis.modules.quantum_dreamer.federated import (
    FederatedJobSubmission,
    FederatedScheduler,
)
from qaegis.modules.quantum_dreamer.policy_updater import PolicyUpdater
from qaegis.modules.quantum_dreamer.service import QuantumDreamerService
from qaegis.modules.quantum_dreamer.solvers import QaoaSolver, get_backend_registry
from qaegis.modules.quantum_entropy.harvester import (
    QuantumDistributionHarvester,
    QuantumEntropyPool,
)
from qaegis.modules.quantum_entropy.ollama_bridge import OllamaQuantumBridge
from qaegis.modules.quantum_entropy.sampler import QuantumEvolutionaryMutator
from qaegis.modules.quantum_entropy.service import QuantumEntropyService
from qaegis.modules.qubit_compiler.autoencoder import AngleEncoderPipeline
from qaegis.modules.qubit_compiler.circuit_builder import (
    BackendNoiseProfile,
    NoiseAwareCircuitBuilder,
)
from qaegis.modules.qubit_compiler.qubo_mapper import (
    QuboProblem,
    build_maxcut_qubo,
    build_resource_allocation_qubo,
    build_task_scheduling_qubo,
)
from qaegis.modules.qubit_compiler.service import QubitCompilerService
from qaegis.modules.reality_stamp.gossip import MerkleGossipNode
from qaegis.modules.reality_stamp.qrng import MultiSourceQrng
from qaegis.modules.reality_stamp.service import RealityStampService
from qaegis.modules.reality_stamp.signer import (
    RealitySigner,
    RealityStamp,
    verify_reality_stamp,
)

logger = get_logger(__name__)


def _atomic_write_yaml(path: Path, data: dict[str, Any]) -> None:
    """Persist configuration YAML atomically with 0o600 permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = yaml.safe_dump(data, sort_keys=False).encode("utf-8")
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".qaegis-cfg-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
        os.chmod(path, 0o600)
    except Exception:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise


_REDACTED_PLACEHOLDER = "***REDACTED***"


def _sanitize_config_dict(raw: dict[str, Any]) -> dict[str, Any]:
    """Convert Path values to strings and redact auth_token when returning or auditing."""
    cleaned: dict[str, Any] = orjson.loads(orjson.dumps(raw, default=str))
    dash = cleaned.get("dashboard")
    if isinstance(dash, dict) and dash.get("auth_token"):
        dash["auth_token"] = _REDACTED_PLACEHOLDER
    return cleaned


class DashboardKernelRuntime:
    """Live orchestrator overseeing all 5 Q-Aegis subsystems, telemetry, and live config."""

    def __init__(
        self,
        config: QAegisConfig,
        config_file_path: Path | None = None,
        metrics: QAegisMetrics | None = None,
        bus: EventBus | None = None,
        storage: StorageEngine | None = None,
        lifecycle: LifecycleManager | None = None,
        identity: DeviceIdentity | None = None,
        reality_service: RealityStampService | None = None,
        chameleon_service: ChameleonFirewallService | None = None,
        compiler_service: QubitCompilerService | None = None,
        dreamer_service: QuantumDreamerService | None = None,
        entropy_service: QuantumEntropyService | None = None,
    ) -> None:
        self._config = config
        self._config_file_path = config_file_path or (config.data_dir / "qaegis.runtime.yaml")
        self._owns_kernel = bus is None
        self._started_at_monotonic = time.monotonic()
        self._started_at_utc = datetime.now(UTC)
        self._process = psutil.Process(os.getpid())
        self._config_lock = asyncio.Lock()

        self._metrics = metrics or QAegisMetrics()
        self._bus = bus or EventBus(config=config.bus, metrics=self._metrics)
        self._storage = storage or StorageEngine(config.db_path)
        self._lifecycle = lifecycle or LifecycleManager(
            bus=self._bus,
            config=config.lifecycle,
            metrics=self._metrics,
        )
        self._identity_mgr = IdentityManager(
            keys_dir=config.keys_dir,
            node_id=config.node_id,
            config=config.identity,
        )
        self._identity: DeviceIdentity | None = identity
        self._reality_svc = reality_service
        self._chameleon_svc = chameleon_service
        self._compiler_svc = compiler_service
        self._dreamer_svc = dreamer_service
        self._entropy_svc = entropy_service
        self._gossip_node: MerkleGossipNode | None = None
        self._peer_sandbox_identity: DeviceIdentity | None = None

        self._wildcard_sub: Subscription | None = None
        self._event_history: deque[dict[str, Any]] = deque(
            maxlen=config.dashboard.event_history_limit
        )
        self._sse_subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self._last_stamps: deque[dict[str, Any]] = deque(maxlen=50)
        self._running = False

    @property
    def config(self) -> QAegisConfig:
        return self._config

    @property
    def config_file_path(self) -> Path:
        return self._config_file_path

    @property
    def bus(self) -> EventBus:
        return self._bus

    @property
    def storage(self) -> StorageEngine:
        return self._storage

    @property
    def lifecycle(self) -> LifecycleManager:
        return self._lifecycle

    @property
    def metrics(self) -> QAegisMetrics:
        return self._metrics

    def _require_services(
        self,
    ) -> tuple[
        DeviceIdentity,
        RealityStampService,
        ChameleonFirewallService,
        QubitCompilerService,
        QuantumDreamerService,
        QuantumEntropyService,
        MerkleGossipNode,
    ]:
        if (
            self._identity is None
            or self._reality_svc is None
            or self._chameleon_svc is None
            or self._compiler_svc is None
            or self._dreamer_svc is None
            or self._entropy_svc is None
            or self._gossip_node is None
        ):
            raise RuntimeError("DashboardKernelRuntime has not been started")
        return (
            self._identity,
            self._reality_svc,
            self._chameleon_svc,
            self._compiler_svc,
            self._dreamer_svc,
            self._entropy_svc,
            self._gossip_node,
        )

    async def start(self) -> None:
        """Start the underlying microkernel (if owned) and subscribe to live EventBus streams."""
        if self._running:
            return
        self._config.ensure_directories()

        if self._owns_kernel:
            await self._bus.start()
            await self._storage.initialize()
            self._identity = self._identity_mgr.load_or_create()
            self._reality_svc = RealityStampService(
                bus=self._bus,
                identity=self._identity,
                storage=self._storage,
                config=self._config.reality_stamp,
                metrics=self._metrics,
            )
            self._chameleon_svc = ChameleonFirewallService(
                bus=self._bus,
                identity=self._identity,
                config=self._config.chameleon_fw,
                metrics=self._metrics,
            )
            self._compiler_svc = QubitCompilerService(
                bus=self._bus,
                config=self._config.qubit_compiler,
            )
            self._dreamer_svc = QuantumDreamerService(
                bus=self._bus,
                storage=self._storage,
                lifecycle=self._lifecycle,
                config=self._config.quantum_dreamer,
                metrics=self._metrics,
            )
            self._entropy_svc = QuantumEntropyService(
                bus=self._bus,
                config=self._config.quantum_entropy,
                metrics=self._metrics,
            )
            await self._reality_svc.start()
            await self._chameleon_svc.start()
            await self._compiler_svc.start()
            await self._dreamer_svc.start()
            await self._entropy_svc.start()
        elif self._identity is None:
            self._identity = self._identity_mgr.load_or_create()

        self._gossip_node = MerkleGossipNode(
            identity=self._identity,
            storage=self._storage,
            bus=self._bus,
            metrics=self._metrics,
        )
        await self._gossip_node.hydrate_from_storage()

        # Ephemeral peer identity used for live Chameleon loopback verification in the sandbox UI
        peer_dir = self._config.data_dir / ".dashboard_peer_keys"
        self._peer_sandbox_identity = IdentityManager(
            keys_dir=peer_dir,
            node_id="qaegis-verifier-peer",
            config=self._config.identity,
        ).load_or_create()

        self._wildcard_sub = self._bus.subscribe(
            "*",
            handler=self._on_any_bus_event,
            max_queue_size=1024,
        )
        self._running = True
        logger.info("dashboard_runtime_started", node_id=self._config.node_id)

    async def stop(self) -> None:
        """Unsubscribe SSE streams and cleanly shut down owned microkernel components."""
        if not self._running:
            return
        self._running = False
        if self._wildcard_sub is not None:
            await self._bus.unsubscribe(self._wildcard_sub)
            self._wildcard_sub = None
        if self._gossip_node is not None:
            await self._gossip_node.stop_mesh()

        if self._owns_kernel:
            await self._lifecycle.shutdown()
            if self._reality_svc is not None:
                await self._reality_svc.stop()
            await self._storage.close()
            await self._bus.stop()
        logger.info("dashboard_runtime_stopped")

    def open_sse_queue(self) -> asyncio.Queue[dict[str, Any]]:
        """Register a live Server-Sent Events client queue."""
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=256)
        self._sse_subscribers.add(q)
        return q

    def close_sse_queue(self, q: asyncio.Queue[dict[str, Any]]) -> None:
        """Unregister a disconnected Server-Sent Events client queue."""
        self._sse_subscribers.discard(q)

    async def _on_any_bus_event(self, envelope: EventEnvelope) -> None:
        item = envelope.model_dump(mode="json")
        self._event_history.appendleft(item)
        if envelope.topic == "reality_stamp.created":
            self._last_stamps.appendleft(envelope.payload)
        sse_msg = {"type": "bus_event", "data": item}
        for q in list(self._sse_subscribers):
            if q.full():
                with contextlib.suppress(asyncio.QueueEmpty):
                    q.get_nowait()
            with contextlib.suppress(asyncio.QueueFull):
                q.put_nowait(sse_msg)

    def get_recent_events(self, limit: int = 100) -> list[dict[str, Any]]:
        return list(self._event_history)[:limit]

    async def get_overview(self) -> dict[str, Any]:
        """Collect a comprehensive real-time snapshot across host, microkernel, and 5 modules."""
        (
            ident,
            reality_svc,
            chameleon_svc,
            _compiler_svc,
            _dreamer_svc,
            _entropy_svc,
            gossip_node,
        ) = self._require_services()

        vm = psutil.virtual_memory()
        cpu_pct = float(psutil.cpu_percent(interval=None))
        rss_mb = round(self._process.memory_info().rss / (1024**2), 2)
        uptime_s = round(time.monotonic() - self._started_at_monotonic, 1)

        problems = await self._storage.list_dream_problems(limit=200)
        pending_cnt = sum(1 for p in problems if p.status == "PENDING")
        solved_cnt = sum(1 for p in problems if p.status == "SOLVED")
        failed_cnt = sum(1 for p in problems if p.status == "FAILED")
        policies = await self._storage.list_policy_snapshots(limit=20)
        active_policies = [p.model_dump(mode="json") for p in policies if p.active]
        audit_ok, audit_count = await self._storage.verify_audit_chain()

        return {
            "timestamp_utc": datetime.now(UTC).isoformat(),
            "version": __version__,
            "node_id": self._config.node_id,
            "uptime_s": uptime_s,
            "started_at_utc": self._started_at_utc.isoformat(),
            "host": {
                "platform": f"{platform.system()} {platform.machine()}",
                "python": sys.version.split()[0],
                "cpu_percent": cpu_pct,
                "cpu_count_logical": psutil.cpu_count(logical=True) or 1,
                "ram_used_gb": round((vm.total - vm.available) / (1024**3), 2),
                "ram_total_gb": round(vm.total / (1024**3), 2),
                "ram_percent": float(vm.percent),
                "process_rss_mb": rss_mb,
                "liboqs_version": str(oqs.oqs_version()),
                "qiskit_version": qiskit.__version__,
                "pennylane_version": qml.__version__,
                "torch_version": torch.__version__,
            },
            "lifecycle": {
                "mode": self._lifecycle.mode.value,
                "in_night_window": self._lifecycle.is_within_night_window(),
                "night_window_hours_utc": [
                    self._config.lifecycle.night_window_start_hour,
                    self._config.lifecycle.night_window_end_hour,
                ],
                "idle_cpu_threshold_pct": self._config.lifecycle.idle_cpu_threshold_pct,
                "transitions": [t.model_dump(mode="json") for t in self._lifecycle.history[-10:]],
            },
            "bus": {
                "running": self._bus.is_running,
                "transport": self._config.bus.transport,
                "zmq_security": self._config.bus.zmq_security,
                "backpressure_policy": self._config.bus.backpressure_policy,
                "recent_events_buffered": len(self._event_history),
                "sse_clients_connected": len(self._sse_subscribers),
            },
            "identity": {
                "key_id": ident.key_id,
                "key_version": ident.key_version,
                "primary_sig_alg": ident.primary_sig_alg,
                "fallback_sig_alg": ident.fallback_sig_alg,
                "kem_alg": ident.kem_alg,
                "sealed_present": self._identity_mgr.sealed_path.is_file(),
            },
            "subsystems": {
                "reality_stamp": {
                    "status": "ONLINE",
                    "merkle_tree_size": reality_svc.tree_size,
                    "merkle_root": reality_svc.merkle_root,
                    "strict_nist_checks": self._config.reality_stamp.strict_nist_checks,
                    "gossip_peers_witnessed": len(gossip_node.latest_roots),
                    "equivocation_alerts": len(gossip_node.equivocation_alerts),
                },
                "chameleon_fw": {
                    "status": "ONLINE",
                    "current_tier": chameleon_svc.current_tier.value,
                    "session_epoch": chameleon_svc.crypto_engine.session_epoch,
                    "message_counter": chameleon_svc.crypto_engine.message_counter,
                    "elevated_threshold": self._config.chameleon_fw.elevated_risk_threshold,
                    "critical_threshold": self._config.chameleon_fw.critical_risk_threshold,
                },
                "qubit_compiler": {
                    "status": "ONLINE",
                    "default_num_qubits": self._config.qubit_compiler.default_num_qubits,
                    "optimization_level": self._config.qubit_compiler.optimization_level,
                    "backend_noise_level": self._config.qubit_compiler.backend_noise_level,
                    "onnx_active": self._compiler_svc._pipeline._onnx_session is not None
                    if self._compiler_svc is not None
                    else False,
                },
                "quantum_dreamer": {
                    "status": "ONLINE",
                    "backend_type": self._config.quantum_dreamer.backend_type,
                    "mitigation_mode": self._config.quantum_dreamer.mitigation_mode,
                    "qaoa_reps": self._config.quantum_dreamer.qaoa_reps,
                    "pending_problems": pending_cnt,
                    "solved_problems": solved_cnt,
                    "failed_problems": failed_cnt,
                    "active_policies": active_policies,
                },
                "quantum_entropy": {
                    "status": "ONLINE",
                    "harvester_qubits": self._config.quantum_entropy.harvester_qubits,
                    "harvester_shots": self._config.quantum_entropy.harvester_shots,
                    "pool_min_bytes": self._config.quantum_entropy.pool_min_bytes,
                    "ollama_model": self._config.quantum_entropy.ollama_model,
                },
            },
            "adapters": {
                "mqtt_supported": True,
                "ros2_available": is_ros2_available(),
            },
            "storage": {
                "db_path": str(self._storage.db_path),
                "audit_chain_valid": audit_ok,
                "audit_event_count": audit_count,
            },
        }

    async def get_diagnostics(self) -> dict[str, Any]:
        """Execute full `qaegis doctor` cryptographic, storage, and HSM/TPM2 checks."""
        schema_v = await self._storage.get_schema_version()
        audit_ok, audit_count = await self._storage.verify_audit_chain()
        dream_ok, dream_count = await self._storage.verify_dream_problem_integrity()
        policy_ok, policy_count = await self._storage.verify_policy_snapshots()

        enabled_kems = set(oqs.get_enabled_kem_mechanisms())
        enabled_sigs = set(oqs.get_enabled_sig_mechanisms())

        tpm = TPM2Sealer(device_path=Path(self._config.identity.tpm2_device))
        pkcs11_lib = detect_pkcs11_library(self._config.identity.pkcs11_library)
        pkcs11_slots: list[dict[str, Any]] = []
        pkcs11_error: str | None = None
        if pkcs11_lib is not None:
            try:
                pkcs11_slots = PKCS11Sealer(library_path=pkcs11_lib).list_slots()
            except Exception as exc:
                pkcs11_error = str(exc)

        keyring = self._identity_mgr.load_keyring()
        healthy = audit_ok and dream_ok and policy_ok and ("ML-KEM-768" in enabled_kems)
        return {
            "healthy": healthy,
            "schema_version": schema_v,
            "audit_chain": {"valid": audit_ok, "records": audit_count},
            "dream_queue_integrity": {"valid": dream_ok, "problems": dream_count},
            "policy_snapshots_integrity": {"valid": policy_ok, "snapshots": policy_count},
            "pqc_mechanisms": {
                "ml_kem_768": "ML-KEM-768" in enabled_kems,
                "ml_dsa_65": "ML-DSA-65" in enabled_sigs,
                "slh_dsa_128f": any("SLH" in s and "128F" in s.upper() for s in enabled_sigs),
            },
            "keyring": {
                "current_version": keyring.current_version,
                "current_key_id": keyring.current_key_id,
                "total_keys": len(keyring.keys),
            },
            "hardware_security": {
                "tpm2_device": str(tpm.device_path),
                "tpm2_device_exists": tpm.device_path.exists(),
                "tpm2_tools_installed": tpm.tools_installed(),
                "pkcs11_library": str(pkcs11_lib) if pkcs11_lib is not None else None,
                "pkcs11_slots": pkcs11_slots,
                "pkcs11_error": pkcs11_error,
            },
            "quantum_backends": get_backend_registry().available_backends(),
        }

    # ------------------------------------------------------------------
    # Full Live Configuration Center ("Configure Everything")
    # ------------------------------------------------------------------

    def get_config_bundle(self, redact_secrets: bool = True) -> dict[str, Any]:
        """Return active configuration, JSON schema, and YAML representation."""
        raw_dict: dict[str, Any] = orjson.loads(
            orjson.dumps(self._config.model_dump(mode="json"), default=str)
        )
        display_dict = _sanitize_config_dict(raw_dict) if redact_secrets else raw_dict
        yaml_str = yaml.safe_dump(display_dict, sort_keys=False)
        return {
            "config": display_dict,
            "yaml": yaml_str,
            "config_file_path": str(self._config_file_path),
            "schema": QAegisConfig.model_json_schema(),
            "available_quantum_backends": get_backend_registry().available_backends(),
        }

    async def update_config(
        self,
        patch: dict[str, Any],
        persist_yaml: bool = True,
        replace_full: bool = False,
    ) -> dict[str, Any]:
        """Validate, hot-apply across all subsystems, audit, and optionally persist config."""
        async with self._config_lock:
            current_raw: dict[str, Any] = orjson.loads(
                orjson.dumps(self._config.model_dump(mode="json"), default=str)
            )
            merged = dict(patch) if replace_full else _deep_merge(current_raw, patch)
            # Preserve existing auth_token if UI sent back the redacted placeholder
            dash_section = merged.get("dashboard")
            if (
                isinstance(dash_section, dict)
                and dash_section.get("auth_token") == _REDACTED_PLACEHOLDER
            ):
                dash_section["auth_token"] = self._config.dashboard.auth_token

            validated = QAegisConfig.model_validate(merged)
            await self._apply_live_config(validated)

            if persist_yaml:
                to_disk: dict[str, Any] = orjson.loads(
                    orjson.dumps(validated.model_dump(mode="json"), default=str)
                )
                await asyncio.to_thread(_atomic_write_yaml, self._config_file_path, to_disk)

            sanitized = _sanitize_config_dict(
                orjson.loads(orjson.dumps(validated.model_dump(mode="json"), default=str))
            )
            await self._storage.append_audit_event(
                event_type="config.updated",
                actor="dashboard",
                payload={
                    "persisted_yaml": persist_yaml,
                    "config_file": str(self._config_file_path),
                    "node_id": validated.node_id,
                },
            )
            await self._bus.publish(
                topic="config.updated",
                source="dashboard.config",
                payload={"persisted_yaml": persist_yaml, "config": sanitized},
            )
            return self.get_config_bundle(redact_secrets=True)

    async def update_config_from_yaml(
        self,
        yaml_text: str,
        persist_yaml: bool = True,
    ) -> dict[str, Any]:
        """Parse, validate, hot-apply, and persist a full YAML configuration document."""
        parsed = yaml.safe_load(yaml_text)
        if not isinstance(parsed, dict):
            raise ValueError("Configuration YAML root must be a mapping")
        return await self.update_config(parsed, persist_yaml=persist_yaml, replace_full=False)

    async def reset_default_config(self, persist_yaml: bool = True) -> dict[str, Any]:
        """Reset subsystem settings to defaults while preserving active runtime storage paths."""
        defaults = QAegisConfig(
            node_id=self._config.node_id,
            data_dir=self._config.data_dir,
            keys_dir=self._config.keys_dir,
            db_path=self._config.db_path,
            dashboard=self._config.dashboard,
        )
        raw: dict[str, Any] = orjson.loads(
            orjson.dumps(defaults.model_dump(mode="json"), default=str)
        )
        return await self.update_config(raw, persist_yaml=persist_yaml, replace_full=True)

    async def _apply_live_config(self, new_cfg: QAegisConfig) -> None:
        """Hot-reload subsystem runtime parameters in place without dropping connections."""
        (
            ident,
            reality_svc,
            chameleon_svc,
            compiler_svc,
            dreamer_svc,
            entropy_svc,
            _gossip_node,
        ) = self._require_services()

        prev_cfg = self._config
        self._config = new_cfg
        new_cfg.ensure_directories()

        if new_cfg.telemetry != prev_cfg.telemetry:
            configure_logging(new_cfg.telemetry)

        # Resize event ring buffer if limit changed
        if new_cfg.dashboard.event_history_limit != self._event_history.maxlen:
            self._event_history = deque(
                self._event_history,
                maxlen=new_cfg.dashboard.event_history_limit,
            )

        # IdentityManager config
        self._identity_mgr = IdentityManager(
            keys_dir=new_cfg.keys_dir,
            node_id=new_cfg.node_id,
            config=new_cfg.identity,
        )

        # Lifecycle config
        self._lifecycle._config = new_cfg.lifecycle

        # Bus runtime backpressure & timeout settings
        self._bus._config = self._bus._config.model_copy(
            update={
                "max_queue_size": new_cfg.bus.max_queue_size,
                "backpressure_policy": new_cfg.bus.backpressure_policy,
                "request_timeout_s": new_cfg.bus.request_timeout_s,
            }
        )

        # Module 1: RealityStamp
        if new_cfg.reality_stamp != prev_cfg.reality_stamp:
            reality_svc._config = new_cfg.reality_stamp
            reality_svc._qrng = MultiSourceQrng(
                config=new_cfg.reality_stamp,
                metrics=self._metrics,
            )

        # Module 2: Quantum Chameleon
        if new_cfg.chameleon_fw != prev_cfg.chameleon_fw:
            chameleon_svc._config = new_cfg.chameleon_fw
            chameleon_svc._detector = AdaptiveThreatDetector(config=new_cfg.chameleon_fw)
            chameleon_svc._crypto._config = new_cfg.chameleon_fw

        # Module 3: AI-to-Qubit Compiler
        if new_cfg.qubit_compiler != prev_cfg.qubit_compiler:
            compiler_svc._config = new_cfg.qubit_compiler
            compiler_svc._builder = NoiseAwareCircuitBuilder(
                noise_profile=BackendNoiseProfile(
                    two_qubit_error=new_cfg.qubit_compiler.backend_noise_level,
                    optimization_level=new_cfg.qubit_compiler.optimization_level,
                )
            )
            if (
                new_cfg.qubit_compiler.default_num_qubits
                != prev_cfg.qubit_compiler.default_num_qubits
                or new_cfg.qubit_compiler.encoder_hidden_dim
                != prev_cfg.qubit_compiler.encoder_hidden_dim
            ):
                compiler_svc._pipeline = AngleEncoderPipeline(
                    input_dim=compiler_svc._pipeline.input_dim,
                    num_qubits=new_cfg.qubit_compiler.default_num_qubits,
                    hidden_dim=new_cfg.qubit_compiler.encoder_hidden_dim,
                )

        # Module 4: Quantum Dreamer
        if new_cfg.quantum_dreamer != prev_cfg.quantum_dreamer:
            dreamer_svc._config = new_cfg.quantum_dreamer
            dreamer_svc._solver = QaoaSolver(config=new_cfg.quantum_dreamer)
            dreamer_svc._updater = PolicyUpdater(
                storage=self._storage,
                min_improvement=new_cfg.quantum_dreamer.min_policy_improvement,
                metrics=self._metrics,
            )

        # Module 5: Quantum Entropy
        if new_cfg.quantum_entropy != prev_cfg.quantum_entropy:
            entropy_svc._config = new_cfg.quantum_entropy
            entropy_svc._harvester = QuantumDistributionHarvester(
                config=new_cfg.quantum_entropy,
                metrics=self._metrics,
            )
            entropy_svc._ollama = OllamaQuantumBridge(config=new_cfg.quantum_entropy)

        del ident
        logger.info("dashboard_live_config_applied", node_id=new_cfg.node_id)

    # ------------------------------------------------------------------
    # Lifecycle, Identity, & Subsystem Interactive Control Plane Actions
    # ------------------------------------------------------------------

    async def set_lifecycle_mode(
        self, mode: str, reason: str = "dashboard_operator"
    ) -> dict[str, Any]:
        upper = mode.upper()
        if upper == "NIGHT":
            rec = await self._lifecycle.enter_night_mode(reason=reason)
        elif upper == "DAY":
            rec = await self._lifecycle.enter_day_mode(reason=reason)
        else:
            raise ValueError(f"Unsupported mode '{mode}'. Use DAY or NIGHT.")
        return rec.model_dump(mode="json")

    def get_identity_summary(self) -> dict[str, Any]:
        ident, *_rest = self._require_services()
        keyring = self._identity_mgr.load_keyring()
        return {
            "active_bundle": ident.public_bundle().model_dump(mode="json"),
            "keyring": keyring.model_dump(mode="json"),
            "secret_file": str(self._identity_mgr.secret_path),
            "sealed_file": str(self._identity_mgr.sealed_path),
            "sealed_exists": self._identity_mgr.sealed_path.is_file(),
            "public_file": str(self._identity_mgr.public_path),
        }

    async def rotate_identity_keys(
        self,
        seal_backend: str | None = None,
        token_label: str | None = None,
        user_pin: str | None = None,
        remove_plaintext: bool = False,
    ) -> dict[str, Any]:
        """Execute zero-downtime PQC key rotation and hot-rebind active services."""
        (
            _old_id,
            reality_svc,
            chameleon_svc,
            _compiler_svc,
            _dreamer_svc,
            _entropy_svc,
            gossip_node,
        ) = self._require_services()

        sealer: HardwareSealer | None = None
        if seal_backend and seal_backend != "none":
            sealer = create_sealer_from_config(
                self._config.identity,
                backend=seal_backend,
                token_label=token_label,
                user_pin=user_pin,
            )

        new_id, keyring = await asyncio.to_thread(
            self._identity_mgr.rotate_keys,
            sealer,
            self._metrics,
            remove_plaintext,
        )
        self._identity = new_id
        reality_svc._identity = new_id
        reality_svc._signer = RealitySigner(identity=new_id, metrics=self._metrics)
        chameleon_svc._identity = new_id
        chameleon_svc._crypto = CryptoAgilityEngine(
            identity=new_id,
            config=self._config.chameleon_fw,
            metrics=self._metrics,
        )
        gossip_node._identity = new_id
        gossip_node.register_trusted_keyring(keyring)

        await self._storage.append_audit_event(
            event_type="identity.rotated",
            actor="dashboard",
            payload={
                "new_key_id": new_id.key_id,
                "new_version": new_id.key_version,
                "sealed": seal_backend or "none",
            },
        )
        await self._bus.publish(
            topic="identity.rotated",
            source="dashboard.identity",
            payload={
                "key_id": new_id.key_id,
                "key_version": new_id.key_version,
                "keyring_entries": len(keyring.keys),
            },
        )
        return self.get_identity_summary()

    def export_cbom(self, fmt: str = "cyclonedx") -> dict[str, Any]:
        ident, *_rest = self._require_services()
        if fmt == "json":
            return self._identity_mgr.generate_cbom(ident).model_dump(mode="json")
        if fmt == "cyclonedx":
            return self._identity_mgr.generate_cyclonedx_cbom(ident)
        raise ValueError(f"Unsupported CBOM format '{fmt}'. Use 'json' or 'cyclonedx'.")

    # Module 1: Proof of Reality & Gossip
    async def list_reality_state(self) -> dict[str, Any]:
        _id, reality_svc, *_rest = self._require_services()
        leaves = await self._storage.list_merkle_leaves(limit=50)
        return {
            "merkle_root": reality_svc.merkle_root,
            "tree_size": reality_svc.tree_size,
            "recent_stamps": list(self._last_stamps),
            "persisted_leaves": leaves,
        }

    async def create_stamp(
        self,
        sensor_id: str,
        perception_label: str,
        confidence: float,
        metadata: dict[str, Any] | None = None,
        use_stateless_hash_sig: bool = False,
    ) -> dict[str, Any]:
        _id, reality_svc, *_rest = self._require_services()
        stamp = await reality_svc.stamp_perception(
            sensor_id=sensor_id,
            perception_label=perception_label,
            confidence=confidence,
            metadata=metadata or {},
            use_stateless_hash_sig=use_stateless_hash_sig,
        )
        return stamp.model_dump(mode="json")

    def verify_stamp_payload(self, stamp_dict: dict[str, Any]) -> dict[str, Any]:
        stamp = RealityStamp.model_validate(stamp_dict)
        keyring = self._identity_mgr.load_keyring()
        res = verify_reality_stamp(stamp, keyring=keyring, metrics=self._metrics)
        return res.model_dump(mode="json")

    async def harvest_qrng(self, num_bytes: int = 64) -> dict[str, Any]:
        _id, reality_svc, *_rest = self._require_services()
        batch = await reality_svc._qrng.harvest(num_bytes=num_bytes)
        return batch.model_dump(mode="json")

    async def get_gossip_state(self) -> dict[str, Any]:
        *_head, gossip_node = self._require_services()
        checkpoints = await self._storage.list_gossip_checkpoints()
        return {
            "node_id": gossip_node.node_id,
            "curve_public_key": gossip_node.curve_public_key,
            "latest_roots": {
                peer: {"tree_size": sz, "merkle_root": root}
                for peer, (sz, root) in gossip_node.latest_roots.items()
            },
            "equivocation_alerts": [
                a.model_dump(mode="json") for a in gossip_node.equivocation_alerts
            ],
            "checkpoints": checkpoints[:50],
        }

    async def sign_local_gossip_checkpoint(self) -> dict[str, Any]:
        _id, reality_svc, *_mid, gossip_node = self._require_services()
        env = gossip_node.create_checkpoint(reality_svc.merkle_root, reality_svc.tree_size)
        outcome = await gossip_node.ingest_checkpoint(env, rebroadcast=False)
        return {
            "checkpoint": env.model_dump(mode="json"),
            "outcome": outcome.model_dump(mode="json"),
        }

    # Module 2: Quantum Chameleon Firewall
    async def run_chameleon_protection(
        self,
        protocol: str,
        sensitivity: SensitivityTag,
        retention_years: float,
        payload_text: str,
        minimum_tier: str | None = None,
    ) -> dict[str, Any]:
        ident, _r, chameleon_svc, *_rest = self._require_services()
        if self._peer_sandbox_identity is None:
            raise RuntimeError("Sandbox peer identity unavailable")

        min_tier_enum = ThreatTier(minimum_tier) if minimum_tier else None
        payload_bytes = payload_text.encode("utf-8")
        obs = TrafficObservation(
            source=ident.node_id,
            destination=self._peer_sandbox_identity.node_id,
            protocol=protocol,
            sensitivity=sensitivity,
            payload_bytes=payload_bytes,
            long_term_retention_years=retention_years,
        )

        t0 = time.perf_counter()
        packet = await chameleon_svc.protect(
            obs,
            recipient=self._peer_sandbox_identity.public_bundle(),
            minimum_tier=min_tier_enum,
        )
        peer_engine = CryptoAgilityEngine(
            self._peer_sandbox_identity,
            config=self._config.chameleon_fw,
        )
        recovered = peer_engine.decrypt(
            packet.envelope,
            expected_sender_keyring=self._identity_mgr.load_keyring(),
        )
        roundtrip_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        wire_bytes = len(packet.envelope.model_dump_json().encode("utf-8"))

        return {
            "assessment": packet.assessment.model_dump(mode="json"),
            "envelope": packet.envelope.model_dump(mode="json"),
            "wire_size_bytes": wire_bytes,
            "roundtrip_verified": recovered == payload_bytes,
            "roundtrip_latency_ms": roundtrip_ms,
            "session_epoch": chameleon_svc.crypto_engine.session_epoch,
            "message_counter": chameleon_svc.crypto_engine.message_counter,
        }

    # Module 3: AI-to-Qubit Compiler
    async def compile_sensor_vector(
        self,
        vector: list[float],
        run_pennylane: bool = True,
    ) -> dict[str, Any]:
        _id, _r, _c, compiler_svc, *_rest = self._require_services()
        expected_dim = compiler_svc.pipeline.input_dim
        if len(vector) < expected_dim:
            padded = [*vector, *([0.0] * (expected_dim - len(vector)))]
        else:
            padded = vector[:expected_dim]

        t0 = time.perf_counter()
        angles, artifact, pl = await asyncio.to_thread(
            self._compile_sync,
            compiler_svc,
            padded,
            run_pennylane,
        )
        compile_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        await self._bus.publish(
            topic="compiler.circuit_ready",
            source="dashboard.compiler",
            payload={
                "num_qubits": artifact.num_qubits,
                "depth": artifact.depth,
                "estimated_fidelity": artifact.estimated_fidelity,
            },
        )
        return {
            "compile_latency_ms": compile_ms,
            "input_dim_used": expected_dim,
            "angles": angles.model_dump(mode="json"),
            "artifact": artifact.model_dump(mode="json"),
            "pennylane": pl.model_dump(mode="json") if pl is not None else None,
        }

    def _compile_sync(
        self,
        compiler_svc: QubitCompilerService,
        vec: list[float],
        run_pennylane: bool,
    ) -> tuple[Any, Any, Any]:
        angles = compiler_svc.pipeline.encode_to_angles(vec)
        _qc, artifact = compiler_svc.builder.build_qiskit_circuit(angles)
        pl = (
            compiler_svc.builder.run_pennylane_circuit(
                angles,
                noise_level=self._config.qubit_compiler.backend_noise_level,
            )
            if run_pennylane
            else None
        )
        return angles, artifact, pl

    async def train_and_export_autoencoder(
        self,
        epochs: int = 30,
        samples_count: int = 64,
        lr: float = 0.01,
    ) -> dict[str, Any]:
        _id, _r, _c, compiler_svc, *_rest = self._require_services()

        def _train_sync() -> dict[str, Any]:
            dim = compiler_svc.pipeline.input_dim
            rng = np.random.default_rng(42)
            samples = rng.normal(loc=0.5, scale=1.5, size=(samples_count, dim)).astype(np.float32)
            t0 = time.perf_counter()
            losses = compiler_svc.pipeline.train(samples, epochs=epochs, lr=lr)
            onnx_path = self._config.data_dir / "dashboard_angle_encoder.onnx"
            compiler_svc.pipeline.export_onnx(onnx_path)
            compiler_svc.pipeline.load_onnx(onnx_path)
            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            return {
                "epochs": epochs,
                "samples_count": samples_count,
                "input_dim": dim,
                "num_qubits": compiler_svc.pipeline.num_qubits,
                "initial_loss": round(losses[0], 6) if losses else 0.0,
                "final_loss": round(losses[-1], 6) if losses else 0.0,
                "loss_history": [round(v, 6) for v in losses],
                "onnx_path": str(onnx_path),
                "elapsed_ms": elapsed_ms,
            }

        res = await asyncio.to_thread(_train_sync)
        await self._bus.publish(
            topic="compiler.autoencoder_trained",
            source="dashboard.compiler",
            payload={"epochs": epochs, "final_loss": res["final_loss"]},
        )
        return res

    # Module 4: Quantum Dreamer
    async def list_dreamer_state(self) -> dict[str, Any]:
        problems = await self._storage.list_dream_problems(limit=50)
        policies = await self._storage.list_policy_snapshots(limit=30)
        return {
            "problems": [p.model_dump(mode="json") for p in problems],
            "policies": [s.model_dump(mode="json") for s in policies],
            "available_backends": get_backend_registry().available_backends(),
            "active_config": self._config.quantum_dreamer.model_dump(mode="json"),
        }

    async def enqueue_dream_problem(
        self,
        kind: str = "maxcut",
        priority: int = 70,
        policy_name: str = "edge_routing_policy",
        num_nodes: int = 4,
        edges: list[list[float]] | None = None,
        task_costs: list[float] | None = None,
        conflicts: list[list[int]] | None = None,
        target_active_tasks: int = 2,
        utilities: list[float] | None = None,
        costs: list[float] | None = None,
    ) -> dict[str, Any]:
        *_head, dreamer_svc, _entropy, _gossip = self._require_services()
        qubo: QuboProblem
        if kind == "maxcut":
            parsed_edges = (
                [(int(e[0]), int(e[1]), float(e[2])) for e in edges]
                if edges
                else [(i, (i + 1) % num_nodes, 1.0 + 0.5 * (i % 2)) for i in range(num_nodes)]
            )
            qubo = build_maxcut_qubo(num_nodes=num_nodes, weighted_edges=parsed_edges)
        elif kind == "scheduling":
            t_costs = task_costs or [1.2, 0.8, 1.5, 1.0]
            t_conf = [(int(c[0]), int(c[1])) for c in (conflicts or [[0, 1], [2, 3]])]
            qubo = build_task_scheduling_qubo(t_costs, t_conf, target_active_tasks)
        elif kind == "resource_allocation":
            u_vals = utilities or [4.0, 3.5, 5.0, 2.8]
            c_vals = costs or [1.0, 1.2, 1.5, 0.9]
            qubo = build_resource_allocation_qubo(u_vals, c_vals)
        else:
            raise ValueError(f"Unsupported problem kind '{kind}'")

        pid = await dreamer_svc.enqueue_day_problem(
            problem=qubo,
            priority=priority,
            policy_name=policy_name,
        )
        return {"problem_id": pid, "qubo": qubo.model_dump(mode="json")}

    async def run_night_cycle(
        self,
        max_problems: int = 8,
        backend_override: str | None = None,
        mitigation_override: str | None = None,
    ) -> dict[str, Any]:
        *_head, dreamer_svc, _entropy, _gossip = self._require_services()
        if backend_override or mitigation_override:
            patch_dream: dict[str, Any] = {}
            if backend_override:
                patch_dream["backend_type"] = backend_override
            if mitigation_override:
                patch_dream["mitigation_mode"] = mitigation_override
            await self.update_config({"quantum_dreamer": patch_dream}, persist_yaml=False)

        report = await dreamer_svc.run_night_cycle(max_problems=max_problems)
        return report.model_dump(mode="json")

    async def run_federated_demo(
        self,
        fleet_nodes: int = 3,
        budget_seconds: float = 120.0,
    ) -> dict[str, Any]:
        ident, *_mid, dreamer_svc, _entropy, _gossip = self._require_services()

        def _run_sync() -> dict[str, Any]:
            sched = FederatedScheduler(
                coordinator_identity=ident,
                solver=dreamer_svc.solver,
                max_qpu_seconds_per_night=budget_seconds,
            )
            base_edges = [(0, 1, 1.5), (1, 2, 1.0), (2, 3, 1.5), (3, 0, 1.0)]
            for idx in range(max(1, min(fleet_nodes, 8))):
                # Relabel nodes on alternating edge drones to exercise exact isomorphism dedup
                if idx % 2 == 0:
                    q = build_maxcut_qubo(4, base_edges)
                else:
                    perm = [1, 2, 3, 0]
                    relabeled = [(perm[u], perm[v], w) for u, v, w in base_edges]
                    q = build_maxcut_qubo(4, relabeled)
                sched.submit(
                    FederatedJobSubmission(
                        node_id=f"edge-drone-0{idx + 1}",
                        policy_name="fleet_mesh_routing",
                        priority=90 - idx * 5,
                        estimated_qpu_seconds=2.0,
                        qubo=q,
                    )
                )
            rep = sched.run_federated_cycle()
            return rep.model_dump(mode="json")

        result = await asyncio.to_thread(_run_sync)
        await self._bus.publish(
            topic="dreamer.federated_cycle_completed",
            source="dashboard.federated",
            payload={
                "submissions": result["submissions_received"],
                "unique_solved": result["unique_problems_solved"],
                "deduplicated": result["deduplicated_count"],
            },
        )
        return result

    # Module 5: Quantum Entropy & Audit / Metrics
    async def harvest_entropy_batch(
        self,
        num_qubits: int | None = None,
        shots: int | None = None,
        noise_rate: float = 0.01,
    ) -> dict[str, Any]:
        *_head, entropy_svc, _gossip = self._require_services()
        batch, _pool = await entropy_svc.harvest(
            num_qubits=num_qubits,
            shots=shots,
            noise_rate=noise_rate,
        )
        return batch.model_dump(mode="json")

    async def sample_quantum_logits(
        self,
        logits: list[float],
        temperature: float = 0.8,
        top_k: int = 40,
        top_p: float = 0.9,
    ) -> dict[str, Any]:
        *_head, entropy_svc, _gossip = self._require_services()
        res = await entropy_svc.sample_logits(
            logits=logits,
            temperature=temperature,
            top_k=top_k,
            top_p=top_p,
        )
        return res.model_dump(mode="json")

    async def run_quantum_evolution(
        self,
        genome_dim: int = 6,
        population_size: int = 12,
        generations: int = 20,
    ) -> dict[str, Any]:
        *_head, entropy_svc, _gossip = self._require_services()
        if entropy_svc._pool is None:
            _b, entropy_svc._pool = await entropy_svc.harvester.harvest_batch()
        pool: QuantumEntropyPool = entropy_svc._pool

        def _evolve_sync() -> dict[str, Any]:
            mut = QuantumEvolutionaryMutator(pool=pool, mutation_sigma=0.25)
            target = [0.75 * ((-1) ** i) for i in range(genome_dim)]
            res = mut.evolve(
                initial_genome=[0.0] * genome_dim,
                fitness_fn=lambda g: -sum((g[i] - target[i]) ** 2 for i in range(genome_dim)),
                population_size=population_size,
                generations=generations,
            )
            return {"target": target, **res.model_dump(mode="json")}

        return await asyncio.to_thread(_evolve_sync)

    async def check_ollama_status(self) -> dict[str, Any]:
        *_head, entropy_svc, _gossip = self._require_services()
        reachable, models = await entropy_svc.ollama.check_health()
        return {
            "reachable": reachable,
            "endpoint": self._config.quantum_entropy.ollama_base_url,
            "configured_model": self._config.quantum_entropy.ollama_model,
            "available_models": models,
        }

    async def list_audit_ledger(self, limit: int = 100) -> dict[str, Any]:
        valid, total_count = await self._storage.verify_audit_chain()
        records = await self._storage.list_audit_events(limit=limit)
        return {
            "chain_valid": valid,
            "total_records": total_count,
            "events": [r.model_dump(mode="json") for r in records],
        }

    def render_prometheus_metrics(self) -> str:
        return self._metrics.render_prometheus_text().decode("utf-8", errors="replace")
