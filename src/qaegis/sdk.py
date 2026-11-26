"""High-level ergonomic Python SDK facade (`QAegisClient`) for embedding Q-Aegis in applications."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from qaegis.core.bus import EventBus
from qaegis.core.config import QAegisConfig, RealityStampConfig, load_config
from qaegis.core.identity import (
    DeviceIdentity,
    IdentityManager,
    PublicIdentityBundle,
    TrustKeyring,
)
from qaegis.core.lifecycle import LifecycleManager
from qaegis.core.storage import StorageEngine
from qaegis.core.telemetry import QAegisMetrics
from qaegis.modules.chameleon_fw.crypto_agility import EncryptedEnvelope
from qaegis.modules.chameleon_fw.detector import ThreatTier
from qaegis.modules.chameleon_fw.features import SensitivityTag, TrafficObservation
from qaegis.modules.chameleon_fw.service import ChameleonFirewallService, ProtectedPacket
from qaegis.modules.quantum_dreamer.service import QuantumDreamerService
from qaegis.modules.quantum_dreamer.solvers import QaoaSolution, QaoaSolver
from qaegis.modules.quantum_entropy.harvester import QuantumDistributionBatch, QuantumEntropyPool
from qaegis.modules.quantum_entropy.service import QuantumEntropyService
from qaegis.modules.qubit_compiler.autoencoder import QuantumAnglePayload
from qaegis.modules.qubit_compiler.circuit_builder import (
    CompiledCircuitArtifact,
    PennyLaneExecutionResult,
)
from qaegis.modules.qubit_compiler.qubo_mapper import build_maxcut_qubo
from qaegis.modules.qubit_compiler.service import QubitCompilerService
from qaegis.modules.reality_stamp.service import RealityStampService
from qaegis.modules.reality_stamp.signer import (
    ArtifactSignatureBundle,
    ArtifactVerificationResult,
    RealityStamp,
    StampVerificationResult,
    sign_artifact_file,
    verify_artifact_file,
    verify_reality_stamp,
)


class QAegisClient:
    """Batteries-included async Python SDK unifying PQC signing, hybrid encryption, AI & QAOA.

    Example:
        ```python
        from qaegis import QAegisClient

        async with QAegisClient("./my_qaegis_state") as client:
            stamp = await client.stamp("cam-01", "person_detected", 0.98)
            sig = await client.sign_file("model.onnx")
            enc = client.encrypt(b"secret-key", tier=ThreatTier.QUANTUM_CRITICAL)
            plain = client.decrypt(enc)
        ```
    """

    def __init__(
        self,
        workspace_dir: Path | str | None = None,
        config: QAegisConfig | None = None,
        config_path: Path | str | None = None,
        strict_nist_checks: bool = False,
    ) -> None:
        if config is not None:
            self._config = config
        elif config_path is not None:
            self._config = load_config(config_path)
        else:
            root = Path(workspace_dir) if workspace_dir is not None else Path("./.qaegis")
            self._config = QAegisConfig(
                data_dir=root / "data",
                keys_dir=root / "keys",
                db_path=root / "data" / "qaegis.db",
                reality_stamp=RealityStampConfig(strict_nist_checks=strict_nist_checks),
            )

        self._metrics = QAegisMetrics()
        self._bus = EventBus(config=self._config.bus, metrics=self._metrics)
        self._storage = StorageEngine(self._config.db_path)
        self._lifecycle = LifecycleManager(
            bus=self._bus,
            config=self._config.lifecycle,
            metrics=self._metrics,
        )
        self._identity_mgr = IdentityManager(
            keys_dir=self._config.keys_dir,
            node_id=self._config.node_id,
            config=self._config.identity,
        )
        self._identity: DeviceIdentity | None = None
        self._reality: RealityStampService | None = None
        self._chameleon: ChameleonFirewallService | None = None
        self._compiler: QubitCompilerService | None = None
        self._dreamer: QuantumDreamerService | None = None
        self._entropy: QuantumEntropyService | None = None
        self._started = False

    @property
    def config(self) -> QAegisConfig:
        return self._config

    @property
    def identity(self) -> DeviceIdentity:
        if self._identity is None:
            raise RuntimeError("QAegisClient is not started; use `async with QAegisClient(...)`")
        return self._identity

    @property
    def public_bundle(self) -> PublicIdentityBundle:
        return self.identity.public_bundle()

    @property
    def keyring(self) -> TrustKeyring:
        return self._identity_mgr.load_keyring()

    async def start(self) -> QAegisClient:
        """Initialize directories, PQC identity, SQLite WAL, EventBus, and all 5 subsystems."""
        if self._started:
            return self
        self._config.ensure_directories()
        self._identity = self._identity_mgr.load_or_create()
        await self._bus.start()
        await self._storage.initialize()

        self._reality = RealityStampService(
            bus=self._bus,
            identity=self._identity,
            storage=self._storage,
            config=self._config.reality_stamp,
            metrics=self._metrics,
        )
        self._chameleon = ChameleonFirewallService(
            bus=self._bus,
            identity=self._identity,
            config=self._config.chameleon_fw,
            metrics=self._metrics,
        )
        self._compiler = QubitCompilerService(
            bus=self._bus,
            config=self._config.qubit_compiler,
        )
        self._dreamer = QuantumDreamerService(
            bus=self._bus,
            storage=self._storage,
            lifecycle=self._lifecycle,
            config=self._config.quantum_dreamer,
            metrics=self._metrics,
        )
        self._entropy = QuantumEntropyService(
            bus=self._bus,
            config=self._config.quantum_entropy,
            metrics=self._metrics,
        )

        await self._reality.start()
        await self._chameleon.start()
        await self._compiler.start()
        await self._dreamer.start()
        await self._entropy.start()
        self._started = True
        return self

    async def close(self) -> None:
        """Shut down all services, SQLite WAL connection, and EventBus cleanly."""
        if not self._started:
            return
        self._started = False
        await self._lifecycle.shutdown()
        if self._reality is not None:
            await self._reality.stop()
        await self._storage.close()
        await self._bus.stop()

    async def __aenter__(self) -> QAegisClient:
        return await self.start()

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()

    # 1. Proof of Reality & Post-Quantum File Signing
    async def stamp(
        self,
        sensor_id: str,
        label: str,
        confidence: float = 1.0,
        metadata: dict[str, Any] | None = None,
        stateless: bool = False,
    ) -> RealityStamp:
        """Sign an Edge-AI perception event with QRNG entropy, ML-DSA/SLH-DSA, and Merkle proof."""
        if self._reality is None:
            raise RuntimeError("QAegisClient is not started")
        return await self._reality.stamp_perception(
            sensor_id=sensor_id,
            perception_label=label,
            confidence=confidence,
            metadata=metadata,
            use_stateless_hash_sig=stateless,
        )

    def verify_stamp(self, stamp: RealityStamp) -> StampVerificationResult:
        """Verify a RealityStamp against this node's historical TrustKeyring and Merkle proof."""
        return verify_reality_stamp(stamp, keyring=self.keyring, metrics=self._metrics)

    async def sign_file(
        self,
        file_path: Path | str,
        stateless: bool = False,
        annotations: dict[str, Any] | None = None,
    ) -> ArtifactSignatureBundle:
        """Sign any file (model weights, SBOM, firmware, archive) with QRNG + ML-DSA-65/SLH-DSA."""
        if self._reality is None:
            raise RuntimeError("QAegisClient is not started")
        qrng = await self._reality._qrng.harvest(num_bytes=32)
        target = Path(file_path)
        return await asyncio.to_thread(
            sign_artifact_file,
            target,
            self.identity,
            stateless,
            qrng.raw_hex,
            annotations,
        )

    def verify_file(
        self,
        file_path: Path | str,
        signature_bundle: ArtifactSignatureBundle,
        use_keyring: bool = True,
    ) -> ArtifactVerificationResult:
        """Verify a file on disk against its detached post-quantum ArtifactSignatureBundle."""
        return verify_artifact_file(
            Path(file_path),
            signature_bundle,
            keyring=self.keyring if use_keyring else None,
        )

    # 2. Quantum Chameleon Hybrid Encryption & AI Firewall
    def encrypt(
        self,
        plaintext: bytes,
        recipient: PublicIdentityBundle | None = None,
        tier: ThreatTier = ThreatTier.QUANTUM_CRITICAL,
        associated_data: bytes = b"",
    ) -> EncryptedEnvelope:
        """Encrypt `plaintext` using X25519 + ML-KEM-768 + AES-256-GCM (+ ML-DSA-65 in CRITICAL)."""
        if self._chameleon is None:
            raise RuntimeError("QAegisClient is not started")
        target_recipient = recipient or self.public_bundle
        return self._chameleon.crypto_engine.encrypt(
            plaintext=plaintext,
            recipient=target_recipient,
            tier=tier,
            associated_data=associated_data,
        )

    def decrypt(
        self,
        envelope: EncryptedEnvelope,
        expected_sender: PublicIdentityBundle | None = None,
        use_local_keyring: bool = False,
    ) -> bytes:
        """Verify and decrypt an `EncryptedEnvelope` with replay & tamper protection."""
        if self._chameleon is None:
            raise RuntimeError("QAegisClient is not started")
        return self._chameleon.unprotect(
            envelope=envelope,
            expected_sender=expected_sender,
            expected_sender_keyring=self.keyring if use_local_keyring else None,
        )

    async def protect(
        self,
        payload: bytes,
        recipient: PublicIdentityBundle | None = None,
        protocol: str = "wan",
        sensitivity: SensitivityTag = "confidential",
        retention_years: float = 5.0,
    ) -> ProtectedPacket:
        """Run AI anomaly + HNDL risk classification and dynamically encrypt `payload`."""
        if self._chameleon is None:
            raise RuntimeError("QAegisClient is not started")
        obs = TrafficObservation(
            source=self.identity.node_id,
            destination=(recipient or self.public_bundle).node_id,
            protocol=protocol,
            sensitivity=sensitivity,
            payload_bytes=payload,
            long_term_retention_years=retention_years,
        )
        return await self._chameleon.protect(obs, recipient=recipient or self.public_bundle)

    # 3. AI-to-Qubit Compiler
    async def compile_tensor(
        self,
        vector: list[float],
        run_pennylane: bool = True,
    ) -> tuple[QuantumAnglePayload, CompiledCircuitArtifact, PennyLaneExecutionResult | None]:
        """Compile a numeric feature vector into bounded angles, OpenQASM 3.0 & PennyLane."""
        if self._compiler is None:
            raise RuntimeError("QAegisClient is not started")
        expected = self._compiler.pipeline.input_dim
        padded = [*vector, *([0.0] * max(0, expected - len(vector)))][:expected]
        return await self._compiler.compile_sensor_vector(padded, run_pennylane=run_pennylane)

    # 4. Quantum Dreamer QAOA
    async def solve_maxcut(
        self,
        num_nodes: int,
        weighted_edges: list[tuple[int, int, float]],
        backend: str | None = None,
        mitigation: str | None = None,
    ) -> QaoaSolution:
        """Solve a weighted Max-Cut routing problem via QAOA with optional ZNE/TREX mitigation."""
        qubo = build_maxcut_qubo(num_nodes=num_nodes, weighted_edges=weighted_edges)
        cfg = self._config.quantum_dreamer.model_copy(
            update={
                k: v
                for k, v in {
                    "backend_type": backend,
                    "mitigation_mode": mitigation,
                }.items()
                if v is not None
            }
        )
        solver = QaoaSolver(config=cfg)
        return await asyncio.to_thread(solver.solve, qubo)

    # 5. Quantum Entropy Pool
    async def random_bytes(self, num_bytes: int = 64) -> bytes:
        """Return verified quantum-harvested random bytes (entangled circuit XOR QRNG)."""
        if self._entropy is None:
            raise RuntimeError("QAegisClient is not started")
        if self._entropy._pool is None:
            _batch, self._entropy._pool = await self._entropy.harvest()
        pool: QuantumEntropyPool = self._entropy._pool
        return pool.next_bytes(num_bytes)

    async def harvest_entropy(
        self,
        num_qubits: int = 6,
        shots: int = 512,
    ) -> QuantumDistributionBatch:
        """Harvest a fresh entangled quantum measurement distribution and refresh the pool."""
        if self._entropy is None:
            raise RuntimeError("QAegisClient is not started")
        batch, _pool = await self._entropy.harvest(num_qubits=num_qubits, shots=shots)
        return batch
