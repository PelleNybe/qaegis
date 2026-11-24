"""Event-bus integrated AI-to-Qubit Compiler Service."""

from __future__ import annotations

from typing import Any

from qaegis.core.bus import EventBus, EventEnvelope
from qaegis.core.config import QubitCompilerConfig
from qaegis.core.telemetry import get_logger
from qaegis.modules.qubit_compiler.autoencoder import AngleEncoderPipeline, QuantumAnglePayload
from qaegis.modules.qubit_compiler.circuit_builder import (
    BackendNoiseProfile,
    CompiledCircuitArtifact,
    NoiseAwareCircuitBuilder,
    PennyLaneExecutionResult,
)
from qaegis.modules.qubit_compiler.qubo_mapper import (
    QuboProblem,
    build_maxcut_qubo,
    build_resource_allocation_qubo,
    build_task_scheduling_qubo,
)

logger = get_logger(__name__)


class QubitCompilerService:
    """Compiles numeric edge sensor tensors into OpenQASM 3.0 circuits and QUBO formulations."""

    def __init__(
        self,
        bus: EventBus,
        input_dim: int = 16,
        config: QubitCompilerConfig | None = None,
    ) -> None:
        self._bus = bus
        self._config = config or QubitCompilerConfig()
        self._pipeline = AngleEncoderPipeline(
            input_dim=input_dim,
            num_qubits=self._config.default_num_qubits,
            hidden_dim=self._config.encoder_hidden_dim,
        )
        self._builder = NoiseAwareCircuitBuilder(
            noise_profile=BackendNoiseProfile(
                two_qubit_error=self._config.backend_noise_level,
                optimization_level=self._config.optimization_level,
            )
        )

    @property
    def pipeline(self) -> AngleEncoderPipeline:
        return self._pipeline

    @property
    def builder(self) -> NoiseAwareCircuitBuilder:
        return self._builder

    async def start(self) -> None:
        """Register AI-to-Qubit Compiler RPC responders on the EventBus."""
        self._bus.register_responder("compiler.compile_tensor", self._handle_compile_rpc)
        self._bus.register_responder("compiler.build_qubo", self._handle_qubo_rpc)
        logger.info(
            "qubit_compiler_service_started",
            num_qubits=self._config.default_num_qubits,
        )

    async def compile_sensor_vector(
        self,
        vector: list[float],
        run_pennylane: bool = True,
    ) -> tuple[QuantumAnglePayload, CompiledCircuitArtifact, PennyLaneExecutionResult | None]:
        """Encode sensor vector -> bounded rotation angles -> OpenQASM 3.0 + PennyLane probs."""
        angles = self._pipeline.encode_to_angles(vector)
        _qc, artifact = self._builder.build_qiskit_circuit(angles)
        pl_result = (
            self._builder.run_pennylane_circuit(
                angles,
                noise_level=self._config.backend_noise_level,
            )
            if run_pennylane
            else None
        )
        await self._bus.publish(
            topic="compiler.circuit_ready",
            source="modules.qubit_compiler",
            payload={
                "num_qubits": artifact.num_qubits,
                "depth": artifact.depth,
                "estimated_fidelity": artifact.estimated_fidelity,
            },
        )
        return angles, artifact, pl_result

    async def _handle_compile_rpc(self, envelope: EventEnvelope) -> dict[str, Any]:
        vec = [float(v) for v in envelope.payload["vector"]]
        angles, artifact, pl = await self.compile_sensor_vector(vec)
        return {
            "angles": angles.model_dump(mode="json"),
            "artifact": artifact.model_dump(mode="json"),
            "pennylane": pl.model_dump(mode="json") if pl is not None else None,
        }

    async def _handle_qubo_rpc(self, envelope: EventEnvelope) -> dict[str, Any]:
        p = envelope.payload
        kind = str(p.get("problem_type", "maxcut"))
        qubo: QuboProblem
        if kind == "maxcut":
            edges = [(int(u), int(v), float(w)) for u, v, w in p["edges"]]
            qubo = build_maxcut_qubo(int(p["num_nodes"]), edges)
        elif kind == "scheduling":
            costs = [float(c) for c in p["task_costs"]]
            conflicts = [(int(u), int(v)) for u, v in p.get("conflicts", [])]
            qubo = build_task_scheduling_qubo(costs, conflicts, int(p["target_active_tasks"]))
        elif kind == "resource_allocation":
            utilities = [float(u) for u in p["utilities"]]
            costs = [float(c) for c in p["costs"]]
            penalty = float(p.get("budget_penalty", 1.5))
            qubo = build_resource_allocation_qubo(utilities, costs, budget_penalty=penalty)
        else:
            raise ValueError(f"Unsupported QUBO problem_type: {kind}")
        return qubo.model_dump(mode="json")
