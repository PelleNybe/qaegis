"""Quantum Dreaming Async Day/Night Service coordinating queuing, QAOA solving, and updates."""

from __future__ import annotations

import asyncio
from typing import Any

from pydantic import BaseModel

from qaegis.core.bus import EventBus, EventEnvelope
from qaegis.core.config import QuantumDreamerConfig
from qaegis.core.lifecycle import LifecycleManager, ModeTransitionRecord
from qaegis.core.storage import StorageEngine
from qaegis.core.telemetry import QAegisMetrics, get_logger
from qaegis.modules.quantum_dreamer.policy_updater import (
    PolicyScorer,
    PolicyUpdater,
    PolicyUpdateResult,
)
from qaegis.modules.quantum_dreamer.problem_queue import DreamProblemQueue
from qaegis.modules.quantum_dreamer.solvers import QaoaSolution, QaoaSolver, QuantumBackend
from qaegis.modules.qubit_compiler.qubo_mapper import QuboProblem, evaluate_qubo

logger = get_logger(__name__)


class NightCycleReport(BaseModel):
    """Summary emitted at the completion of a Night-Mode Quantum Dreaming batch."""

    problems_processed: int
    solutions: list[QaoaSolution]
    policy_updates: list[PolicyUpdateResult]


def _default_qubo_policy_scorer(problem: QuboProblem) -> PolicyScorer:
    """Create a deterministic held-out scorer mapping continuous weights to negative QUBO energy."""

    def _score(weights: dict[str, float]) -> float:
        bits = "".join(
            "1" if weights.get(f"w_{i}", 0.5) >= 0.5 else "0" for i in range(problem.num_variables)
        )
        # Also reward continuous alignment with the low-energy discrete solution
        discrete_e = evaluate_qubo(problem, bits)
        # Continuous quadratic objective x^T Q x + c evaluated at continuous weights
        vec = [float(weights.get(f"w_{i}", 0.5)) for i in range(problem.num_variables)]
        cont_e = problem.constant_offset
        for i in range(problem.num_variables):
            for j in range(problem.num_variables):
                cont_e += problem.matrix[i][j] * vec[i] * vec[j]
        return float(-(0.5 * discrete_e + 0.5 * cont_e))

    return _score


class QuantumDreamerService:
    """Collects hard problems in Day Mode and solves them via QAOA during Night Mode."""

    def __init__(
        self,
        bus: EventBus,
        storage: StorageEngine,
        lifecycle: LifecycleManager,
        config: QuantumDreamerConfig | None = None,
        backend: QuantumBackend | None = None,
        metrics: QAegisMetrics | None = None,
    ) -> None:
        self._bus = bus
        self._storage = storage
        self._lifecycle = lifecycle
        self._config = config or QuantumDreamerConfig()
        self._metrics = metrics or QAegisMetrics()
        self._queue = DreamProblemQueue(storage)
        self._solver = QaoaSolver(config=self._config, backend=backend)
        self._updater = PolicyUpdater(
            storage=storage,
            min_improvement=self._config.min_policy_improvement,
            metrics=self._metrics,
        )
        self._custom_scorers: dict[str, PolicyScorer] = {}

    @property
    def queue(self) -> DreamProblemQueue:
        return self._queue

    @property
    def solver(self) -> QaoaSolver:
        return self._solver

    @property
    def updater(self) -> PolicyUpdater:
        return self._updater

    def register_policy_scorer(self, policy_name: str, scorer: PolicyScorer) -> None:
        """Register a held-out validation scorer for a named AI policy."""
        self._custom_scorers[policy_name] = scorer

    async def start(self) -> None:
        """Bind Night-Mode lifecycle hook and EventBus RPC endpoints."""
        self._lifecycle.register_night_hook(self._on_enter_night)
        self._bus.register_responder("dreamer.enqueue", self._handle_enqueue_rpc)
        self._bus.register_responder("dreamer.run_night_cycle", self._handle_run_night_rpc)
        logger.info("quantum_dreamer_service_started", backend=self._solver.backend.name)

    async def enqueue_day_problem(
        self,
        problem: QuboProblem,
        priority: int = 50,
        policy_name: str = "edge_routing_policy",
    ) -> str:
        """Queue a Day-Mode problem with zero blocking quantum execution."""
        rec = await self._queue.enqueue(
            problem=problem,
            priority=priority,
            metadata={"policy_name": policy_name},
        )
        await self._bus.publish(
            topic="dreamer.problem_queued",
            source="modules.quantum_dreamer",
            payload={"problem_id": rec.problem_id, "priority": rec.priority},
        )
        return rec.problem_id

    async def run_night_cycle(self, max_problems: int = 16) -> NightCycleReport:
        """Drain pending Day-Mode problems, execute QAOA, and validate local policy updates."""
        batch = await self._queue.fetch_next_batch(limit=max_problems)
        solutions: list[QaoaSolution] = []
        updates: list[PolicyUpdateResult] = []

        for record, qubo in batch:
            try:
                # Offload CPU-bound Qiskit QAOA optimization to a worker thread
                sol = await asyncio.to_thread(self._solver.solve, qubo)
                await self._queue.mark_solved(qubo.problem_id, sol.model_dump(mode="json"))
                self._metrics.dreamer_qaoa_solves.labels(
                    backend=sol.backend_name,
                    status="success",
                ).inc()
                solutions.append(sol)

                policy_name = str(record.metadata.get("policy_name", "edge_routing_policy"))
                scorer = self._custom_scorers.get(policy_name) or _default_qubo_policy_scorer(qubo)
                upd = await self._updater.evaluate_and_update(
                    policy_name=policy_name,
                    solution=sol,
                    scorer=scorer,
                )
                updates.append(upd)
            except Exception as exc:
                await self._queue.mark_failed(qubo.problem_id, str(exc))
                self._metrics.dreamer_qaoa_solves.labels(
                    backend=self._solver.backend.name,
                    status="failed",
                ).inc()
                logger.exception("dreamer_qaoa_solve_failed", problem_id=qubo.problem_id)

        report = NightCycleReport(
            problems_processed=len(batch),
            solutions=solutions,
            policy_updates=updates,
        )
        await self._bus.publish(
            topic="dreamer.night_cycle_completed",
            source="modules.quantum_dreamer",
            payload=report.model_dump(mode="json"),
        )
        return report

    async def _on_enter_night(self, transition: ModeTransitionRecord) -> None:
        logger.info("quantum_dreamer_night_hook_triggered", reason=transition.reason)
        await self.run_night_cycle()

    async def _handle_enqueue_rpc(self, envelope: EventEnvelope) -> dict[str, Any]:
        p = envelope.payload
        qubo = QuboProblem.model_validate(p["qubo"])
        pid = await self.enqueue_day_problem(
            problem=qubo,
            priority=int(p.get("priority", 50)),
            policy_name=str(p.get("policy_name", "edge_routing_policy")),
        )
        return {"problem_id": pid, "status": "PENDING"}

    async def _handle_run_night_rpc(self, envelope: EventEnvelope) -> dict[str, Any]:
        max_n = int(envelope.payload.get("max_problems", 16))
        report = await self.run_night_cycle(max_problems=max_n)
        return report.model_dump(mode="json")
