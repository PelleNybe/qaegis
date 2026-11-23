"""Validated local AI policy weight updater with automatic rollback guard."""

from __future__ import annotations

from collections.abc import Callable

from pydantic import BaseModel

from qaegis.core.storage import StorageEngine
from qaegis.core.telemetry import QAegisMetrics, get_logger
from qaegis.modules.quantum_dreamer.solvers import QaoaSolution

logger = get_logger(__name__)

PolicyScorer = Callable[[dict[str, float]], float]


class PolicyUpdateResult(BaseModel):
    """Audited outcome of evaluating and applying or rolling back a Night-Mode policy update."""

    policy_name: str
    source_problem_id: str
    applied: bool
    rolled_back: bool
    candidate_score: float
    baseline_score: float
    improvement: float
    active_version: int
    candidate_weights: dict[str, float]
    reason: str


def bitstring_to_policy_weights(
    bitstring: str,
    base_weights: dict[str, float] | None = None,
    learning_rate: float = 0.25,
) -> dict[str, float]:
    """Blend a QAOA optimal binary decision vector into continuous local AI policy weights."""
    n = len(bitstring)
    current = base_weights or {f"w_{i}": 0.5 for i in range(n)}
    updated: dict[str, float] = {}
    for i, ch in enumerate(bitstring):
        key = f"w_{i}"
        prev_val = float(current.get(key, 0.5))
        target = 1.0 if ch == "1" else 0.0
        updated[key] = round((1.0 - learning_rate) * prev_val + learning_rate * target, 6)
    return updated


class PolicyUpdater:
    """Applies Night-Mode quantum-optimized weights only when held-out validation improves."""

    def __init__(
        self,
        storage: StorageEngine,
        min_improvement: float = 0.01,
        metrics: QAegisMetrics | None = None,
    ) -> None:
        self._storage = storage
        self._min_improvement = min_improvement
        self._metrics = metrics or QAegisMetrics()

    async def evaluate_and_update(
        self,
        policy_name: str,
        solution: QaoaSolution,
        scorer: PolicyScorer,
        learning_rate: float = 0.35,
    ) -> PolicyUpdateResult:
        """Score candidate policy weights against active baseline and rollback if regressed."""
        active_snap = await self._storage.get_active_policy(policy_name)
        n = len(solution.optimal_bitstring)
        baseline_weights = (
            active_snap.weights if active_snap is not None else {f"w_{i}": 0.5 for i in range(n)}
        )
        baseline_score = float(scorer(baseline_weights))

        # Ensure initial baseline snapshot exists in storage for rollback lineage
        if active_snap is None:
            active_snap = await self._storage.save_policy_snapshot(
                policy_name=policy_name,
                weights=baseline_weights,
                validation_score=baseline_score,
                baseline_score=baseline_score,
                active=True,
                source_problem_id=None,
            )

        candidate_weights = bitstring_to_policy_weights(
            solution.optimal_bitstring,
            base_weights=baseline_weights,
            learning_rate=learning_rate,
        )
        candidate_score = float(scorer(candidate_weights))
        improvement = candidate_score - baseline_score

        if improvement >= self._min_improvement:
            new_snap = await self._storage.save_policy_snapshot(
                policy_name=policy_name,
                weights=candidate_weights,
                validation_score=candidate_score,
                baseline_score=baseline_score,
                active=True,
                source_problem_id=solution.problem_id,
            )
            await self._storage.append_audit_event(
                event_type="policy.updated",
                actor="quantum_dreamer",
                payload={
                    "policy_name": policy_name,
                    "version": new_snap.version,
                    "baseline_score": baseline_score,
                    "candidate_score": candidate_score,
                    "problem_id": solution.problem_id,
                },
            )
            self._metrics.dreamer_policy_updates.labels(outcome="applied").inc()
            logger.info(
                "policy_update_applied",
                policy_name=policy_name,
                version=new_snap.version,
                improvement=round(improvement, 4),
            )
            return PolicyUpdateResult(
                policy_name=policy_name,
                source_problem_id=solution.problem_id,
                applied=True,
                rolled_back=False,
                candidate_score=candidate_score,
                baseline_score=baseline_score,
                improvement=improvement,
                active_version=new_snap.version,
                candidate_weights=candidate_weights,
                reason="validation_improved",
            )

        # Record rejected candidate snapshot with active=False so baseline remains active
        await self._storage.save_policy_snapshot(
            policy_name=policy_name,
            weights=candidate_weights,
            validation_score=candidate_score,
            baseline_score=baseline_score,
            active=False,
            source_problem_id=solution.problem_id,
        )
        await self._storage.append_audit_event(
            event_type="policy.rollback_guarded",
            actor="quantum_dreamer",
            payload={
                "policy_name": policy_name,
                "active_version": active_snap.version,
                "baseline_score": baseline_score,
                "candidate_score": candidate_score,
                "problem_id": solution.problem_id,
            },
        )
        self._metrics.dreamer_policy_updates.labels(outcome="rolled_back").inc()
        logger.warning(
            "policy_update_rolled_back",
            policy_name=policy_name,
            active_version=active_snap.version,
            improvement=round(improvement, 4),
        )
        return PolicyUpdateResult(
            policy_name=policy_name,
            source_problem_id=solution.problem_id,
            applied=False,
            rolled_back=True,
            candidate_score=candidate_score,
            baseline_score=baseline_score,
            improvement=improvement,
            active_version=active_snap.version,
            candidate_weights=candidate_weights,
            reason=f"improvement {improvement:.4f} below threshold {self._min_improvement:.4f}",
        )
