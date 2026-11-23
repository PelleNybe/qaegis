"""Day-Mode combinatorial problem collector and priority queue backed by SQLite WAL."""

from __future__ import annotations

from typing import Any

from qaegis.core.storage import DreamProblemRecord, StorageEngine
from qaegis.modules.qubit_compiler.qubo_mapper import QuboProblem


class DreamProblemQueue:
    """Persists and prioritizes combinatorial optimization problems for Night-Mode QAOA solving."""

    def __init__(self, storage: StorageEngine) -> None:
        self._storage = storage

    async def enqueue(
        self,
        problem: QuboProblem,
        priority: int = 50,
        metadata: dict[str, Any] | None = None,
    ) -> DreamProblemRecord:
        """Queue a QUBO problem during Day Mode with bounded priority [0, 100]."""
        clamped_priority = max(0, min(100, priority))
        combined_meta = {**problem.metadata, **(metadata or {})}
        return await self._storage.enqueue_dream_problem(
            problem_id=problem.problem_id,
            priority=clamped_priority,
            problem_type=problem.problem_type,
            qubo=problem.model_dump(mode="json"),
            metadata=combined_meta,
        )

    async def fetch_next_batch(
        self, limit: int = 16
    ) -> list[tuple[DreamProblemRecord, QuboProblem]]:
        """Retrieve the highest-priority pending problems deserialized into QuboProblem objects."""
        records = await self._storage.fetch_pending_dream_problems(limit=limit)
        return [(rec, QuboProblem.model_validate(rec.qubo)) for rec in records]

    async def mark_solved(self, problem_id: str, solution: dict[str, Any]) -> None:
        """Persist a completed QAOA solution and mark the problem SOLVED."""
        await self._storage.update_dream_problem_solution(
            problem_id=problem_id,
            status="SOLVED",
            solution=solution,
        )

    async def mark_failed(self, problem_id: str, error: str) -> None:
        """Mark a problem FAILED with diagnostic context."""
        await self._storage.update_dream_problem_solution(
            problem_id=problem_id,
            status="FAILED",
            solution={"error": error},
        )
