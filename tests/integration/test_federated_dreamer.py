"""Integration tests for Federated Night-Mode QAOA Fleet Scheduling."""

from __future__ import annotations

from pathlib import Path

import pytest

from qaegis.core.config import QuantumDreamerConfig
from qaegis.core.identity import IdentityManager
from qaegis.core.storage import StorageEngine
from qaegis.modules.quantum_dreamer.federated import (
    FederatedJobSubmission,
    FederatedScheduler,
    apply_federated_broadcast,
    canonicalize_qubo,
    verify_federated_broadcast,
)
from qaegis.modules.quantum_dreamer.policy_updater import PolicyUpdater
from qaegis.modules.quantum_dreamer.solvers import AerStatevectorBackend, QaoaSolver
from qaegis.modules.qubit_compiler.qubo_mapper import build_maxcut_qubo, evaluate_qubo


@pytest.mark.integration
async def test_federated_three_node_deduplication_budget_and_local_rollback(
    tmp_path: Path,
) -> None:
    coord_id = IdentityManager(tmp_path / "coord_keys", "fleet-coordinator").generate()
    solver = QaoaSolver(
        config=QuantumDreamerConfig(
            backend_type="aer_statevector",
            qaoa_reps=2,
            max_optimizer_iters=35,
        ),
        backend=AerStatevectorBackend(),
    )

    # Budget allows 2 QPU jobs (45.0s budget, 20.0s each -> 3rd unique job deferred)
    scheduler = FederatedScheduler(
        coordinator_identity=coord_id,
        solver=solver,
        max_qpu_seconds_per_night=45.0,
    )

    # Node 1 and Node 2 submit RELABELED ISOMORPHIC 4-node Max-Cut graphs:
    # Node 1: 0-1 (2.0), 1-2 (1.0), 2-3 (2.0), 3-0 (1.0)
    # Node 2: permute (0->2, 1->0, 2->3, 3->1) -> 2-0 (2.0), 0-3 (1.0), 3-1 (2.0), 1-2 (1.0)
    qubo_n1 = build_maxcut_qubo(4, [(0, 1, 2.0), (1, 2, 1.0), (2, 3, 2.0), (3, 0, 1.0)], "p-n1")
    qubo_n2 = build_maxcut_qubo(4, [(2, 0, 2.0), (0, 3, 1.0), (3, 1, 2.0), (1, 2, 1.0)], "p-n2")
    h1, _ = canonicalize_qubo(qubo_n1)
    h2, _ = canonicalize_qubo(qubo_n2)
    assert h1 == h2, "Isomorphic relabeled QUBOs must share identical canonical hash"

    # Node 3 submits a distinct weighted graph (priority 80) AND a low-priority 3rd unique graph
    qubo_n3_hi = build_maxcut_qubo(4, [(0, 1, 3.0), (1, 2, 1.0), (2, 3, 1.0), (0, 2, 2.0)], "p-n3")
    qubo_n3_lo = build_maxcut_qubo(4, [(0, 1, 0.5), (1, 2, 0.5), (2, 3, 0.5)], "p-n3-deferred")

    scheduler.submit(
        FederatedJobSubmission(
            node_id="drone-1",
            policy_name="routing_policy",
            priority=95,
            estimated_qpu_seconds=20.0,
            qubo=qubo_n1,
        )
    )
    scheduler.submit(
        FederatedJobSubmission(
            node_id="drone-2",
            policy_name="routing_policy",
            priority=90,
            estimated_qpu_seconds=20.0,
            qubo=qubo_n2,
        )
    )
    scheduler.submit(
        FederatedJobSubmission(
            node_id="drone-3",
            policy_name="routing_policy",
            priority=80,
            estimated_qpu_seconds=20.0,
            qubo=qubo_n3_hi,
        )
    )
    scheduler.submit(
        FederatedJobSubmission(
            node_id="drone-3",
            policy_name="low_priority_policy",
            priority=10,
            estimated_qpu_seconds=20.0,
            qubo=qubo_n3_lo,
        )
    )

    report = scheduler.run_federated_cycle()
    assert report.submissions_received == 4
    assert report.unique_problems_solved == 2
    assert report.deduplicated_count == 1
    assert report.deferred_for_budget_count == 1
    assert len(report.broadcasts) == 3

    coord_pub = coord_id.public_bundle()
    by_node = {b.target_node_id: b for b in report.broadcasts}

    # Verify ML-DSA-65 signature and bitstring remapping optimality for BOTH isomorphic nodes!
    assert verify_federated_broadcast(by_node["drone-1"], coord_pub) is True
    assert verify_federated_broadcast(by_node["drone-2"], coord_pub) is True
    assert evaluate_qubo(qubo_n1, by_node["drone-1"].optimal_bitstring) == pytest.approx(-6.0)
    assert evaluate_qubo(qubo_n2, by_node["drone-2"].optimal_bitstring) == pytest.approx(-6.0)

    # Tampered broadcast must fail verification
    tampered = by_node["drone-1"].model_copy(update={"optimal_bitstring": "0000"})
    assert verify_federated_broadcast(tampered, coord_pub) is False

    # Drone 1 applies broadcast cleanly; Drone 2 rejects via local rollback guard
    store1 = StorageEngine(tmp_path / "drone1.db")
    store2 = StorageEngine(tmp_path / "drone2.db")
    await store1.initialize()
    await store2.initialize()
    try:
        updater1 = PolicyUpdater(store1, min_improvement=0.01)
        updater2 = PolicyUpdater(store2, min_improvement=0.05)

        def improving_scorer(weights: dict[str, float]) -> float:
            vec = [weights[f"w_{i}"] for i in range(4)]
            # Negative continuous QUBO energy -> optimal cut improves score over neutral 0.5
            e = sum(qubo_n1.matrix[i][j] * vec[i] * vec[j] for i in range(4) for j in range(4))
            return -float(e)

        res1 = await apply_federated_broadcast(
            by_node["drone-1"],
            coord_pub,
            updater1,
            improving_scorer,
        )
        assert res1.applied is True
        assert res1.rolled_back is False

        # Regressive local environment on drone-2 triggers automatic rollback
        res2 = await apply_federated_broadcast(
            by_node["drone-2"],
            coord_pub,
            updater2,
            lambda weights: -sum(abs(v - 0.5) for v in weights.values()),
        )
        assert res2.applied is False
        assert res2.rolled_back is True
    finally:
        await store1.close()
        await store2.close()
