"""Federated Night-Mode QAOA fleet scheduler with isomorphism deduplication and PQC signing."""

from __future__ import annotations

import base64
import hashlib
import itertools
from datetime import UTC, datetime

import numpy as np
import orjson
from pydantic import BaseModel, Field

from qaegis.core.identity import (
    DeviceIdentity,
    PublicIdentityBundle,
    TrustKeyring,
    constant_time_equal,
)
from qaegis.core.telemetry import get_logger
from qaegis.modules.quantum_dreamer.policy_updater import (
    PolicyScorer,
    PolicyUpdater,
    PolicyUpdateResult,
)
from qaegis.modules.quantum_dreamer.solvers import QaoaSolution, QaoaSolver
from qaegis.modules.qubit_compiler.qubo_mapper import QuboProblem

logger = get_logger(__name__)


def canonicalize_qubo(problem: QuboProblem) -> tuple[str, tuple[int, ...]]:
    """Compute a structural/isomorphism-invariant canonical hash and variable permutation.

    For QUBO instances up to 7 variables, finds the exact lexicographically minimal
    permuted upper-triangular matrix representation so relabeled isomorphic graphs
    deduplicate cleanly while preserving the inverse permutation to map solutions back.
    For larger instances, hashes the sorted node-degree and diagonal spectral signature.
    """
    n = problem.num_variables
    q = np.asarray(problem.matrix, dtype=np.float64)
    # Symmetrize off-diagonal entries: sym[i,j] = q[i,j] + q[j,i] for i < j
    sym = np.zeros((n, n), dtype=np.float64)
    for i in range(n):
        sym[i, i] = round(float(q[i, i]), 6)
        for j in range(i + 1, n):
            val = round(float(q[i, j] + q[j, i]), 6)
            sym[i, j] = val
            sym[j, i] = val

    if n <= 7:
        best_tuple: tuple[float, ...] | None = None
        best_perm: tuple[int, ...] = tuple(range(n))
        for perm in itertools.permutations(range(n)):
            flat: list[float] = []
            for a in range(n):
                flat.append(float(sym[perm[a], perm[a]]))
                for b in range(a + 1, n):
                    flat.append(float(sym[perm[a], perm[b]]))
            cand = tuple(flat)
            if best_tuple is None or cand < best_tuple:
                best_tuple = cand
                best_perm = perm
        payload = {
            "n": n,
            "offset": round(problem.constant_offset, 6),
            "canonical_entries": list(best_tuple or ()),
        }
        digest = hashlib.sha256(orjson.dumps(payload, option=orjson.OPT_SORT_KEYS)).hexdigest()
        return digest, best_perm

    # Fallback invariant for large QUBOs: sort nodes by (diag, sorted incident edge weights)
    node_sigs = [
        (float(sym[i, i]), tuple(sorted(float(sym[i, j]) for j in range(n) if j != i)), i)
        for i in range(n)
    ]
    node_sigs.sort()
    perm_large = tuple(item[2] for item in node_sigs)
    entries = [float(sym[perm_large[a], perm_large[b]]) for a in range(n) for b in range(a, n)]
    payload = {
        "n": n,
        "offset": round(problem.constant_offset, 6),
        "canonical_entries": entries,
    }
    digest = hashlib.sha256(orjson.dumps(payload, option=orjson.OPT_SORT_KEYS)).hexdigest()
    return digest, perm_large


def remap_bitstring(
    canonical_bitstring: str,
    source_perm: tuple[int, ...],
    target_perm: tuple[int, ...],
) -> str:
    """Translate a solution bitstring from `source_perm` indexing to `target_perm` indexing."""
    n = len(canonical_bitstring)
    # source_perm[k] is the original variable at canonical slot k
    # First map solved source bitstring into canonical slot order
    canon_bits = [canonical_bitstring[source_perm[k]] for k in range(n)]
    # Then place canonical slot k into target node's original variable target_perm[k]
    target_bits = ["0"] * n
    for k in range(n):
        target_bits[target_perm[k]] = canon_bits[k]
    return "".join(target_bits)


class FederatedJobSubmission(BaseModel):
    """Day-Mode QUBO optimization job submitted by an edge node to the Fleet Coordinator."""

    node_id: str
    policy_name: str
    priority: int = Field(default=50, ge=0, le=100)
    estimated_qpu_seconds: float = Field(default=5.0, gt=0.0)
    qubo: QuboProblem


class SignedPolicyBroadcast(BaseModel):
    """ML-DSA-65 signed federated QAOA solution broadcast to participating edge nodes."""

    coordinator_node_id: str
    target_node_id: str
    canonical_hash: str
    problem_id: str
    policy_name: str
    optimal_bitstring: str
    optimal_energy: float
    approximation_ratio: float | None = None
    backend_name: str
    broadcast_at_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    sig_alg: str
    coordinator_pub_b64: str
    signature_b64: str

    def signing_bytes(self) -> bytes:
        """Canonical transcript signed by the Fleet Coordinator's ML-DSA-65 key."""
        doc = {
            "approximation_ratio": self.approximation_ratio,
            "backend_name": self.backend_name,
            "broadcast_at_utc": self.broadcast_at_utc.isoformat(),
            "canonical_hash": self.canonical_hash,
            "coordinator_node_id": self.coordinator_node_id,
            "optimal_bitstring": self.optimal_bitstring,
            "optimal_energy": self.optimal_energy,
            "policy_name": self.policy_name,
            "problem_id": self.problem_id,
            "sig_alg": self.sig_alg,
            "target_node_id": self.target_node_id,
        }
        return orjson.dumps(doc, option=orjson.OPT_SORT_KEYS)


class FederatedScheduleReport(BaseModel):
    """Summary of a Night-Mode federated QAOA scheduling cycle."""

    submissions_received: int
    unique_problems_solved: int
    deduplicated_count: int
    deferred_for_budget_count: int
    failed_groups_count: int = 0
    qpu_seconds_used: float
    budget_seconds: float
    broadcasts: list[SignedPolicyBroadcast] = Field(default_factory=list)


class FederatedScheduler:
    """Fleet Coordinator deduplicating QUBOs, enforcing QPU budgets, and signing policies."""

    def __init__(
        self,
        coordinator_identity: DeviceIdentity,
        solver: QaoaSolver,
        max_qpu_seconds_per_night: float = 300.0,
    ) -> None:
        self._identity = coordinator_identity
        self._solver = solver
        self._budget_s = max_qpu_seconds_per_night
        self._pending: list[FederatedJobSubmission] = []

    def submit(self, submission: FederatedJobSubmission) -> None:
        """Queue a node's QUBO job for the next federated Night-Mode batch."""
        self._pending.append(submission)

    def run_federated_cycle(self) -> FederatedScheduleReport:
        """Deduplicate isomorphic QUBOs, solve within QPU budget, and sign policy broadcasts."""
        submissions = list(self._pending)
        self._pending.clear()

        # Group submissions by canonical isomorphic QUBO hash
        groups: dict[str, list[tuple[FederatedJobSubmission, tuple[int, ...]]]] = {}
        for sub in submissions:
            c_hash, perm = canonicalize_qubo(sub.qubo)
            groups.setdefault(c_hash, []).append((sub, perm))

        # Rank unique canonical groups by highest priority across participating nodes
        ranked_groups = sorted(
            groups.items(),
            key=lambda kv: max(item[0].priority for item in kv[1]),
            reverse=True,
        )

        qpu_used = 0.0
        solved_groups = 0
        dedup_saved = 0
        deferred_groups = 0
        failed_groups = 0
        broadcasts: list[SignedPolicyBroadcast] = []

        for c_hash, members in ranked_groups:
            rep_sub, rep_perm = max(members, key=lambda m: m[0].priority)
            if qpu_used + rep_sub.estimated_qpu_seconds > self._budget_s:
                deferred_groups += 1
                # Re-queue deferred submissions for the following Night-Mode window
                for sub, _perm in members:
                    self._pending.append(sub)
                continue

            try:
                sol = self._solver.solve(rep_sub.qubo)
            except Exception:
                failed_groups += 1
                logger.exception(
                    "federated_qaoa_group_failed",
                    canonical_hash=c_hash[:16],
                    problem_id=rep_sub.qubo.problem_id,
                )
                continue

            qpu_used += max(rep_sub.estimated_qpu_seconds, sol.solve_time_s)
            solved_groups += 1
            dedup_saved += len(members) - 1

            for member_sub, member_perm in members:
                mapped_bits = remap_bitstring(sol.optimal_bitstring, rep_perm, member_perm)
                broadcasts.append(
                    self._sign_broadcast(
                        canonical_hash=c_hash,
                        submission=member_sub,
                        mapped_bitstring=mapped_bits,
                        solution=sol,
                    )
                )

        logger.info(
            "federated_night_cycle_completed",
            submissions=len(submissions),
            unique_solved=solved_groups,
            deduplicated=dedup_saved,
            deferred=deferred_groups,
            failed=failed_groups,
            qpu_seconds_used=round(qpu_used, 2),
        )
        return FederatedScheduleReport(
            submissions_received=len(submissions),
            unique_problems_solved=solved_groups,
            deduplicated_count=dedup_saved,
            deferred_for_budget_count=deferred_groups,
            failed_groups_count=failed_groups,
            qpu_seconds_used=qpu_used,
            budget_seconds=self._budget_s,
            broadcasts=broadcasts,
        )

    def _sign_broadcast(
        self,
        canonical_hash: str,
        submission: FederatedJobSubmission,
        mapped_bitstring: str,
        solution: QaoaSolution,
    ) -> SignedPolicyBroadcast:
        unsigned = SignedPolicyBroadcast(
            coordinator_node_id=self._identity.node_id,
            target_node_id=submission.node_id,
            canonical_hash=canonical_hash,
            problem_id=submission.qubo.problem_id,
            policy_name=submission.policy_name,
            optimal_bitstring=mapped_bitstring,
            optimal_energy=solution.optimal_energy,
            approximation_ratio=solution.approximation_ratio,
            backend_name=solution.backend_name,
            sig_alg=self._identity.primary_sig_alg,
            coordinator_pub_b64=base64.b64encode(self._identity.primary_sig_public).decode("ascii"),
            signature_b64="",
        )
        alg, signature = self._identity.sign(unsigned.signing_bytes(), use_fallback=False)
        return unsigned.model_copy(
            update={
                "sig_alg": alg,
                "signature_b64": base64.b64encode(signature).decode("ascii"),
            }
        )


def verify_federated_broadcast(
    broadcast: SignedPolicyBroadcast,
    trusted_coordinator: PublicIdentityBundle | TrustKeyring,
) -> bool:
    """Verify the Fleet Coordinator's ML-DSA-65 signature on a federated policy broadcast."""
    if broadcast.coordinator_node_id != trusted_coordinator.node_id:
        return False

    candidate_pubs: list[bytes] = []
    if isinstance(trusted_coordinator, TrustKeyring):
        for bundle in trusted_coordinator.keys.values():
            candidate_pubs.append(base64.b64decode(bundle.primary_sig_public_b64))
    else:
        candidate_pubs.append(base64.b64decode(trusted_coordinator.primary_sig_public_b64))

    try:
        claimed_pub = base64.b64decode(broadcast.coordinator_pub_b64)
        sig_bytes = base64.b64decode(broadcast.signature_b64)
    except Exception:
        return False

    matched_pub: bytes | None = None
    for pub in candidate_pubs:
        if constant_time_equal(claimed_pub, pub):
            matched_pub = pub
            break
    if matched_pub is None:
        return False

    try:
        return DeviceIdentity.verify(
            broadcast.signing_bytes(),
            sig_bytes,
            matched_pub,
            broadcast.sig_alg,
        )
    except Exception:
        return False


async def apply_federated_broadcast(
    broadcast: SignedPolicyBroadcast,
    trusted_coordinator: PublicIdentityBundle | TrustKeyring,
    local_updater: PolicyUpdater,
    local_scorer: PolicyScorer,
    expected_target_node_id: str | None = None,
) -> PolicyUpdateResult:
    """Verify coordinator PQC signature & target node, then apply with rollback guard."""
    if expected_target_node_id is not None and broadcast.target_node_id != expected_target_node_id:
        raise ValueError(
            f"Federated broadcast targeted to '{broadcast.target_node_id}', "
            f"not local node '{expected_target_node_id}'"
        )
    if not verify_federated_broadcast(broadcast, trusted_coordinator):
        raise ValueError(
            f"ML-DSA-65 signature verification failed for federated broadcast from "
            f"'{broadcast.coordinator_node_id}'"
        )
    synthetic_solution = QaoaSolution(
        problem_id=broadcast.problem_id,
        backend_name=broadcast.backend_name,
        optimal_bitstring=broadcast.optimal_bitstring,
        optimal_energy=broadcast.optimal_energy,
        expected_energy=broadcast.optimal_energy,
        approximation_ratio=broadcast.approximation_ratio,
        optimal_gammas=[],
        optimal_betas=[],
        shots=0,
        optimizer_iters=0,
        openqasm3="",
        solve_time_s=0.0,
    )
    return await local_updater.evaluate_and_update(
        policy_name=broadcast.policy_name,
        solution=synthetic_solution,
        scorer=local_scorer,
    )
