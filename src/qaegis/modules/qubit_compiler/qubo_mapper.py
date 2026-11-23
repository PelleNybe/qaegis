"""Automatic combinatorial problem-to-QUBO and Ising Hamiltonian translator."""

from __future__ import annotations

import uuid
from typing import Any

import numpy as np
from pydantic import BaseModel, Field, model_validator


class QuboProblem(BaseModel):
    """Quadratic Unconstrained Binary Optimization problem: minimize x^T Q x + offset."""

    problem_id: str = Field(default_factory=lambda: f"qubo-{uuid.uuid4().hex[:12]}")
    problem_type: str
    num_variables: int = Field(ge=1, le=64)
    matrix: list[list[float]]
    constant_offset: float = 0.0
    variable_names: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_shape(self) -> QuboProblem:
        if len(self.matrix) != self.num_variables:
            raise ValueError("QUBO matrix row count must match num_variables")
        for row in self.matrix:
            if len(row) != self.num_variables:
                raise ValueError("QUBO matrix must be square")
        if not self.variable_names:
            self.variable_names = [f"x_{i}" for i in range(self.num_variables)]
        return self


class IsingCoupling(BaseModel):
    """Quadratic ZZ interaction term J_ij * Z_i * Z_j."""

    i: int
    j: int
    weight: float


class IsingHamiltonian(BaseModel):
    """Exact Ising spin Hamiltonian H = offset + sum_i h_i Z_i + sum_{i<j} J_ij Z_i Z_j."""

    num_qubits: int
    linear_h: list[float]
    couplings: list[IsingCoupling]
    offset: float


def qubo_to_ising(problem: QuboProblem) -> IsingHamiltonian:
    """Convert QUBO minimize x^T Q x + c (x_i in {0, 1}) to exact Ising H(z) (z_i in {-1, +1}).

    Uses the standard substitution x_i = (1 - z_i) / 2 so that z_i = +1 -> x_i = 0
    and z_i = -1 -> x_i = 1 (matching Qiskit computational basis |0> -> +1, |1> -> -1).
    """
    n = problem.num_variables
    q_mat = np.asarray(problem.matrix, dtype=np.float64)
    # Symmetrize into upper-triangular effective coefficients: diag q_ii and off-diag q_ij + q_ji
    linear_h = np.zeros(n, dtype=np.float64)
    couplings: list[IsingCoupling] = []
    offset = float(problem.constant_offset)

    for i in range(n):
        q_ii = float(q_mat[i, i])
        offset += 0.5 * q_ii
        linear_h[i] -= 0.5 * q_ii

    for i in range(n):
        for j in range(i + 1, n):
            w = float(q_mat[i, j] + q_mat[j, i])
            if abs(w) < 1e-12:
                continue
            offset += 0.25 * w
            linear_h[i] -= 0.25 * w
            linear_h[j] -= 0.25 * w
            couplings.append(IsingCoupling(i=i, j=j, weight=0.25 * w))

    return IsingHamiltonian(
        num_qubits=n,
        linear_h=[float(v) for v in linear_h],
        couplings=couplings,
        offset=float(offset),
    )


def evaluate_qubo(problem: QuboProblem, bitstring: str) -> float:
    """Evaluate x^T Q x + offset for binary string `bitstring` (MSB = x_0)."""
    if len(bitstring) != problem.num_variables:
        raise ValueError(
            f"Expected bitstring of length {problem.num_variables}, got {len(bitstring)}"
        )
    x = np.array([int(ch) for ch in bitstring], dtype=np.float64)
    q_mat = np.asarray(problem.matrix, dtype=np.float64)
    return float(x @ q_mat @ x + problem.constant_offset)


def evaluate_ising(hamiltonian: IsingHamiltonian, bitstring: str) -> float:
    """Evaluate Ising Hamiltonian H(z) where bit '0' -> z=+1 and bit '1' -> z=-1."""
    if len(bitstring) != hamiltonian.num_qubits:
        raise ValueError(
            f"Expected bitstring of length {hamiltonian.num_qubits}, got {len(bitstring)}"
        )
    z = np.array([1.0 if ch == "0" else -1.0 for ch in bitstring], dtype=np.float64)
    energy = hamiltonian.offset + float(np.dot(hamiltonian.linear_h, z))
    for c in hamiltonian.couplings:
        energy += c.weight * z[c.i] * z[c.j]
    return float(energy)


def build_maxcut_qubo(
    num_nodes: int,
    weighted_edges: list[tuple[int, int, float]],
    problem_id: str | None = None,
) -> QuboProblem:
    """Translate a weighted Max-Cut graph routing problem into a minimization QUBO.

    Maximizing sum w_ij (x_i + x_j - 2 x_i x_j) is equivalent to minimizing
    sum w_ij (-x_i - x_j + 2 x_i x_j).
    """
    q_mat = np.zeros((num_nodes, num_nodes), dtype=np.float64)
    for u, v, weight in weighted_edges:
        if u == v or u < 0 or v < 0 or u >= num_nodes or v >= num_nodes:
            raise ValueError(f"Invalid edge ({u}, {v}) for {num_nodes} nodes")
        q_mat[u, u] -= weight
        q_mat[v, v] -= weight
        i, j = (u, v) if u < v else (v, u)
        q_mat[i, j] += 2.0 * weight

    return QuboProblem(
        problem_id=problem_id or f"maxcut-{uuid.uuid4().hex[:10]}",
        problem_type="weighted_maxcut_routing",
        num_variables=num_nodes,
        matrix=[[float(v) for v in row] for row in q_mat],
        constant_offset=0.0,
        variable_names=[f"node_{i}" for i in range(num_nodes)],
        metadata={"edges": weighted_edges},
    )


def build_task_scheduling_qubo(
    task_costs: list[float],
    conflicts: list[tuple[int, int]],
    target_active_tasks: int,
    penalty: float = 5.0,
    problem_id: str | None = None,
) -> QuboProblem:
    """Build a QUBO for edge task scheduling with cardinality and conflict penalties."""
    n = len(task_costs)
    q_mat = np.zeros((n, n), dtype=np.float64)

    # Linear task execution cost + cardinality penalty P*(sum x_i - K)^2
    # Since x_i^2 = x_i: (sum x_i - K)^2 = K^2 + sum (1 - 2K) x_i + 2 sum_{i<j} x_i x_j
    for i, cost in enumerate(task_costs):
        q_mat[i, i] += cost + penalty * (1.0 - 2.0 * target_active_tasks)
    for i in range(n):
        for j in range(i + 1, n):
            q_mat[i, j] += 2.0 * penalty

    # Pairwise conflict penalties
    for u, v in conflicts:
        i, j = (u, v) if u < v else (v, u)
        q_mat[i, j] += penalty * 2.0

    constant_offset = penalty * float(target_active_tasks**2)
    return QuboProblem(
        problem_id=problem_id or f"sched-{uuid.uuid4().hex[:10]}",
        problem_type="edge_task_scheduling",
        num_variables=n,
        matrix=[[float(v) for v in row] for row in q_mat],
        constant_offset=constant_offset,
        variable_names=[f"task_{i}" for i in range(n)],
        metadata={
            "task_costs": task_costs,
            "conflicts": conflicts,
            "target_active_tasks": target_active_tasks,
            "penalty": penalty,
        },
    )


def build_resource_allocation_qubo(
    utilities: list[float],
    costs: list[float],
    budget_penalty: float = 1.5,
    problem_id: str | None = None,
) -> QuboProblem:
    """Translate edge resource allocation into a QUBO balancing utility vs quadratic congestion."""
    n = len(utilities)
    if len(costs) != n:
        raise ValueError("utilities and costs must have equal length")
    q_mat = np.zeros((n, n), dtype=np.float64)
    for i in range(n):
        q_mat[i, i] = -utilities[i] + budget_penalty * (costs[i] ** 2)
    for i in range(n):
        for j in range(i + 1, n):
            q_mat[i, j] = 2.0 * budget_penalty * costs[i] * costs[j]

    return QuboProblem(
        problem_id=problem_id or f"alloc-{uuid.uuid4().hex[:10]}",
        problem_type="resource_allocation",
        num_variables=n,
        matrix=[[float(v) for v in row] for row in q_mat],
        constant_offset=0.0,
        variable_names=[f"res_{i}" for i in range(n)],
        metadata={"utilities": utilities, "costs": costs, "budget_penalty": budget_penalty},
    )
