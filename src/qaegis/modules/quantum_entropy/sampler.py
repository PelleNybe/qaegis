"""Quantum-seeded MCTS planner, evolutionary mutator, and LLM logit perturbation sampler."""

from __future__ import annotations

import math
from collections.abc import Callable
from typing import Generic, TypeVar

import numpy as np
from numpy.typing import NDArray
from pydantic import BaseModel

from qaegis.modules.quantum_entropy.harvester import QuantumEntropyPool

StateT = TypeVar("StateT")
ActionT = TypeVar("ActionT")


class EvolutionResult(BaseModel):
    """Output of a quantum-seeded evolutionary optimization run."""

    best_genome: list[float]
    best_fitness: float
    generations: int
    population_diversity: float


class TokenSampleResult(BaseModel):
    """Output of quantum-entropy nucleus/top-k token sampling over logits."""

    token_index: int
    token_probability: float
    effective_temperature: float
    candidate_count: int


class _MctsNode(Generic[StateT, ActionT]):
    def __init__(
        self,
        state: StateT,
        parent: _MctsNode[StateT, ActionT] | None = None,
        action: ActionT | None = None,
    ) -> None:
        self.state = state
        self.parent = parent
        self.action = action
        self.children: list[_MctsNode[StateT, ActionT]] = []
        self.visits = 0
        self.total_reward = 0.0
        self.untried_actions: list[ActionT] | None = None


class QuantumMCTS(Generic[StateT, ActionT]):
    """Monte Carlo Tree Search driven by verified quantum entropy for rollouts and UCT jitter."""

    def __init__(
        self,
        pool: QuantumEntropyPool,
        actions_fn: Callable[[StateT], list[ActionT]],
        step_fn: Callable[[StateT, ActionT], StateT],
        is_terminal_fn: Callable[[StateT], bool],
        reward_fn: Callable[[StateT], float],
        exploration_c: float = 1.414,
        quantum_jitter: float = 0.02,
    ) -> None:
        self._pool = pool
        self._actions_fn = actions_fn
        self._step_fn = step_fn
        self._is_terminal_fn = is_terminal_fn
        self._reward_fn = reward_fn
        self._c = exploration_c
        self._jitter = quantum_jitter

    def search(self, root_state: StateT, iterations: int = 100) -> tuple[ActionT, float]:
        """Run `iterations` quantum-seeded MCTS simulations and return (best_action, mean_value)."""
        root: _MctsNode[StateT, ActionT] = _MctsNode(root_state)
        root.untried_actions = list(self._actions_fn(root_state))
        if not root.untried_actions:
            raise ValueError("Root state has no legal actions")

        for _ in range(iterations):
            node = root
            # 1. Selection
            while node.untried_actions is not None and not node.untried_actions and node.children:
                node = self._select_uct(node)

            # 2. Expansion
            if node.untried_actions is None:
                node.untried_actions = list(self._actions_fn(node.state))
            if node.untried_actions and not self._is_terminal_fn(node.state):
                pick_idx = int(self._pool.next_uniform() * len(node.untried_actions))
                pick_idx = min(pick_idx, len(node.untried_actions) - 1)
                action = node.untried_actions.pop(pick_idx)
                next_state = self._step_fn(node.state, action)
                child: _MctsNode[StateT, ActionT] = _MctsNode(
                    state=next_state,
                    parent=node,
                    action=action,
                )
                child.untried_actions = list(self._actions_fn(next_state))
                node.children.append(child)
                node = child

            # 3. Quantum-seeded rollout
            rollout_state = node.state
            depth_guard = 0
            while not self._is_terminal_fn(rollout_state) and depth_guard < 32:
                legal = self._actions_fn(rollout_state)
                if not legal:
                    break
                r_idx = min(int(self._pool.next_uniform() * len(legal)), len(legal) - 1)
                rollout_state = self._step_fn(rollout_state, legal[r_idx])
                depth_guard += 1
            reward = float(self._reward_fn(rollout_state))

            # 4. Backpropagation
            curr: _MctsNode[StateT, ActionT] | None = node
            while curr is not None:
                curr.visits += 1
                curr.total_reward += reward
                curr = curr.parent

        best_child = max(root.children, key=lambda ch: ch.visits)
        if best_child.action is None:
            raise RuntimeError("Selected MCTS child node is missing its originating action")
        mean_val = best_child.total_reward / max(best_child.visits, 1)
        return best_child.action, float(mean_val)

    def _select_uct(self, node: _MctsNode[StateT, ActionT]) -> _MctsNode[StateT, ActionT]:
        log_parent = math.log(max(node.visits, 1))
        best_score = float("-inf")
        best_child = node.children[0]
        for child in node.children:
            mean = child.total_reward / max(child.visits, 1)
            explore = self._c * math.sqrt(log_parent / max(child.visits, 1))
            jitter = self._jitter * self._pool.next_uniform()
            score = mean + explore + jitter
            if score > best_score:
                best_score = score
                best_child = child
        return best_child


class QuantumEvolutionaryMutator:
    """Quantum-noise evolutionary optimizer using Box-Muller Gaussian mutations."""

    def __init__(self, pool: QuantumEntropyPool, mutation_sigma: float = 0.25) -> None:
        self._pool = pool
        self._sigma = mutation_sigma

    def mutate_genome(self, genome: list[float], sigma: float | None = None) -> list[float]:
        """Apply independent quantum-seeded Gaussian perturbations to each gene."""
        scale = sigma if sigma is not None else self._sigma
        return [float(g + scale * self._pool.next_gaussian()) for g in genome]

    def evolve(
        self,
        initial_genome: list[float],
        fitness_fn: Callable[[list[float]], float],
        population_size: int = 12,
        generations: int = 20,
        elite_count: int = 3,
    ) -> EvolutionResult:
        """Evolve a continuous genome population using quantum-entropy mutations."""
        pop: list[list[float]] = [list(initial_genome)]
        while len(pop) < population_size:
            pop.append(self.mutate_genome(initial_genome))

        for gen in range(generations):
            scored = sorted(
                [(fitness_fn(ind), ind) for ind in pop],
                key=lambda item: item[0],
                reverse=True,
            )
            elites = [ind for _score, ind in scored[: max(1, elite_count)]]
            annealed_sigma = self._sigma * (0.95**gen)
            next_pop: list[list[float]] = [list(e) for e in elites]
            while len(next_pop) < population_size:
                parent_idx = min(int(self._pool.next_uniform() * len(elites)), len(elites) - 1)
                next_pop.append(self.mutate_genome(elites[parent_idx], sigma=annealed_sigma))
            pop = next_pop

        final_scored = sorted(
            [(fitness_fn(ind), ind) for ind in pop],
            key=lambda item: item[0],
            reverse=True,
        )
        pop_arr = np.asarray(pop, dtype=np.float64)
        diversity = float(np.mean(np.std(pop_arr, axis=0)))
        return EvolutionResult(
            best_genome=final_scored[0][1],
            best_fitness=float(final_scored[0][0]),
            generations=generations,
            population_diversity=diversity,
        )


class QuantumLogitSampler:
    """Probability-perturbation token sampler for local LLM agents using quantum entropy."""

    def __init__(self, pool: QuantumEntropyPool) -> None:
        self._pool = pool

    def sample_token(
        self,
        logits: list[float] | NDArray[np.float64],
        temperature: float = 0.8,
        top_k: int = 40,
        top_p: float = 0.9,
        quantum_perturbation: float = 0.05,
    ) -> TokenSampleResult:
        """Apply quantum logit perturbation, top-k, and top-p nucleus filtering, then draw."""
        arr = np.asarray(logits, dtype=np.float64)
        if arr.ndim != 1 or arr.size == 0:
            raise ValueError("logits must be a non-empty 1D sequence")

        eff_temp = max(temperature, 1e-4)
        # Quantum-entropy micro-perturbation prevents deterministic mode collapse
        if quantum_perturbation > 0.0:
            noise = np.array(
                [self._pool.next_gaussian() * quantum_perturbation for _ in range(arr.size)],
                dtype=np.float64,
            )
            arr = arr + noise

        scaled = (arr - float(np.max(arr))) / eff_temp
        probs = np.exp(scaled)
        probs = probs / float(np.sum(probs))

        # Top-k filter
        order = np.argsort(probs)[::-1]
        k = max(1, min(top_k, arr.size))
        kept_idx = order[:k]
        kept_probs = probs[kept_idx]

        # Top-p nucleus filter
        cumulative = np.cumsum(kept_probs)
        cutoff_pos = int(np.searchsorted(cumulative, top_p)) + 1
        cutoff_pos = max(1, min(cutoff_pos, kept_idx.size))
        nucleus_idx = kept_idx[:cutoff_pos]
        nucleus_probs = kept_probs[:cutoff_pos]
        nucleus_probs = nucleus_probs / float(np.sum(nucleus_probs))

        # Categorical draw using verified quantum uniform float
        u = self._pool.next_uniform()
        draw_pos = int(np.searchsorted(np.cumsum(nucleus_probs), u))
        draw_pos = min(draw_pos, nucleus_idx.size - 1)
        chosen_idx = int(nucleus_idx[draw_pos])
        return TokenSampleResult(
            token_index=chosen_idx,
            token_probability=float(nucleus_probs[draw_pos]),
            effective_temperature=eff_temp,
            candidate_count=int(nucleus_idx.size),
        )
