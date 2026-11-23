"""Quantum circuit fidelity, QAOA convergence, entropy evolution, and adapter tests."""

from __future__ import annotations

import math
from pathlib import Path

import httpx
import numpy as np
import pytest
from typer.testing import CliRunner

from qaegis.adapters.mqtt_bridge import AsyncMqttBridge, MqttBridgeConfig
from qaegis.adapters.ros2_bridge import Ros2Bridge, Ros2UnavailableError, is_ros2_available
from qaegis.cli import app
from qaegis.core.bus import EventBus
from qaegis.core.config import QuantumDreamerConfig
from qaegis.core.lifecycle import LifecycleManager
from qaegis.core.storage import StorageEngine
from qaegis.core.telemetry import QAegisMetrics
from qaegis.modules.quantum_dreamer.policy_updater import PolicyUpdater
from qaegis.modules.quantum_dreamer.service import QuantumDreamerService
from qaegis.modules.quantum_dreamer.solvers import (
    AerNoisyBackend,
    AerStatevectorBackend,
    IbmRuntimeBackend,
    QaoaSolver,
)
from qaegis.modules.quantum_entropy.ollama_bridge import OllamaQuantumBridge
from qaegis.modules.quantum_entropy.sampler import (
    QuantumEvolutionaryMutator,
    QuantumLogitSampler,
    QuantumMCTS,
)
from qaegis.modules.quantum_entropy.service import QuantumEntropyService
from qaegis.modules.qubit_compiler.autoencoder import AngleEncoderPipeline
from qaegis.modules.qubit_compiler.circuit_builder import (
    BackendNoiseProfile,
    NoiseAwareCircuitBuilder,
)
from qaegis.modules.qubit_compiler.qubo_mapper import (
    build_maxcut_qubo,
    build_resource_allocation_qubo,
    build_task_scheduling_qubo,
    evaluate_ising,
    evaluate_qubo,
    qubo_to_ising,
)
from qaegis.modules.qubit_compiler.service import QubitCompilerService


@pytest.mark.quantum
def test_autoencoder_training_onnx_and_circuits(tmp_path: Path) -> None:
    rng = np.random.default_rng(7)
    samples = rng.normal(loc=0.0, scale=2.0, size=(128, 12)).astype(np.float32)

    pipe = AngleEncoderPipeline(input_dim=12, num_qubits=4, hidden_dim=24, seed=7)
    losses = pipe.train(samples, epochs=40, lr=0.02)
    assert losses[-1] < losses[0]

    torch_angles = pipe.encode_to_angles(samples[0])
    assert torch_angles.encoder_backend == "pytorch_cpu"
    assert len(torch_angles.angles_rad) == 4
    for row in torch_angles.angles_rad:
        assert len(row) == 3
        for angle in row:
            assert -math.pi <= angle <= math.pi

    onnx_file = tmp_path / "angle_encoder.onnx"
    pipe.export_onnx(onnx_file)
    pipe.load_onnx(onnx_file)
    onnx_angles = pipe.encode_to_angles(samples[0])
    assert onnx_angles.encoder_backend == "onnxruntime_cpu"
    assert np.allclose(torch_angles.angles_rad, onnx_angles.angles_rad, atol=1e-4)

    builder = NoiseAwareCircuitBuilder(
        BackendNoiseProfile(two_qubit_error=0.01, topology="ring", optimization_level=2)
    )
    _qc, artifact = builder.build_qiskit_circuit(onnx_angles)
    assert "OPENQASM 3.0;" in artifact.openqasm3
    assert artifact.num_qubits == 4
    assert 0.0 < artifact.estimated_fidelity <= 1.0

    pl_ideal = builder.run_pennylane_circuit(onnx_angles, noise_level=0.0)
    pl_noisy = builder.run_pennylane_circuit(onnx_angles, noise_level=0.03)
    assert pl_ideal.device_name == "default.qubit"
    assert pl_noisy.device_name == "default.mixed"
    assert math.isclose(sum(pl_ideal.probabilities), 1.0, abs_tol=1e-5)
    assert math.isclose(sum(pl_noisy.probabilities), 1.0, abs_tol=1e-5)


@pytest.mark.quantum
def test_qubo_to_ising_exact_mathematical_equivalence() -> None:
    problems = [
        build_maxcut_qubo(4, [(0, 1, 2.0), (1, 2, 1.5), (2, 3, 2.0), (3, 0, 1.0)]),
        build_task_scheduling_qubo([1.0, 2.5, 0.5, 3.0], conflicts=[(0, 2)], target_active_tasks=2),
        build_resource_allocation_qubo([5.0, 4.0, 3.0, 2.0], [1.0, 1.2, 0.8, 0.5]),
    ]
    for prob in problems:
        ising = qubo_to_ising(prob)
        for idx in range(1 << prob.num_variables):
            bs = format(idx, f"0{prob.num_variables}b")
            e_qubo = evaluate_qubo(prob, bs)
            e_ising = evaluate_ising(ising, bs)
            assert math.isclose(e_qubo, e_ising, abs_tol=1e-9), (
                f"Mismatch on {prob.problem_type} bitstring={bs}: {e_qubo} vs {e_ising}"
            )


@pytest.mark.quantum
def test_qaoa_solvers_statevector_noisy_and_ibm_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    # Weighted 4-node cycle Max-Cut: exact ground state is '0101' or '1010' with energy -6.0
    qubo = build_maxcut_qubo(4, [(0, 1, 1.5), (1, 2, 1.5), (2, 3, 1.5), (3, 0, 1.5)])

    sv_solver = QaoaSolver(
        config=QuantumDreamerConfig(qaoa_reps=2, max_optimizer_iters=45),
        backend=AerStatevectorBackend(),
    )
    sv_sol = sv_solver.solve(qubo)
    assert sv_sol.backend_name == "aer_statevector"
    assert sv_sol.exact_ground_energy == pytest.approx(-6.0)
    assert sv_sol.optimal_energy == pytest.approx(-6.0)
    assert sv_sol.approximation_ratio is not None
    assert sv_sol.approximation_ratio >= 0.99
    assert "OPENQASM 3.0;" in sv_sol.openqasm3

    noisy_solver = QaoaSolver(
        config=QuantumDreamerConfig(qaoa_reps=1, qaoa_shots=512, max_optimizer_iters=25),
        backend=AerNoisyBackend(seed=123),
    )
    noisy_sol = noisy_solver.solve(qubo)
    assert noisy_sol.backend_name == "aer_noisy"
    assert noisy_sol.approximation_ratio is not None
    assert noisy_sol.approximation_ratio >= 0.75

    # Without IBM token in env, IbmRuntimeBackend honestly falls back to AerNoisyBackend
    monkeypatch.delenv("IBM_QUANTUM_TOKEN", raising=False)
    monkeypatch.delenv("QISKIT_IBM_TOKEN", raising=False)
    ibm_backend = IbmRuntimeBackend()
    assert ibm_backend.name == "aer_noisy_fallback"


@pytest.mark.quantum
async def test_quantum_dreamer_day_night_cycle_and_rollback_guard(
    event_bus: EventBus,
    storage: StorageEngine,
    lifecycle: LifecycleManager,
    metrics: QAegisMetrics,
) -> None:
    dreamer = QuantumDreamerService(
        bus=event_bus,
        storage=storage,
        lifecycle=lifecycle,
        config=QuantumDreamerConfig(
            backend_type="aer_statevector",
            qaoa_reps=2,
            max_optimizer_iters=35,
            min_policy_improvement=0.01,
        ),
        metrics=metrics,
    )
    await dreamer.start()

    sub = event_bus.subscribe("dreamer.night_cycle_completed")
    qubo = build_maxcut_qubo(4, [(0, 1, 2.0), (1, 2, 2.0), (2, 3, 2.0), (3, 0, 2.0)])
    pid = await dreamer.enqueue_day_problem(qubo, priority=95, policy_name="routing_policy")
    assert pid == qubo.problem_id

    # Entering Night Mode triggers Quantum Dreaming automatically via lifecycle hook
    await lifecycle.enter_night_mode(reason="charging_window")
    completed_env = sub.queue.get_nowait()
    assert completed_env.payload["problems_processed"] == 1
    assert completed_env.payload["policy_updates"][0]["applied"] is True
    await event_bus.unsubscribe(sub)

    # Verify rollback guard blocks a regressed policy update
    updater = PolicyUpdater(storage=storage, min_improvement=0.05, metrics=metrics)
    sol = dreamer.solver.solve(qubo)
    active_before = await storage.get_active_policy("routing_policy")
    assert active_before is not None

    def regressive_scorer(weights: dict[str, float]) -> float:
        # Penalize moving away from current weights -> triggers rollback guard
        return -sum(abs(weights[k] - active_before.weights[k]) for k in active_before.weights)

    rollback_res = await updater.evaluate_and_update("routing_policy", sol, regressive_scorer)
    assert rollback_res.applied is False
    assert rollback_res.rolled_back is True
    active_after = await storage.get_active_policy("routing_policy")
    assert active_after is not None
    assert active_after.version == active_before.version


@pytest.mark.quantum
async def test_quantum_entropy_mcts_evolution_logits_and_ollama_bridge(
    event_bus: EventBus,
    metrics: QAegisMetrics,
) -> None:
    svc = QuantumEntropyService(bus=event_bus, metrics=metrics)
    await svc.start()
    batch, pool = await svc.harvest(num_qubits=6, shots=512, noise_rate=0.01)
    assert batch.shannon_entropy_bits > 3.0
    assert batch.pool_bytes >= 256

    # 1. Quantum MCTS on a 2-step grid choice where action "right" leads to +10 reward
    mcts: QuantumMCTS[int, str] = QuantumMCTS(
        pool=pool,
        actions_fn=lambda s: ["left", "right"] if s == 0 else [],
        step_fn=lambda s, a: 1 if a == "right" else -1,
        is_terminal_fn=lambda s: s != 0,
        reward_fn=lambda s: 10.0 if s == 1 else 0.0,
    )
    best_action, mean_val = mcts.search(root_state=0, iterations=80)
    assert best_action == "right"
    assert mean_val > 8.0

    # 2. Quantum Evolutionary Mutator maximizing -||x - target||^2
    target = [1.5, -1.0, 0.5]
    mutator = QuantumEvolutionaryMutator(pool=pool, mutation_sigma=0.4)
    evo = mutator.evolve(
        initial_genome=[0.0, 0.0, 0.0],
        fitness_fn=lambda g: -sum((a - b) ** 2 for a, b in zip(g, target, strict=True)),
        population_size=16,
        generations=30,
    )
    assert evo.best_fitness > -0.5

    # 3. Quantum Logit Sampler
    sampler = QuantumLogitSampler(pool=pool)
    tok = sampler.sample_token(
        logits=[0.1, 0.2, 5.0, 0.0, -2.0], temperature=0.5, top_k=3, top_p=0.9
    )
    assert tok.token_index in (0, 1, 2)
    assert 0.0 < tok.token_probability <= 1.0

    # 4. OllamaQuantumBridge contract test via httpx.MockTransport
    def _mock_ollama_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/api/tags"):
            return httpx.Response(200, json={"models": [{"name": "llama3.2"}]})
        if request.url.path.endswith("/api/generate"):
            body = request.read()
            assert b'"seed"' in body
            return httpx.Response(
                200,
                json={"model": "llama3.2", "response": "quantum-seeded plan", "eval_count": 12},
            )
        return httpx.Response(
            200,
            json={
                "model": "llama3.2",
                "choices": [{"message": {"content": "openai-compat plan"}}],
                "usage": {"completion_tokens": 9},
            },
        )

    transport = httpx.MockTransport(_mock_ollama_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        bridge = OllamaQuantumBridge(client=client)
        healthy, models = await bridge.check_health()
        assert healthy is True
        assert "llama3.2" in models
        gen = await bridge.generate_with_quantum_seed("Plan next waypoint", pool=pool)
        assert gen.response_text == "quantum-seeded plan"
        assert gen.sampling_params.seed >= 0
        compat = await bridge.generate_openai_compatible(
            [{"role": "user", "content": "Explore"}],
            pool=pool,
        )
        assert compat.response_text == "openai-compat plan"


@pytest.mark.unit
async def test_adapters_and_compiler_service(event_bus: EventBus) -> None:
    compiler = QubitCompilerService(bus=event_bus, input_dim=8)
    await compiler.start()
    reply = await event_bus.request(
        "compiler.compile_tensor",
        {"vector": [0.1, 0.2, -0.3, 0.4, 0.5, -0.6, 0.7, 0.8]},
        source="test",
    )
    assert "OPENQASM 3.0;" in reply.payload["artifact"]["openqasm3"]

    mqtt_bridge = AsyncMqttBridge(event_bus, MqttBridgeConfig(topic_prefix="qaegis"))
    assert (
        mqtt_bridge.map_bus_to_mqtt_topic("reality_stamp.created") == "qaegis/reality_stamp/created"
    )
    assert mqtt_bridge.map_mqtt_to_bus_topic("qaegis/sensor/imu") == "sensor.imu"
    sub = event_bus.subscribe("sensor.imu")
    await mqtt_bridge.ingest_mqtt_payload("qaegis/sensor/imu", b'{"az": 9.81}')
    env = sub.queue.get_nowait()
    assert env.payload["az"] == 9.81
    await event_bus.unsubscribe(sub)

    ros_bridge = Ros2Bridge(event_bus)
    st = ros_bridge.status()
    assert st["ros2_available"] == is_ros2_available()
    if not is_ros2_available():
        with pytest.raises(Ros2UnavailableError):
            await ros_bridge.start()


@pytest.mark.quantum
def test_cli_compile_dream_and_entropy(tmp_path: Path) -> None:
    runner = CliRunner()
    qasm_out = tmp_path / "out.qasm"
    res_c = runner.invoke(
        app,
        ["compile-circuit", "--qubits", "3", "--output-qasm", str(qasm_out)],
    )
    assert res_c.exit_code == 0, res_c.output
    assert "OPENQASM 3.0;" in qasm_out.read_text(encoding="utf-8")

    cfg_file = tmp_path / "dream.yaml"
    cfg_file.write_text(
        f"data_dir: {tmp_path}/d\nkeys_dir: {tmp_path}/k\ndb_path: {tmp_path}/d/q.db\n",
        encoding="utf-8",
    )
    res_d = runner.invoke(app, ["dream", "--nodes", "4", "--config", str(cfg_file)])
    assert res_d.exit_code == 0, res_d.output
    assert "aer_statevector" in res_d.output

    res_e = runner.invoke(app, ["entropy", "--qubits", "4", "--shots", "256"])
    assert res_e.exit_code == 0, res_e.output
    assert "Shannon Entropy" in res_e.output
