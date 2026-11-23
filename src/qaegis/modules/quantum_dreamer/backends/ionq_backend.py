"""IonQ Cloud API v0.3 backend plugin with QIS gate compiler and honest local fallback."""

from __future__ import annotations

import os
import time
from typing import Any

import httpx
from qiskit import QuantumCircuit

from qaegis.core.telemetry import get_logger
from qaegis.modules.quantum_dreamer.solvers import (
    AerNoisyBackend,
    QuantumBackend,
    build_qaoa_circuit,
)
from qaegis.modules.qubit_compiler.qubo_mapper import IsingHamiltonian

logger = get_logger(__name__)

_SINGLE_QUBIT_NO_PARAM = {"h", "x", "y", "z", "s", "t"}
_SINGLE_QUBIT_ROT = {"rx", "ry", "rz"}


def qiskit_to_ionq_circuit(qc: QuantumCircuit) -> dict[str, Any]:
    """Translate a Qiskit QuantumCircuit into an IonQ API v0.3 QIS JSON gate payload."""
    n_qubits = int(qc.num_qubits)
    qubit_index = {qubit: idx for idx, qubit in enumerate(qc.qubits)}
    gates: list[dict[str, Any]] = []

    for inst in qc.data:
        op_name = str(inst.operation.name).lower()
        q_indices = [qubit_index[q] for q in inst.qubits]
        params = [float(p) for p in inst.operation.params]

        if op_name in ("measure", "barrier"):
            continue
        if op_name in _SINGLE_QUBIT_NO_PARAM:
            gates.append({"gate": op_name, "target": q_indices[0]})
        elif op_name in _SINGLE_QUBIT_ROT:
            gates.append({"gate": op_name, "target": q_indices[0], "rotation": params[0]})
        elif op_name in ("cx", "cnot"):
            gates.append({"gate": "cnot", "control": q_indices[0], "target": q_indices[1]})
        elif op_name == "rzz":
            # Exact decomposition: RZZ(theta) = CNOT(i, j) -> RZ(theta, j) -> CNOT(i, j)
            gates.append({"gate": "cnot", "control": q_indices[0], "target": q_indices[1]})
            gates.append({"gate": "rz", "target": q_indices[1], "rotation": params[0]})
            gates.append({"gate": "cnot", "control": q_indices[0], "target": q_indices[1]})
        else:
            raise ValueError(f"Unsupported Qiskit gate for IonQ QIS compilation: '{op_name}'")

    return {
        "qubits": n_qubits,
        "circuit": gates,
    }


class IonQBackend(QuantumBackend):
    """Production IonQ Cloud API v0.3 client with job polling and honest noisy local fallback."""

    def __init__(
        self,
        target: str = "simulator",
        api_key: str | None = None,
        api_url: str = "https://api.ionq.co/v0.3/jobs",
        poll_interval_s: float = 0.5,
        timeout_s: float = 120.0,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._target = target
        self._api_key = api_key or os.environ.get("IONQ_API_KEY")
        self._api_url = api_url.rstrip("/")
        self._poll_interval_s = poll_interval_s
        self._timeout_s = timeout_s
        self._http_client = http_client
        self._fallback = AerNoisyBackend()
        self._last_calibration: dict[str, Any] = {}

        if not self._api_key and self._http_client is None:
            logger.info(
                "ionq_api_key_not_configured_using_local_noisy_aer",
                requested_target=self._target,
            )

    @property
    def name(self) -> str:
        if self._api_key or self._http_client is not None:
            return f"ionq:{self._target}"
        return "ionq:aer_noisy_fallback"

    @property
    def last_calibration(self) -> dict[str, Any]:
        """Return calibration metadata returned by the latest IonQ job response."""
        return dict(self._last_calibration)

    def build_job_payload(
        self,
        hamiltonian: IsingHamiltonian,
        gammas: list[float],
        betas: list[float],
        shots: int,
        job_name: str = "qaegis-qaoa",
    ) -> dict[str, Any]:
        """Build a schema-valid IonQ API v0.3 job submission JSON document."""
        qc = build_qaoa_circuit(hamiltonian, gammas, betas, measure=False)
        body = qiskit_to_ionq_circuit(qc)
        return {
            "name": job_name,
            "target": self._target,
            "shots": shots,
            "lang": "json",
            "input": body,
        }

    def sample_distribution(
        self,
        hamiltonian: IsingHamiltonian,
        gammas: list[float],
        betas: list[float],
        shots: int,
    ) -> dict[str, float]:
        """Submit QAOA job to IonQ Cloud API v0.3 or execute on honest local noisy Aer fallback."""
        payload = self.build_job_payload(hamiltonian, gammas, betas, shots)

        if not self._api_key and self._http_client is None:
            return self._fallback.sample_distribution(hamiltonian, gammas, betas, shots)

        headers = {
            "Authorization": f"apiKey {self._api_key or 'injected-client'}",
            "Content-Type": "application/json",
        }
        own_client = self._http_client is None
        client = self._http_client or httpx.Client(timeout=30.0)
        try:
            submit_resp = client.post(self._api_url, json=payload, headers=headers)
            submit_resp.raise_for_status()
            job_info = submit_resp.json()
            job_id = str(job_info["id"])

            deadline = time.monotonic() + self._timeout_s
            status = str(job_info.get("status", "submitted"))
            while status not in ("completed", "failed", "canceled"):
                if time.monotonic() > deadline:
                    raise TimeoutError(f"IonQ job {job_id} timed out after {self._timeout_s}s")
                if self._poll_interval_s > 0.0:
                    time.sleep(self._poll_interval_s)
                poll_resp = client.get(f"{self._api_url}/{job_id}", headers=headers)
                poll_resp.raise_for_status()
                job_info = poll_resp.json()
                status = str(job_info.get("status", "unknown"))

            if status != "completed":
                raise RuntimeError(f"IonQ job {job_id} ended with status '{status}'")

            if isinstance(job_info.get("calibration"), dict):
                self._last_calibration = dict(job_info["calibration"])

            # IonQ API v0.3 returns probabilities at /jobs/{id}/results or data.histogram
            histogram: dict[str, Any]
            if isinstance(job_info.get("data"), dict) and "histogram" in job_info["data"]:
                histogram = dict(job_info["data"]["histogram"])
            else:
                res_resp = client.get(f"{self._api_url}/{job_id}/results", headers=headers)
                res_resp.raise_for_status()
                res_body = res_resp.json()
                histogram = dict(res_body.get("histogram", res_body))

            n = hamiltonian.num_qubits
            dist: dict[str, float] = {}
            for state_key, prob in histogram.items():
                idx = int(state_key)
                # IonQ integer keys are little-endian (bit q is qubit q) -> convert to x_0..x_{n-1}
                bitstring = "".join(str((idx >> q) & 1) for q in range(n))
                dist[bitstring] = float(prob)
            return dist
        finally:
            if own_client:
                client.close()
