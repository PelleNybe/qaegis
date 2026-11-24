"""AWS Braket QPU & LocalSimulator backend plugin using OpenQASM 3.0."""

from __future__ import annotations

import os
from typing import Any

from braket.aws import AwsDevice
from braket.devices import LocalSimulator
from braket.ir.openqasm import Program

from qaegis.core.telemetry import get_logger
from qaegis.modules.quantum_dreamer.solvers import QuantumBackend
from qaegis.modules.qubit_compiler.qubo_mapper import IsingHamiltonian

logger = get_logger(__name__)


def build_braket_openqasm3(
    hamiltonian: IsingHamiltonian,
    gammas: list[float],
    betas: list[float],
) -> str:
    """Compile a QAOA Ising circuit into AWS Braket-compatible OpenQASM 3.0 source."""
    if len(gammas) != len(betas) or not gammas:
        raise ValueError("gammas and betas must be non-empty lists of equal length")
    n = hamiltonian.num_qubits
    lines: list[str] = [
        "OPENQASM 3.0;",
        f"bit[{n}] c;",
        f"qubit[{n}] q;",
    ]
    for q in range(n):
        lines.append(f"h q[{q}];")

    for gamma, beta in zip(gammas, betas, strict=True):
        for q, h_i in enumerate(hamiltonian.linear_h):
            if abs(h_i) > 1e-12:
                lines.append(f"rz({2.0 * gamma * h_i:.10f}) q[{q}];")
        for coupling in hamiltonian.couplings:
            if abs(coupling.weight) > 1e-12:
                angle = 2.0 * gamma * coupling.weight
                lines.append(f"cnot q[{coupling.i}], q[{coupling.j}];")
                lines.append(f"rz({angle:.10f}) q[{coupling.j}];")
                lines.append(f"cnot q[{coupling.i}], q[{coupling.j}];")
        for q in range(n):
            lines.append(f"rx({2.0 * beta:.10f}) q[{q}];")

    for q in range(n):
        lines.append(f"c[{q}] = measure q[{q}];")
    return "\n".join(lines) + "\n"


class AwsBraketBackend(QuantumBackend):
    """Real Amazon Braket backend supporting LocalSimulator and remote AWS QPU ARNs."""

    def __init__(
        self,
        device_arn: str | None = None,
        s3_folder: tuple[str, str] | None = None,
    ) -> None:
        self._device_arn = device_arn or os.environ.get("QAEGIS_BRAKET_DEVICE_ARN")
        self._s3_folder = s3_folder
        self._device: Any
        self._is_remote = False

        has_aws_creds = any(
            os.environ.get(var)
            for var in (
                "AWS_ACCESS_KEY_ID",
                "AWS_PROFILE",
                "AWS_SESSION_TOKEN",
                "AWS_WEB_IDENTITY_TOKEN_FILE",
                "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
            )
        )
        if self._device_arn and has_aws_creds:
            self._device = AwsDevice(self._device_arn)
            self._is_remote = True
        else:
            if self._device_arn:
                logger.info(
                    "aws_credentials_unset_using_braket_local_simulator",
                    requested_arn=self._device_arn,
                )
            self._device = LocalSimulator()

    @property
    def name(self) -> str:
        if self._is_remote and self._device_arn:
            return f"aws_braket:{self._device_arn}"
        return "aws_braket:local_simulator"

    def sample_distribution(
        self,
        hamiltonian: IsingHamiltonian,
        gammas: list[float],
        betas: list[float],
        shots: int,
    ) -> dict[str, float]:
        """Execute the OpenQASM 3.0 QAOA program on AWS Braket LocalSimulator or QPU."""
        if shots < 1:
            raise ValueError(f"shots must be >= 1, got {shots}")
        source = build_braket_openqasm3(hamiltonian, gammas, betas)
        program = Program(source=source)
        if self._is_remote and self._s3_folder is not None:
            task = self._device.run(program, s3_destination_folder=self._s3_folder, shots=shots)
        else:
            task = self._device.run(program, shots=shots)
        result = task.result()
        counts: dict[str, int] = dict(result.measurement_counts)
        total = float(sum(counts.values()))
        if total <= 0.0:
            raise RuntimeError("AWS Braket returned empty measurement_counts")
        # Braket measurement bitstrings are already big-endian (q[0] at index 0 -> x_0..x_{n-1})
        return {bs: float(cnt) / total for bs, cnt in counts.items()}
