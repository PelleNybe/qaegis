"""Structured JSON logging (structlog) and Prometheus metrics instrumentation."""

from __future__ import annotations

import logging
import sys
from http.server import HTTPServer
from threading import Thread
from typing import Any

import structlog
from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    start_http_server,
)

from qaegis.core.config import TelemetryConfig


def configure_logging(config: TelemetryConfig | None = None) -> None:
    """Configure structlog and standard-library logging for JSON or console output."""
    cfg = config or TelemetryConfig()
    level = getattr(logging, cfg.log_level, logging.INFO)

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    renderer: structlog.types.Processor = (
        structlog.processors.JSONRenderer()
        if cfg.log_json
        else structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())
    )

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(level)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a structured logger bound to the given module name."""
    logger: Any = structlog.get_logger(name)
    return logger  # type: ignore[no-any-return]


class QAegisMetrics:
    """Prometheus metrics collector registry for all Q-Aegis subsystems."""

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry: CollectorRegistry = registry or CollectorRegistry()
        self._server: HTTPServer | None = None
        self._thread: Thread | None = None

        self.bus_events_published = Counter(
            "qaegis_bus_events_published_total",
            "Total events published to the Q-Aegis event bus",
            labelnames=("topic", "source"),
            registry=self.registry,
        )
        self.bus_events_dropped = Counter(
            "qaegis_bus_events_dropped_total",
            "Total events dropped due to subscriber backpressure",
            labelnames=("topic",),
            registry=self.registry,
        )
        self.bus_auth_rejections = Counter(
            "qaegis_bus_auth_rejections_total",
            "Total CurveZMQ peer handshakes rejected by ZAP authentication",
            labelnames=("reason",),
            registry=self.registry,
        )
        self.gossip_equivocations = Counter(
            "qaegis_gossip_equivocation_total",
            "Total split-view Merkle root equivocation alerts detected in gossip mesh",
            labelnames=("peer_node_id",),
            registry=self.registry,
        )
        self.gossip_roots_accepted = Counter(
            "qaegis_gossip_roots_accepted_total",
            "Total verified peer Merkle root checkpoints accepted via gossip",
            labelnames=("peer_node_id",),
            registry=self.registry,
        )
        self.mitigation_runs = Counter(
            "qaegis_mitigation_runs_total",
            "Total quantum error mitigation executions (ZNE / TREX)",
            labelnames=("technique",),
            registry=self.registry,
        )
        self.identity_key_rotations = Counter(
            "qaegis_identity_key_rotations_total",
            "Total zero-downtime PQC device identity key rotations executed",
            labelnames=("node_id",),
            registry=self.registry,
        )
        self.lifecycle_mode = Gauge(
            "qaegis_lifecycle_mode",
            "Current operating mode (0=DAY, 1=NIGHT, 2=TRANSITIONING, -1=SHUTDOWN)",
            registry=self.registry,
        )
        self.reality_stamps_signed = Counter(
            "qaegis_reality_stamps_signed_total",
            "Total Proof-of-Reality stamps cryptographically signed",
            labelnames=("algorithm",),
            registry=self.registry,
        )
        self.reality_stamps_verified = Counter(
            "qaegis_reality_stamps_verified_total",
            "Total Proof-of-Reality stamps verified",
            labelnames=("valid",),
            registry=self.registry,
        )
        self.qrng_health_checks = Counter(
            "qaegis_qrng_health_checks_total",
            "Total NIST SP 800-22 / 800-90B entropy validation runs",
            labelnames=("passed",),
            registry=self.registry,
        )
        self.chameleon_tier_transitions = Counter(
            "qaegis_chameleon_tier_transitions_total",
            "Total Quantum Chameleon security tier decisions",
            labelnames=("tier",),
            registry=self.registry,
        )
        self.crypto_op_latency_seconds = Histogram(
            "qaegis_crypto_operation_duration_seconds",
            "Latency of post-quantum and hybrid cryptographic operations",
            labelnames=("operation", "algorithm"),
            buckets=(0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
            registry=self.registry,
        )
        self.dreamer_qaoa_solves = Counter(
            "qaegis_dreamer_qaoa_solves_total",
            "Total QAOA optimization jobs solved in Night Mode",
            labelnames=("backend", "status"),
            registry=self.registry,
        )
        self.dreamer_policy_updates = Counter(
            "qaegis_dreamer_policy_updates_total",
            "Total local AI policy updates evaluated by Quantum Dreaming",
            labelnames=("outcome",),
            registry=self.registry,
        )
        self.entropy_bytes_harvested = Counter(
            "qaegis_entropy_bytes_harvested_total",
            "Total verified quantum entropy bytes harvested",
            labelnames=("source",),
            registry=self.registry,
        )

    def render_prometheus_text(self) -> bytes:
        """Render the current registry metrics in Prometheus text exposition format."""
        raw: bytes = generate_latest(self.registry)
        return raw

    def start_http_exporter(self, host: str = "127.0.0.1", port: int = 9108) -> tuple[str, int]:
        """Start a non-blocking HTTP server serving `/metrics`."""
        if self._server is not None:
            addr, bound_port = self._server.server_address[:2]
            return (str(addr), int(bound_port))
        server, thread = start_http_server(port=port, addr=host, registry=self.registry)
        self._server = server
        self._thread = thread
        addr, bound_port = server.server_address[:2]
        return (str(addr), int(bound_port))

    def stop_http_exporter(self) -> None:
        """Stop the Prometheus HTTP metrics server if running."""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
            self._thread = None
