"""Integration tests for CurveZMQ encrypted & mutually authenticated EventBus transport."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from qaegis.core.bus import EventBus, load_or_create_curve_keypair
from qaegis.core.config import BusConfig
from qaegis.core.telemetry import QAegisMetrics


@pytest.mark.integration
async def test_curvezmq_authenticated_delivery_and_unauthorized_rejection(tmp_path: Path) -> None:
    server_kp = load_or_create_curve_keypair(tmp_path / "server_keys", name="server")
    allowed_kp = load_or_create_curve_keypair(tmp_path / "allowed_keys", name="client_ok")
    rogue_kp = load_or_create_curve_keypair(tmp_path / "rogue_keys", name="client_rogue")

    # Enforce strict 0o600 secret permissions on Curve25519 key files
    assert ((tmp_path / "server_keys" / "server.curve.secret.json").stat().st_mode & 0o777) == 0o600

    server_metrics = QAegisMetrics()
    server_bus = EventBus(
        config=BusConfig(
            transport="zmq",
            zmq_pub_endpoint="tcp://127.0.0.1:0",
            zmq_bind_pub=True,
            zmq_connect_sub=False,
            zmq_security="curve",
            zmq_allowed_peer_keys=[allowed_kp.public_key],
        ),
        metrics=server_metrics,
        curve_keypair=server_kp,
    )
    await server_bus.start()
    assert server_bus.bound_pub_endpoint is not None
    endpoint = server_bus.bound_pub_endpoint

    allowed_bus = EventBus(
        config=BusConfig(
            transport="zmq",
            zmq_sub_endpoint=endpoint,
            zmq_bind_pub=False,
            zmq_connect_sub=True,
            zmq_security="curve",
            zmq_server_public_key=server_kp.public_key,
        ),
        curve_keypair=allowed_kp,
    )
    rogue_bus = EventBus(
        config=BusConfig(
            transport="zmq",
            zmq_sub_endpoint=endpoint,
            zmq_bind_pub=False,
            zmq_connect_sub=True,
            zmq_security="curve",
            zmq_server_public_key=server_kp.public_key,
        ),
        curve_keypair=rogue_kp,
    )

    await allowed_bus.start()
    await rogue_bus.start()

    allowed_sub = allowed_bus.subscribe("fleet.*")
    rogue_sub = rogue_bus.subscribe("fleet.*")

    try:
        # Allow ZMQ CURVE ZAP handshakes and PUB/SUB subscription propagation to settle
        await asyncio.sleep(0.35)

        for seq in range(5):
            await server_bus.publish("fleet.heartbeat", {"seq": seq, "status": "nominal"})
            await asyncio.sleep(0.05)

        received = await asyncio.wait_for(allowed_sub.queue.get(), timeout=3.0)
        assert received.topic == "fleet.heartbeat"
        assert received.payload["status"] == "nominal"

        # Unauthorized Curve25519 client must receive zero events and be rejected by ZAP
        assert rogue_sub.queue.empty()
        assert server_bus.auth_provider is not None
        assert server_bus.auth_provider.accepted_count >= 1
        assert server_bus.auth_provider.rejected_count >= 1

        prom_text = server_metrics.render_prometheus_text().decode("utf-8")
        assert "qaegis_bus_auth_rejections_total" in prom_text
    finally:
        await rogue_bus.stop()
        await allowed_bus.stop()
        await server_bus.stop()
