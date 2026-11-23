"""Integration tests for 3-node ML-DSA-65 Merkle Root Gossip Mesh & Equivocation Detection."""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

import orjson
import pytest
from typer.testing import CliRunner

from qaegis.cli import app
from qaegis.core.bus import EventBus
from qaegis.core.config import QAegisConfig
from qaegis.core.identity import IdentityManager
from qaegis.core.storage import StorageEngine
from qaegis.core.telemetry import QAegisMetrics
from qaegis.modules.reality_stamp.gossip import MerkleGossipNode
from qaegis.modules.reality_stamp.merkle import MerkleTree


@pytest.mark.integration
async def test_three_node_merkle_gossip_convergence_and_equivocation_detection(
    tmp_path: Path,
) -> None:
    node_names = ("edge-alpha", "edge-beta", "edge-gamma")
    buses: list[EventBus] = []
    stores: list[StorageEngine] = []
    metrics_list: list[QAegisMetrics] = []
    nodes: list[MerkleGossipNode] = []

    for name in node_names:
        cfg = QAegisConfig(
            node_id=name,
            data_dir=tmp_path / name / "data",
            keys_dir=tmp_path / name / "keys",
            db_path=tmp_path / name / "data" / "gossip.db",
        )
        cfg.ensure_directories()
        m = QAegisMetrics()
        bus = EventBus(config=cfg.bus, metrics=m)
        store = StorageEngine(cfg.db_path)
        ident = IdentityManager(cfg.keys_dir, name, cfg.identity).generate()
        await bus.start()
        await store.initialize()

        gossip_node = MerkleGossipNode(
            identity=ident,
            storage=store,
            bus=bus,
            metrics=m,
        )
        buses.append(bus)
        stores.append(store)
        metrics_list.append(m)
        nodes.append(gossip_node)

    # Cross-register PQC public identities & CurveZMQ public keys across all 3 peers
    all_curve_keys = [n.curve_public_key for n in nodes]
    endpoints: list[str] = []
    for n in nodes:
        ep = await n.start_mesh(
            bind_endpoint="tcp://127.0.0.1:0",
            allowed_curve_keys=all_curve_keys,
        )
        endpoints.append(ep)

    for i, node_i in enumerate(nodes):
        for j, node_j in enumerate(nodes):
            if i != j:
                node_i.register_trusted_peer(
                    node_j._identity.public_bundle(),
                    curve_public_key=node_j.curve_public_key,
                )
                await node_i.connect_peer(endpoints[j], node_j.curve_public_key)

    try:
        # Allow CurveZMQ handshakes and subscriptions to settle across the 3-node mesh
        await asyncio.sleep(0.45)

        # Each node builds its own Merkle tree and broadcasts its ML-DSA-65 signed root
        expected_roots: dict[str, str] = {}
        for idx, n in enumerate(nodes):
            tree = MerkleTree()
            for leaf_i in range(3 + idx):
                tree.append_raw(f"{n.node_id}-event-{leaf_i}".encode())
            checkpoint = n.create_checkpoint(merkle_root=tree.root_hex, tree_size=tree.size)
            expected_roots[n.node_id] = tree.root_hex
            for _ in range(3):
                await n.broadcast_checkpoint(checkpoint)
                await asyncio.sleep(0.05)

        # Wait for all 3 nodes to converge on all 3 peers' Merkle roots
        deadline = asyncio.get_running_loop().time() + 4.0
        while asyncio.get_running_loop().time() < deadline:
            if all(all(pid in node.latest_roots for pid in node_names) for node in nodes):
                break
            await asyncio.sleep(0.05)

        for node in nodes:
            for pid, exp_root in expected_roots.items():
                assert pid in node.latest_roots, f"{node.node_id} missing root for {pid}"
                assert node.latest_roots[pid][1] == exp_root

        # Forged signature must be immediately rejected
        alpha = nodes[0]
        beta = nodes[1]
        forged_env = alpha.create_checkpoint(
            merkle_root=hashlib.sha256(b"forged-branch").hexdigest(),
            tree_size=99,
        )
        forged_env = forged_env.model_copy(
            update={"merkle_root": hashlib.sha256(b"tampered-after-sign").hexdigest()}
        )
        forged_res = await beta.ingest_checkpoint(forged_env, rebroadcast=False)
        assert forged_res.accepted is False
        assert forged_res.reason == "invalid_mldsa_signature"

        # Split-view equivocation: alpha signs a DIFFERENT root for the SAME tree_size=3!
        equiv_sub = buses[1].subscribe("gossip.equivocation_detected")
        evil_checkpoint = alpha.create_checkpoint(
            merkle_root=hashlib.sha256(b"split-view-alternate-history").hexdigest(),
            tree_size=3,
        )
        equiv_res = await beta.ingest_checkpoint(evil_checkpoint, rebroadcast=False)
        assert equiv_res.accepted is False
        assert equiv_res.reason == "equivocation_detected"
        assert equiv_res.equivocation_alert is not None
        assert len(beta.equivocation_alerts) == 1

        alert_env = await asyncio.wait_for(equiv_sub.queue.get(), timeout=2.0)
        assert alert_env.payload["peer_node_id"] == "edge-alpha"
        assert "qaegis_gossip_equivocation_total" in metrics_list[
            1
        ].render_prometheus_text().decode("utf-8")
        await buses[1].unsubscribe(equiv_sub)
    finally:
        for n in nodes:
            await n.stop_mesh()
        for s in stores:
            await s.close()
        for b in buses:
            await b.stop()


@pytest.mark.integration
def test_cli_gossip_status_and_verify_peer(tmp_path: Path) -> None:
    cfg_file = tmp_path / "gossip_cli.yaml"
    cfg_file.write_text(
        (
            f"node_id: verifier-node\n"
            f"data_dir: {tmp_path}/data\n"
            f"keys_dir: {tmp_path}/keys\n"
            f"db_path: {tmp_path}/data/gossip_cli.db\n"
        ),
        encoding="utf-8",
    )
    peer_id = IdentityManager(tmp_path / "peer_keys", "peer-01").generate()
    pub_file = tmp_path / "peer_pub.json"
    pub_file.write_bytes(orjson.dumps(peer_id.public_bundle().model_dump(mode="json")))

    # Create a real ML-DSA-65 signed Merkle checkpoint from peer-01
    async def _make_cp() -> bytes:
        bus = EventBus()
        store = StorageEngine(tmp_path / "peer.db")
        await bus.start()
        await store.initialize()
        try:
            node = MerkleGossipNode(peer_id, store, bus)
            cp = node.create_checkpoint(hashlib.sha256(b"root-1").hexdigest(), tree_size=5)
            return orjson.dumps(cp.model_dump(mode="json"))
        finally:
            await store.close()
            await bus.stop()

    cp_file = tmp_path / "checkpoint.json"
    cp_file.write_bytes(asyncio.run(_make_cp()))

    runner = CliRunner()
    res_v = runner.invoke(
        app,
        ["gossip", "verify-peer", str(cp_file), str(pub_file), "--config", str(cfg_file)],
    )
    assert res_v.exit_code == 0, res_v.output
    assert "accepted=True" in res_v.output

    res_s = runner.invoke(app, ["gossip", "status", "--config", str(cfg_file)])
    assert res_s.exit_code == 0, res_s.output
    assert "peer-01" in res_s.output
