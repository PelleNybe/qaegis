"""Distributed multi-node Merkle root gossip protocol over CurveZMQ with ML-DSA-65 auth."""

from __future__ import annotations

import asyncio
import base64
from datetime import UTC, datetime

import orjson
import zmq
import zmq.asyncio
from pydantic import BaseModel, Field
from zmq.auth.asyncio import AsyncioAuthenticator

from qaegis.core.bus import (
    CurveKeyPair,
    CurvePeerAllowlistProvider,
    EventBus,
    generate_curve_keypair,
)
from qaegis.core.identity import (
    DeviceIdentity,
    PublicIdentityBundle,
    compute_key_fingerprint,
    constant_time_equal,
)
from qaegis.core.storage import StorageEngine
from qaegis.core.telemetry import QAegisMetrics, get_logger

logger = get_logger(__name__)


class MerkleGossipEnvelope(BaseModel):
    """ML-DSA-65 signed Merkle root checkpoint broadcast across the Q-Aegis edge fleet."""

    node_id: str
    merkle_root: str = Field(min_length=64, max_length=64)
    tree_size: int = Field(ge=0)
    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    key_id: str
    sig_alg: str
    public_key_fingerprint: str
    signature_b64: str

    def signing_bytes(self) -> bytes:
        """Canonical deterministic payload authenticated by the node's ML-DSA-65 key."""
        doc = {
            "key_id": self.key_id,
            "merkle_root": self.merkle_root,
            "node_id": self.node_id,
            "public_key_fingerprint": self.public_key_fingerprint,
            "sig_alg": self.sig_alg,
            "timestamp_utc": self.timestamp_utc.isoformat(),
            "tree_size": self.tree_size,
        }
        return orjson.dumps(doc, option=orjson.OPT_SORT_KEYS)


class EquivocationAlert(BaseModel):
    """Critical security alert emitted when a peer signs conflicting roots at the same size."""

    peer_node_id: str
    tree_size: int
    expected_root: str
    conflicting_root: str
    detected_at_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    offending_envelope: MerkleGossipEnvelope


class GossipVerificationOutcome(BaseModel):
    """Result of verifying and storing an incoming peer Merkle root checkpoint."""

    accepted: bool
    reason: str
    equivocation_alert: EquivocationAlert | None = None


class MerkleGossipNode:
    """P2P Merkle root cross-witnessing node using ML-DSA-65 signatures and CurveZMQ sockets."""

    def __init__(
        self,
        identity: DeviceIdentity,
        storage: StorageEngine,
        bus: EventBus,
        trusted_peers: dict[str, PublicIdentityBundle] | None = None,
        metrics: QAegisMetrics | None = None,
        curve_keypair: CurveKeyPair | None = None,
    ) -> None:
        self._identity = identity
        self._storage = storage
        self._bus = bus
        self._metrics = metrics or QAegisMetrics()
        self._curve_kp = curve_keypair or generate_curve_keypair()
        self._trusted_peers: dict[str, PublicIdentityBundle] = dict(trusted_peers or {})
        self._trusted_peers[identity.node_id] = identity.public_bundle()

        self._seen_keys: set[tuple[str, int, str]] = set()
        self._latest_roots: dict[str, tuple[int, str]] = {}
        self._equivocation_alerts: list[EquivocationAlert] = []

        # CurveZMQ P2P mesh sockets
        self._ctx: zmq.asyncio.Context | None = None
        self._auth: AsyncioAuthenticator | None = None
        self._allowlist: CurvePeerAllowlistProvider | None = None
        self._pub_sock: zmq.asyncio.Socket | None = None
        self._sub_socks: list[zmq.asyncio.Socket] = []
        self._reader_tasks: list[asyncio.Task[None]] = []
        self._bound_endpoint: str | None = None
        self._running = False

    @property
    def node_id(self) -> str:
        return self._identity.node_id

    @property
    def curve_public_key(self) -> str:
        return self._curve_kp.public_key

    @property
    def bound_endpoint(self) -> str | None:
        return self._bound_endpoint

    @property
    def equivocation_alerts(self) -> list[EquivocationAlert]:
        return list(self._equivocation_alerts)

    @property
    def latest_roots(self) -> dict[str, tuple[int, str]]:
        """Map of peer_node_id -> (highest_verified_tree_size, merkle_root)."""
        return dict(self._latest_roots)

    def register_trusted_peer(
        self,
        bundle: PublicIdentityBundle,
        curve_public_key: str | None = None,
    ) -> None:
        """Add a peer's PQC public identity (and optional CurveZMQ key) to the trust store."""
        self._trusted_peers[bundle.node_id] = bundle
        if curve_public_key is not None and self._allowlist is not None:
            self._allowlist.allow_key(curve_public_key)

    def create_checkpoint(self, merkle_root: str, tree_size: int) -> MerkleGossipEnvelope:
        """Sign this node's current Merkle root using ML-DSA-65."""
        fp = compute_key_fingerprint(self._identity.primary_sig_public)
        unsigned = MerkleGossipEnvelope(
            node_id=self._identity.node_id,
            merkle_root=merkle_root,
            tree_size=tree_size,
            key_id=self._identity.key_id,
            sig_alg=self._identity.primary_sig_alg,
            public_key_fingerprint=fp,
            signature_b64="",
        )
        alg, signature = self._identity.sign(unsigned.signing_bytes(), use_fallback=False)
        return unsigned.model_copy(
            update={
                "sig_alg": alg,
                "signature_b64": base64.b64encode(signature).decode("ascii"),
            }
        )

    async def start_mesh(
        self,
        bind_endpoint: str = "tcp://127.0.0.1:0",
        allowed_curve_keys: list[str] | None = None,
    ) -> str:
        """Start this node's CurveZMQ gossip publisher socket with ZAP authentication."""
        if self._running:
            if self._bound_endpoint is None:
                raise RuntimeError("Gossip node is running without a bound endpoint")
            return self._bound_endpoint
        self._running = True
        self._ctx = zmq.asyncio.Context()
        self._auth = AsyncioAuthenticator(self._ctx)
        self._auth.start()

        allowed = {k.encode("ascii") for k in (allowed_curve_keys or [])}
        allowed.add(self._curve_kp.public_key.encode("ascii"))
        self._allowlist = CurvePeerAllowlistProvider(allowed, self._metrics)
        self._auth.configure_curve_callback(domain="*", credentials_provider=self._allowlist)

        self._pub_sock = self._ctx.socket(zmq.PUB)
        self._pub_sock.setsockopt(zmq.CURVE_SERVER, 1)
        self._pub_sock.setsockopt(zmq.CURVE_SECRETKEY, self._curve_kp.secret_key.encode("ascii"))
        self._pub_sock.setsockopt(zmq.CURVE_PUBLICKEY, self._curve_kp.public_key.encode("ascii"))
        self._pub_sock.bind(bind_endpoint)
        raw_ep = self._pub_sock.getsockopt(zmq.LAST_ENDPOINT)
        self._bound_endpoint = raw_ep.decode("utf-8") if isinstance(raw_ep, bytes) else str(raw_ep)
        logger.info("gossip_node_started", node_id=self.node_id, endpoint=self._bound_endpoint)
        return self._bound_endpoint

    async def connect_peer(self, peer_endpoint: str, peer_curve_public_key: str) -> None:
        """Subscribe to a remote peer's CurveZMQ gossip publisher socket."""
        if self._ctx is None:
            raise RuntimeError("Call start_mesh() before connecting to gossip peers")
        sub = self._ctx.socket(zmq.SUB)
        sub.setsockopt(zmq.CURVE_SERVERKEY, peer_curve_public_key.encode("ascii"))
        sub.setsockopt(zmq.CURVE_PUBLICKEY, self._curve_kp.public_key.encode("ascii"))
        sub.setsockopt(zmq.CURVE_SECRETKEY, self._curve_kp.secret_key.encode("ascii"))
        sub.connect(peer_endpoint)
        sub.setsockopt(zmq.SUBSCRIBE, b"gossip.root")
        self._sub_socks.append(sub)
        self._reader_tasks.append(asyncio.create_task(self._peer_receive_loop(sub)))

    async def stop_mesh(self) -> None:
        """Gracefully close CurveZMQ gossip sockets and background reader tasks."""
        if not self._running:
            return
        self._running = False
        for task in self._reader_tasks:
            task.cancel()
        if self._reader_tasks:
            await asyncio.gather(*self._reader_tasks, return_exceptions=True)
        self._reader_tasks.clear()

        for sock in self._sub_socks:
            sock.close(linger=0)
        self._sub_socks.clear()
        if self._pub_sock is not None:
            self._pub_sock.close(linger=0)
            self._pub_sock = None
        if self._auth is not None:
            self._auth.stop()
            self._auth = None
        if self._ctx is not None:
            self._ctx.term()
            self._ctx = None
        self._bound_endpoint = None

    async def broadcast_checkpoint(self, envelope: MerkleGossipEnvelope) -> None:
        """Persist own/verified checkpoint and broadcast over CurveZMQ to connected peers."""
        await self.ingest_checkpoint(envelope, rebroadcast=False)
        await self._emit_wire(envelope)

    async def _emit_wire(self, envelope: MerkleGossipEnvelope) -> None:
        if self._pub_sock is not None:
            raw = orjson.dumps(envelope.model_dump(mode="json"), option=orjson.OPT_SORT_KEYS)
            await self._pub_sock.send_multipart([b"gossip.root", raw])

    async def ingest_checkpoint(
        self,
        envelope: MerkleGossipEnvelope,
        rebroadcast: bool = True,
    ) -> GossipVerificationOutcome:
        """Verify peer ML-DSA-65 signature, check for split-view equivocation, and persist."""
        peer_bundle = self._trusted_peers.get(envelope.node_id)
        if peer_bundle is None:
            return GossipVerificationOutcome(
                accepted=False,
                reason=f"untrusted_peer:{envelope.node_id}",
            )

        if not constant_time_equal(
            envelope.public_key_fingerprint.encode("ascii"),
            peer_bundle.primary_sig_fingerprint.encode("ascii"),
        ):
            return GossipVerificationOutcome(
                accepted=False,
                reason="fingerprint_mismatch",
            )

        try:
            sig_bytes = base64.b64decode(envelope.signature_b64)
            pub_bytes = base64.b64decode(peer_bundle.primary_sig_public_b64)
            sig_ok = DeviceIdentity.verify(
                envelope.signing_bytes(),
                sig_bytes,
                pub_bytes,
                envelope.sig_alg,
            )
        except Exception as exc:
            return GossipVerificationOutcome(
                accepted=False,
                reason=f"signature_error:{exc}",
            )

        if not sig_ok:
            return GossipVerificationOutcome(
                accepted=False,
                reason="invalid_mldsa_signature",
            )

        # Equivocation check: conflicting root signed by same peer at the same tree_size
        existing = await self._storage.get_peer_checkpoint_at_size(
            envelope.node_id,
            envelope.tree_size,
        )
        if existing is not None and not constant_time_equal(
            str(existing["merkle_root"]).encode("ascii"),
            envelope.merkle_root.encode("ascii"),
        ):
            alert = EquivocationAlert(
                peer_node_id=envelope.node_id,
                tree_size=envelope.tree_size,
                expected_root=str(existing["merkle_root"]),
                conflicting_root=envelope.merkle_root,
                offending_envelope=envelope,
            )
            self._equivocation_alerts.append(alert)
            self._metrics.gossip_equivocations.labels(peer_node_id=envelope.node_id).inc()
            await self._storage.append_audit_event(
                event_type="gossip.equivocation_detected",
                actor=self.node_id,
                payload={
                    "peer_node_id": envelope.node_id,
                    "tree_size": envelope.tree_size,
                    "expected_root": alert.expected_root,
                    "conflicting_root": alert.conflicting_root,
                },
            )
            await self._bus.publish(
                topic="gossip.equivocation_detected",
                source="modules.reality_stamp.gossip",
                payload=alert.model_dump(mode="json"),
            )
            logger.error(
                "merkle_equivocation_detected",
                peer_node_id=envelope.node_id,
                tree_size=envelope.tree_size,
            )
            return GossipVerificationOutcome(
                accepted=False,
                reason="equivocation_detected",
                equivocation_alert=alert,
            )

        dedup_key = (envelope.node_id, envelope.tree_size, envelope.merkle_root)
        if dedup_key in self._seen_keys:
            return GossipVerificationOutcome(accepted=True, reason="already_witnessed")

        self._seen_keys.add(dedup_key)
        await self._storage.save_gossip_checkpoint(
            peer_node_id=envelope.node_id,
            tree_size=envelope.tree_size,
            merkle_root=envelope.merkle_root,
            timestamp_utc=envelope.timestamp_utc.isoformat(),
            sig_alg=envelope.sig_alg,
            signature_b64=envelope.signature_b64,
            public_key_fingerprint=envelope.public_key_fingerprint,
            status="VERIFIED",
        )
        prev = self._latest_roots.get(envelope.node_id)
        if prev is None or envelope.tree_size >= prev[0]:
            self._latest_roots[envelope.node_id] = (envelope.tree_size, envelope.merkle_root)

        self._metrics.gossip_roots_accepted.labels(peer_node_id=envelope.node_id).inc()
        await self._bus.publish(
            topic="gossip.checkpoint_verified",
            source="modules.reality_stamp.gossip",
            payload={
                "peer_node_id": envelope.node_id,
                "tree_size": envelope.tree_size,
                "merkle_root": envelope.merkle_root,
            },
        )
        if rebroadcast:
            await self._emit_wire(envelope)
        return GossipVerificationOutcome(accepted=True, reason="verified_and_persisted")

    async def _peer_receive_loop(self, sock: zmq.asyncio.Socket) -> None:
        while self._running:
            try:
                frames = await sock.recv_multipart()
                if len(frames) != 2:
                    continue
                env = MerkleGossipEnvelope.model_validate(orjson.loads(frames[1]))
                await self.ingest_checkpoint(env, rebroadcast=True)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("gossip_receive_error", node_id=self.node_id)
