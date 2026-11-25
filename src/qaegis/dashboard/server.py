"""Async HTTP/1.1 + Server-Sent Events (SSE) server for the Q-Aegis Web Dashboard."""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import os
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import h11
import orjson
from pydantic import ValidationError

from qaegis.core.telemetry import get_logger
from qaegis.dashboard.runtime import DashboardKernelRuntime

logger = get_logger(__name__)

_STATIC_DIR = Path(__file__).resolve().parent / "static"
_MAX_BODY_BYTES = 2 * 1024 * 1024  # 2 MiB request body ceiling

_SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
)

_PUBLIC_PATHS: frozenset[str] = frozenset(
    {
        "/",
        "/index.html",
        "/assets/app.css",
        "/assets/app.js",
        "/healthz",
        "/api/auth-status",
    }
)


def _json_bytes(payload: Any) -> bytes:
    return orjson.dumps(payload, default=str)


class DashboardServer:
    """Production async HTTP/1.1 + SSE web server exposing the Q-Aegis Mission-Control UI."""

    def __init__(
        self,
        runtime: DashboardKernelRuntime,
        host: str | None = None,
        port: int | None = None,
        auth_token: str | None = None,
    ) -> None:
        self._runtime = runtime
        self._host = host if host is not None else runtime.config.dashboard.host
        self._port = port if port is not None else runtime.config.dashboard.port
        self._explicit_token = auth_token
        self._server: asyncio.AbstractServer | None = None
        self._bound_host: str = self._host
        self._bound_port: int = self._port
        self._active_tasks: set[asyncio.Task[None]] = set()
        self._shutdown_event = asyncio.Event()

    @property
    def runtime(self) -> DashboardKernelRuntime:
        return self._runtime

    @property
    def bound_address(self) -> tuple[str, int]:
        return (self._bound_host, self._bound_port)

    @property
    def url(self) -> str:
        display_host = "127.0.0.1" if self._bound_host == "0.0.0.0" else self._bound_host  # noqa: S104
        return f"http://{display_host}:{self._bound_port}"

    def _effective_token(self) -> str | None:
        tok = (
            self._explicit_token
            or os.environ.get("QAEGIS_DASHBOARD_TOKEN")
            or self._runtime.config.dashboard.auth_token
        )
        return tok if tok else None

    async def start(self) -> tuple[str, int]:
        """Start the underlying runtime (if not started) and bind the async HTTP server."""
        if self._server is not None:
            return self.bound_address
        self._shutdown_event.clear()
        await self._runtime.start()
        server = await asyncio.start_server(
            self._accept_client,
            host=self._host,
            port=self._port,
        )
        self._server = server
        if server.sockets:
            sock_addr = server.sockets[0].getsockname()
            self._bound_host = str(sock_addr[0])
            self._bound_port = int(sock_addr[1])
        logger.info(
            "dashboard_http_server_started",
            host=self._bound_host,
            port=self._bound_port,
            auth_enabled=self._effective_token() is not None,
        )
        return self.bound_address

    async def stop(self) -> None:
        """Close active HTTP/SSE connections and shut down the server cleanly."""
        self._shutdown_event.set()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        for task in list(self._active_tasks):
            task.cancel()
        if self._active_tasks:
            await asyncio.gather(*self._active_tasks, return_exceptions=True)
        self._active_tasks.clear()
        await self._runtime.stop()
        logger.info("dashboard_http_server_stopped")

    async def __aenter__(self) -> DashboardServer:
        await self.start()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.stop()

    def _accept_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        task = asyncio.create_task(self._handle_connection(reader, writer))
        self._active_tasks.add(task)
        task.add_done_callback(self._active_tasks.discard)

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        conn = h11.Connection(h11.SERVER)
        try:
            while not self._shutdown_event.is_set():
                req_event = await self._next_request_headers(conn, reader)
                if req_event is None:
                    break

                method = req_event.method.decode("ascii", errors="replace").upper()
                target = req_event.target.decode("ascii", errors="replace")
                headers = {
                    k.decode("latin1").lower(): v.decode("latin1") for k, v in req_event.headers
                }

                body_bytes, too_large = await self._read_request_body(conn, reader)
                if too_large:
                    await self._send_response(
                        conn,
                        writer,
                        413,
                        "application/json; charset=utf-8",
                        _json_bytes({"error": "Request body exceeds 2 MiB limit"}),
                        close=True,
                    )
                    break

                parsed = urlsplit(target)
                path = parsed.path or "/"
                query = {k: v[0] for k, v in parse_qs(parsed.query).items() if v}

                if not self._is_authorized(path, headers, query):
                    await self._send_response(
                        conn,
                        writer,
                        401,
                        "application/json; charset=utf-8",
                        _json_bytes(
                            {
                                "error": "Unauthorized: provide Bearer token or X-QAegis-Token",
                                "auth_required": True,
                            }
                        ),
                    )
                elif method == "GET" and path == "/api/events/stream":
                    await self._stream_sse(conn, writer)
                    break
                else:
                    status, content_type, resp_body = await self._dispatch_route(
                        method,
                        path,
                        query,
                        body_bytes,
                    )
                    await self._send_response(conn, writer, status, content_type, resp_body)

                if conn.our_state is h11.MUST_CLOSE or conn.their_state is h11.MUST_CLOSE:
                    break
                conn.start_next_cycle()
        except (asyncio.CancelledError, ConnectionError, h11.RemoteProtocolError):
            return
        except Exception:
            logger.exception("dashboard_connection_error")
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _next_request_headers(
        self,
        conn: h11.Connection,
        reader: asyncio.StreamReader,
    ) -> h11.Request | None:
        while True:
            event = conn.next_event()
            if event is h11.NEED_DATA:
                try:
                    chunk = await asyncio.wait_for(reader.read(16384), timeout=30.0)
                except TimeoutError:
                    return None
                if not chunk:
                    return None
                conn.receive_data(chunk)
                continue
            if isinstance(event, h11.Request):
                return event
            if isinstance(event, h11.ConnectionClosed) or event is h11.PAUSED:
                return None

    async def _read_request_body(
        self,
        conn: h11.Connection,
        reader: asyncio.StreamReader,
    ) -> tuple[bytes, bool]:
        buf = bytearray()
        while True:
            event = conn.next_event()
            if event is h11.NEED_DATA:
                chunk = await asyncio.wait_for(reader.read(16384), timeout=30.0)
                if not chunk:
                    conn.receive_data(b"")
                else:
                    conn.receive_data(chunk)
                continue
            if isinstance(event, h11.Data):
                buf.extend(event.data)
                if len(buf) > _MAX_BODY_BYTES:
                    return (b"", True)
                continue
            if isinstance(event, h11.EndOfMessage):
                return (bytes(buf), False)
            return (bytes(buf), False)

    def _is_authorized(
        self,
        path: str,
        headers: dict[str, str],
        query: dict[str, str],
    ) -> bool:
        if path in _PUBLIC_PATHS:
            return True
        required = self._effective_token()
        if required is None:
            return True
        candidate = ""
        auth_hdr = headers.get("authorization", "")
        if auth_hdr.lower().startswith("bearer "):
            candidate = auth_hdr[7:].strip()
        elif "x-qaegis-token" in headers:
            candidate = headers["x-qaegis-token"].strip()
        elif "token" in query:
            candidate = query["token"].strip()
        if not candidate:
            return False
        return hmac.compare_digest(candidate.encode("utf-8"), required.encode("utf-8"))

    async def _send_response(
        self,
        conn: h11.Connection,
        writer: asyncio.StreamWriter,
        status: int,
        content_type: str,
        body: bytes,
        close: bool = False,
    ) -> None:
        resp_headers: list[tuple[str, str]] = [
            ("Content-Type", content_type),
            ("Content-Length", str(len(body))),
            *_SECURITY_HEADERS,
        ]
        if close:
            resp_headers.append(("Connection", "close"))
        raw_head = conn.send(h11.Response(status_code=status, headers=resp_headers))
        raw_body = conn.send(h11.Data(data=body))
        raw_end = conn.send(h11.EndOfMessage())
        writer.write(raw_head + raw_body + raw_end)
        await writer.drain()

    async def _stream_sse(
        self,
        conn: h11.Connection,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Stream real-time EventBus envelopes and telemetry ticks via Server-Sent Events."""
        sse_headers: list[tuple[str, str]] = [
            ("Content-Type", "text/event-stream; charset=utf-8"),
            ("Cache-Control", "no-cache"),
            ("Transfer-Encoding", "chunked"),
            ("Connection", "close"),
            ("X-Accel-Buffering", "no"),
            *_SECURITY_HEADERS,
        ]
        writer.write(conn.send(h11.Response(status_code=200, headers=sse_headers)))
        await writer.drain()

        queue = self._runtime.open_sse_queue()
        heartbeat_s = self._runtime.config.dashboard.sse_heartbeat_s
        try:
            initial = await self._runtime.get_overview()
            init_frame = b"event: overview\ndata: " + _json_bytes(initial) + b"\n\n"
            writer.write(conn.send(h11.Data(data=init_frame)))
            await writer.drain()

            while not self._shutdown_event.is_set():
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=heartbeat_s)
                    ev_name = str(msg.get("type", "message")).encode("ascii")
                    frame = (
                        b"event: "
                        + ev_name
                        + b"\ndata: "
                        + _json_bytes(msg.get("data", {}))
                        + b"\n\n"
                    )
                except TimeoutError:
                    snap = await self._runtime.get_overview()
                    frame = b"event: overview\ndata: " + _json_bytes(snap) + b"\n\n"
                writer.write(conn.send(h11.Data(data=frame)))
                await writer.drain()
        except (asyncio.CancelledError, ConnectionError):
            raise
        finally:
            self._runtime.close_sse_queue(queue)
            with contextlib.suppress(Exception):
                writer.write(conn.send(h11.EndOfMessage()))
                await writer.drain()

    async def _dispatch_route(
        self,
        method: str,
        path: str,
        query: dict[str, str],
        body: bytes,
    ) -> tuple[int, str, bytes]:
        try:
            # Static web assets
            if method == "GET" and path in ("/", "/index.html"):
                html = (_STATIC_DIR / "index.html").read_bytes()
                return (200, "text/html; charset=utf-8", html)
            if method == "GET" and path == "/assets/app.css":
                css = (_STATIC_DIR / "app.css").read_bytes()
                return (200, "text/css; charset=utf-8", css)
            if method == "GET" and path == "/assets/app.js":
                js = (_STATIC_DIR / "app.js").read_bytes()
                return (200, "application/javascript; charset=utf-8", js)
            if method == "GET" and path == "/healthz":
                return (
                    200,
                    "application/json; charset=utf-8",
                    _json_bytes({"status": "ok", "node_id": self._runtime.config.node_id}),
                )
            if method == "GET" and path == "/api/auth-status":
                return (
                    200,
                    "application/json; charset=utf-8",
                    _json_bytes({"auth_required": self._effective_token() is not None}),
                )

            payload: dict[str, Any] = {}
            if body:
                decoded = orjson.loads(body)
                if not isinstance(decoded, dict):
                    raise ValueError("JSON request body must be an object")
                payload = decoded

            result = await self._handle_api(method, path, query, payload)
            if isinstance(result, str):
                return (200, "text/plain; version=0.0.4; charset=utf-8", result.encode("utf-8"))
            return (200, "application/json; charset=utf-8", _json_bytes(result))
        except ValidationError as exc:
            return (
                422,
                "application/json; charset=utf-8",
                _json_bytes({"error": "Configuration validation failed", "details": exc.errors()}),
            )
        except (ValueError, KeyError, orjson.JSONDecodeError) as exc:
            return (
                400,
                "application/json; charset=utf-8",
                _json_bytes({"error": str(exc)}),
            )
        except FileNotFoundError:
            return (
                404,
                "application/json; charset=utf-8",
                _json_bytes({"error": f"Route not found: {method} {path}"}),
            )
        except Exception as exc:
            logger.exception("dashboard_api_error", method=method, path=path)
            return (
                500,
                "application/json; charset=utf-8",
                _json_bytes({"error": f"Internal error: {exc}"}),
            )

    async def _handle_api(
        self,
        method: str,
        path: str,
        query: dict[str, str],
        payload: dict[str, Any],
    ) -> dict[str, Any] | str:
        rt = self._runtime

        if method == "GET" and path == "/api/overview":
            return await rt.get_overview()
        if method == "GET" and path == "/api/doctor":
            return await rt.get_diagnostics()
        if method == "GET" and path == "/api/events/recent":
            limit = int(query.get("limit", "100"))
            return {"events": rt.get_recent_events(limit=max(1, min(limit, 500)))}

        # Configuration Center
        if method == "GET" and path == "/api/config":
            return rt.get_config_bundle(redact_secrets=True)
        if method in ("PUT", "PATCH", "POST") and path == "/api/config":
            persist = bool(payload.get("persist_yaml", True))
            patch = payload.get("config", payload)
            if not isinstance(patch, dict):
                raise ValueError("'config' field must be a JSON mapping")
            return await rt.update_config(patch, persist_yaml=persist)
        if method == "POST" and path == "/api/config/yaml":
            yaml_text = str(payload.get("yaml", ""))
            persist = bool(payload.get("persist_yaml", True))
            return await rt.update_config_from_yaml(yaml_text, persist_yaml=persist)
        if method == "POST" and path == "/api/config/reset":
            persist = bool(payload.get("persist_yaml", True))
            return await rt.reset_default_config(persist_yaml=persist)

        # Lifecycle
        if method == "POST" and path == "/api/lifecycle/mode":
            return await rt.set_lifecycle_mode(
                mode=str(payload["mode"]),
                reason=str(payload.get("reason", "dashboard_operator")),
            )

        # Identity, Key Rotation & CBOM
        if method == "GET" and path == "/api/identity":
            return rt.get_identity_summary()
        if method == "POST" and path == "/api/identity/rotate":
            return await rt.rotate_identity_keys(
                seal_backend=payload.get("seal_backend"),
                token_label=payload.get("token_label"),
                user_pin=payload.get("user_pin"),
                remove_plaintext=bool(payload.get("remove_plaintext", False)),
            )
        if method == "GET" and path == "/api/identity/cbom":
            fmt = query.get("format", "cyclonedx")
            return rt.export_cbom(fmt=fmt)

        # Module 1: Proof of Reality & Merkle Gossip
        if method == "GET" and path == "/api/reality/state":
            return await rt.list_reality_state()
        if method == "POST" and path == "/api/reality/stamp":
            return await rt.create_stamp(
                sensor_id=str(payload.get("sensor_id", "lidar-front-01")),
                perception_label=str(payload.get("perception_label", "pedestrian_detected")),
                confidence=float(payload.get("confidence", 0.97)),
                metadata=dict(payload.get("metadata", {})),
                use_stateless_hash_sig=bool(payload.get("use_stateless_hash_sig", False)),
            )
        if method == "POST" and path == "/api/reality/verify":
            stamp_obj = payload.get("stamp", payload)
            if not isinstance(stamp_obj, dict):
                raise ValueError("Expected 'stamp' object")
            return rt.verify_stamp_payload(stamp_obj)
        if method == "POST" and path == "/api/reality/qrng":
            n_bytes = int(payload.get("num_bytes", 64))
            return await rt.harvest_qrng(num_bytes=max(32, min(n_bytes, 4096)))
        if method == "GET" and path == "/api/gossip":
            return await rt.get_gossip_state()
        if method == "POST" and path == "/api/gossip/checkpoint":
            return await rt.sign_local_gossip_checkpoint()

        # Module 2: Quantum Chameleon Firewall
        if method == "POST" and path == "/api/chameleon/protect":
            sens_val: Any = str(payload.get("sensitivity", "confidential"))
            min_tier = payload.get("minimum_tier") or None
            return await rt.run_chameleon_protection(
                protocol=str(payload.get("protocol", "wan")),
                sensitivity=sens_val,
                retention_years=float(payload.get("retention_years", 6.0)),
                payload_text=str(payload.get("payload_text", "autonomous_telemetry_frame_01")),
                minimum_tier=str(min_tier) if min_tier else None,
            )

        # Module 3: AI-to-Qubit Compiler
        if method == "POST" and path == "/api/compiler/compile":
            raw_vec = payload.get("vector", [0.5, -0.2, 0.8, 0.1, 0.4, -0.7, 0.9, 0.2])
            vec = [float(x) for x in raw_vec]
            return await rt.compile_sensor_vector(
                vector=vec,
                run_pennylane=bool(payload.get("run_pennylane", True)),
            )
        if method == "POST" and path == "/api/compiler/train":
            return await rt.train_and_export_autoencoder(
                epochs=max(1, min(int(payload.get("epochs", 25)), 200)),
                samples_count=max(16, min(int(payload.get("samples_count", 64)), 512)),
                lr=float(payload.get("lr", 0.01)),
            )

        # Module 4: Quantum Dreamer
        if method == "GET" and path == "/api/dreamer/state":
            return await rt.list_dreamer_state()
        if method == "POST" and path == "/api/dreamer/enqueue":
            return await rt.enqueue_dream_problem(
                kind=str(payload.get("kind", "maxcut")),
                priority=int(payload.get("priority", 75)),
                policy_name=str(payload.get("policy_name", "edge_routing_policy")),
                num_nodes=max(2, min(int(payload.get("num_nodes", 4)), 10)),
                edges=payload.get("edges"),
                task_costs=payload.get("task_costs"),
                conflicts=payload.get("conflicts"),
                target_active_tasks=int(payload.get("target_active_tasks", 2)),
                utilities=payload.get("utilities"),
                costs=payload.get("costs"),
            )
        if method == "POST" and path == "/api/dreamer/run-night":
            return await rt.run_night_cycle(
                max_problems=max(1, min(int(payload.get("max_problems", 4)), 32)),
                backend_override=payload.get("backend") or None,
                mitigation_override=payload.get("mitigation") or None,
            )
        if method == "POST" and path == "/api/dreamer/federated":
            return await rt.run_federated_demo(
                fleet_nodes=int(payload.get("fleet_nodes", 3)),
                budget_seconds=float(payload.get("budget_seconds", 120.0)),
            )

        # Module 5: Quantum Entropy & Audit / Metrics
        if method == "POST" and path == "/api/entropy/harvest":
            return await rt.harvest_entropy_batch(
                num_qubits=int(payload["num_qubits"]) if "num_qubits" in payload else None,
                shots=int(payload["shots"]) if "shots" in payload else None,
                noise_rate=float(payload.get("noise_rate", 0.01)),
            )
        if method == "POST" and path == "/api/entropy/sample-logits":
            logits = [float(x) for x in payload.get("logits", [2.1, 1.8, 0.9, 0.4, -0.5, -1.2])]
            return await rt.sample_quantum_logits(
                logits=logits,
                temperature=float(payload.get("temperature", 0.8)),
                top_k=int(payload.get("top_k", 40)),
                top_p=float(payload.get("top_p", 0.9)),
            )
        if method == "POST" and path == "/api/entropy/evolve":
            return await rt.run_quantum_evolution(
                genome_dim=max(2, min(int(payload.get("genome_dim", 6)), 32)),
                population_size=max(4, min(int(payload.get("population_size", 12)), 64)),
                generations=max(2, min(int(payload.get("generations", 20)), 100)),
            )
        if method == "GET" and path == "/api/entropy/ollama":
            return await rt.check_ollama_status()
        if method == "GET" and path == "/api/audit":
            limit = int(query.get("limit", "100"))
            return await rt.list_audit_ledger(limit=max(1, min(limit, 500)))
        if method == "GET" and path == "/api/metrics/raw":
            return rt.render_prometheus_metrics()

        raise FileNotFoundError(path)
