"""App-owned OpenSSH reverse tunnels with durable intent and real probes."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ipaddress
import os
import random
import re
import stat
import time
import uuid
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.monitoring.codex_credentials import SOURCE, CodexCredentialCheck, build_remote_codex_command
from app.monitoring.codex_model_test import (
    ModelPreview,
    ModelTestResult,
    build_remote_model_preview_command,
    build_remote_model_test_command,
)
from app.monitoring.health import HealthProbe, build_remote_curl_command, validate_health_url
from app.proxies.manager import ProxyError, ProxyManager, private_directory, private_write

Publish = Callable[[dict[str, Any]], Awaitable[None] | None]
STATES = {"STOPPED", "STARTING", "HEALTHY", "DEGRADED", "RECONNECTING", "FAILED", "AUTH_REQUIRED", "PORT_CONFLICT"}
MODES = {"MAC_DIRECT", "CLASH_HTTP", "DISABLED"}


class EngineError(RuntimeError):
    def __init__(self, code: str, message: str, *, status_code: int = 409, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.code, self.message, self.status_code = code, message, status_code
        self.details = details or {}


@dataclass
class RunHandle:
    server_id: str
    run_id: str
    generation: int
    nonce: str
    process: asyncio.subprocess.Process
    config_path: Path
    control_socket: Path
    alias: str
    argv: tuple[str, ...]
    config_digest: str
    signature: str | None = None
    socket_identity: tuple[int, int] | None = None
    stderr: deque[str] = field(default_factory=lambda: deque(maxlen=40))
    drains: list[asyncio.Task[None]] = field(default_factory=list)


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _digest(value: bytes | str) -> str:
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()


class TunnelManager:
    """Never adopts external PIDs or executes a user's SSH configuration."""

    def __init__(self, data_dir: Path, repo: Any, publish: Publish | None = None,
                 ssh_executable: str = "/usr/bin/ssh", tinyproxy_executable: str | None = None) -> None:
        self.data_dir = Path(data_dir)
        if not self.data_dir.is_absolute() or self.data_dir.is_symlink():
            raise EngineError("UNSAFE_STORAGE", "Data directory must be an absolute non-symlink path")
        self.repo, self.publish = repo, publish
        self.ssh_executable = str(Path(ssh_executable).resolve())
        self.run_dir = self.data_dir / "tunnels"
        private_directory(self.run_dir)
        project_root = next((path for path in (self.data_dir, *self.data_dir.parents)
                             if (path / "AGENTS.md").is_file()), self.data_dir.parent.parent)
        self.socket_dir = project_root / ".run" / "s"
        private_directory(self.socket_dir.parent)
        private_directory(self.socket_dir)
        self.proxy = ProxyManager(self.data_dir, tinyproxy_executable)
        self._runs: dict[str, RunHandle] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._generation: dict[str, int] = {}
        self._desired: dict[str, str] = {}
        self._monitors: dict[str, asyncio.Task[None]] = {}
        self._owned: dict[str, tuple[Any, ...]] = {}
        self._reservations: dict[tuple[str, int], tuple[str, int]] = {}
        self._runtime: dict[str, dict[str, Any]] = {}
        self._probe_condition = asyncio.Condition()
        self._active_probes = 0
        self._model_test_started: dict[str, float] = {}
        self._closed = False

    def _lock(self, server_id: str) -> asyncio.Lock:
        return self._locks.setdefault(server_id, asyncio.Lock())

    def _server(self, server_id: str) -> dict[str, Any]:
        server = self.repo.get_server(server_id)
        if not server:
            raise EngineError("SERVER_NOT_FOUND", "Server does not exist", status_code=404)
        if server.get("management") != "MANAGED":
            raise EngineError("EXTERNAL_RESOURCE", "External SSH resources are observed only", status_code=403)
        return dict(server)

    def _settings(self) -> dict[str, Any]:
        return self.repo.settings()

    def _persist_desired(self, server_id: str, desired: str) -> None:
        try:
            self.repo.update_server(server_id, {"desired_state": desired})
        except Exception as exc:
            raise EngineError("STORAGE_UNAVAILABLE", "Desired state was not saved; no process action was taken", status_code=503) from exc
        self._desired[server_id] = desired

    def _default(self, server_id: str) -> dict[str, Any]:
        return {
            "server_id": server_id, "state": "STOPPED", "reason_code": None,
            "generation": self._generation.get(server_id, 0), "run_id": None,
            "process_alive": False, "ssh_connected": False, "remote_listener": "UNKNOWN",
            "proxy_health": "UNKNOWN", "http_status": None, "total_ms": None,
            "http_transport_ok": False, "http_connect_status": None, "ssh_latency_ms": None,
            "tls_completed_ms": None, "tls_handshake_ms": None, "consecutive_failures": 0,
            "reconnect_count": 0, "last_disconnected_at": None, "last_recovered_at": None,
            "observed_at": _now(), "stale": False, "pid": None,
            "direct_path_verification": "UNVERIFIED", "monitoring_capability": "PARTIAL", "evidence": [],
        }

    def snapshot(self, server_id: str) -> dict[str, Any]:
        runtime = dict(self._runtime.get(server_id) or self.repo.get_runtime(server_id) or self._default(server_id))
        run = self._runs.get(server_id)
        runtime["process_alive"] = bool(run and run.process.returncode is None)
        runtime["pid"] = run.process.pid if runtime["process_alive"] else None
        if not runtime["process_alive"]:
            runtime["ssh_connected"] = False
            if runtime.get("state") == "HEALTHY":
                runtime.update(state="DEGRADED", reason_code="SSH_DISCONNECTED", stale=True,
                               remote_listener="UNKNOWN", proxy_health="UNKNOWN")
        if not run:
            runtime["ssh_connected"] = False
            if runtime.get("state") in {"HEALTHY", "STARTING", "RECONNECTING", "DEGRADED"}:
                runtime.update(state="DEGRADED", reason_code="STALE_EVIDENCE", stale=True)
        try:
            age = datetime.now(UTC) - datetime.fromisoformat(runtime["observed_at"])
            if age.total_seconds() > max(45, float(self._settings().get("health_interval_s", 15)) * 3):
                runtime["stale"] = True
                if runtime["state"] == "HEALTHY":
                    runtime.update(state="DEGRADED", reason_code="STALE_EVIDENCE")
        except (ValueError, KeyError):
            runtime["stale"] = True
        return runtime

    async def _emit(self, event: dict[str, Any]) -> None:
        if self.publish:
            with contextlib.suppress(Exception):
                result = self.publish(event)
                if asyncio.iscoroutine(result):
                    await result

    async def _state(self, server_id: str, state: str, reason: str | None = None, **updates: Any) -> dict[str, Any]:
        assert state in STATES
        current = dict(self._runtime.get(server_id) or self._default(server_id))
        previous = current["state"]
        current.update(updates)
        current.update(state=state, reason_code=reason, observed_at=_now())
        if state == "HEALTHY" and previous != "HEALTHY":
            current["last_recovered_at"] = _now()
        if previous == "HEALTHY" and state != "HEALTHY":
            current["last_disconnected_at"] = _now()
        try:
            self.repo.save_runtime(current)
        except Exception as exc:
            raise EngineError("STORAGE_UNAVAILABLE", "Runtime evidence could not be persisted", status_code=503) from exc
        self._runtime[server_id] = current
        await self._emit({"type": "server.state", "server_id": server_id, "payload": dict(current)})
        return dict(current)

    async def start(self, server_id: str) -> dict[str, Any]:
        async with self._lock(server_id):
            self._server(server_id)
            self._persist_desired(server_id, "RUNNING")
            result = await self._start_locked(server_id)
            self._ensure_monitor(server_id)
            return result

    async def _start_locked(self, server_id: str) -> dict[str, Any]:
        if self._closed:
            raise EngineError("ENGINE_CLOSED", "Tunnel engine is closed", status_code=503)
        server = self._server(server_id)
        mode = str(server.get("mode"))
        if mode == "DISABLED":
            self._persist_desired(server_id, "STOPPED")
            return await self._state(server_id, "STOPPED", "DISABLED")
        if mode not in MODES:
            raise EngineError("INVALID_MODE", "Unsupported proxy mode", status_code=422)
        old = self._runs.get(server_id)
        if old and old.process.returncode is None:
            return self.snapshot(server_id)
        if old:
            await self._dispose(old)
        generation = self._generation.get(server_id, 0) + 1
        self._generation[server_id] = generation
        run_id = uuid.uuid4().hex
        await self._state(server_id, "STARTING", generation=generation, run_id=run_id,
                          process_alive=False, ssh_connected=False, remote_listener="UNKNOWN", pid=None,
                          proxy_health="UNKNOWN", http_transport_ok=False, http_connect_status=None,
                          ssh_latency_ms=None, http_status=None, total_ms=None, tls_completed_ms=None,
                          tls_handshake_ms=None, stale=False)
        try:
            remote_port = self._port(server["remote_proxy_port"], minimum=1024)
            if remote_port in {17890, 17891}:
                raise EngineError("PROTECTED_PRODUCTION_PORT", "Use an isolated remote port; production migration is not authorized")
            host, user = self._validate_host(server["host"]), self._validate_user(server["user"])
            ssh_port = self._port(server["ssh_port"])
            endpoint = _digest(f"{host.lower()}:{ssh_port}:{user}")
            key = (endpoint, remote_port)
            reserved = self._reservations.get(key)
            if reserved and reserved[0] != server_id:
                raise EngineError("PORT_CONFLICT", "Remote endpoint and port are already reserved")
            self._reservations[key] = (server_id, generation)
            local_port = await self.proxy.ensure_for_mode(mode, int(server["proxy_port"]), server_id)
            alias = "tm-" + run_id[:12]
            config, control = self._profile(server, alias, run_id, local_port)
            argv = (self.ssh_executable, "-F", str(config), "-N", "-T", "-n", "-M", "-S", str(control), alias)
            process = await asyncio.create_subprocess_exec(*argv, stdin=asyncio.subprocess.DEVNULL,
                                                         stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            handle = RunHandle(server_id, run_id, generation, uuid.uuid4().hex, process, config, control,
                               alias, argv, _digest(config.read_bytes()))
            self._runs[server_id] = handle
            self._owned[run_id] = (process, process.pid, handle.nonce, handle.argv, config, control)
            handle.signature = await self._signature(process)
            for stream in (process.stdout, process.stderr):
                if stream:
                    handle.drains.append(asyncio.create_task(self._drain(handle, stream)))
            deadline = time.monotonic() + float(self._settings().get("connect_timeout_s", 15))
            connected = False
            while process.returncode is None and time.monotonic() < deadline:
                if await self._control_check(handle):
                    connected = True
                    break
                await asyncio.sleep(0.15)
            if process.returncode is not None:
                await asyncio.sleep(0)
                reason = self._classify(" ".join(handle.stderr))
                await self._dispose(handle)
                return await self._state(server_id, reason if reason in {"AUTH_REQUIRED", "PORT_CONFLICT"} else "FAILED",
                                         reason, process_alive=False, ssh_connected=False, pid=None)
            if not connected:
                await self._dispose(handle)
                return await self._state(server_id, "FAILED", "SSH_TIMEOUT", process_alive=False, ssh_connected=False, pid=None)
            info = control.lstat()
            if not stat.S_ISSOCK(info.st_mode):
                raise EngineError("OWNERSHIP_MISMATCH", "Control endpoint is not an owned socket")
            handle.socket_identity = (info.st_dev, info.st_ino)
            return await self._probe_locked(server_id, handle)
        except ProxyError as exc:
            await self._release(server_id, generation)
            return await self._state(server_id, "PORT_CONFLICT" if exc.code == "PORT_CONFLICT" else "FAILED", exc.code,
                                     process_alive=False, ssh_connected=False, pid=None)
        except asyncio.CancelledError:
            handle = self._runs.get(server_id)
            if handle:
                if handle.signature is None:
                    handle.signature = await self._signature(handle.process)
                await self._dispose(handle)
            await self._release(server_id, generation)
            raise
        except Exception as exc:
            handle = self._runs.get(server_id)
            if handle:
                await self._dispose(handle)
            await self._release(server_id, generation)
            if isinstance(exc, EngineError):
                if exc.code == "PORT_CONFLICT":
                    return await self._state(server_id, "PORT_CONFLICT", exc.code, process_alive=False, ssh_connected=False)
                if exc.code != "STORAGE_UNAVAILABLE":
                    await self._state(server_id, "FAILED", exc.code, process_alive=False, ssh_connected=False)
                raise
            await self._state(server_id, "FAILED", "SSH_START_FAILED", process_alive=False, ssh_connected=False)
            raise EngineError("SSH_START_FAILED", "Unable to start the managed SSH process", status_code=503) from exc

    async def stop(self, server_id: str) -> dict[str, Any]:
        async with self._lock(server_id):
            self._server(server_id)
            self._persist_desired(server_id, "STOPPED")
            self._cancel_monitor(server_id)
            return await self._stop_locked(server_id, "USER_STOPPED")

    async def _stop_locked(self, server_id: str, reason: str) -> dict[str, Any]:
        self._generation[server_id] = self._generation.get(server_id, 0) + 1
        handle = self._runs.get(server_id)
        if handle:
            await self._dispose(handle)
        await self.proxy.release(server_id)
        return await self._state(server_id, "STOPPED", reason, process_alive=False, ssh_connected=False,
                                 pid=None, run_id=None, remote_listener="UNKNOWN", http_status=None,
                                 proxy_health="UNKNOWN", http_transport_ok=False, http_connect_status=None,
                                 ssh_latency_ms=None, total_ms=None, tls_completed_ms=None,
                                 tls_handshake_ms=None, stale=False, generation=self._generation[server_id])

    async def restart(self, server_id: str) -> dict[str, Any]:
        async with self._lock(server_id):
            self._server(server_id)
            self._persist_desired(server_id, "RUNNING")
            self._cancel_monitor(server_id)
            await self._stop_locked(server_id, "RESTARTING")
            result = await self._start_locked(server_id)
            self._ensure_monitor(server_id)
            return result

    async def set_mode(self, server_id: str, mode: str, proxy_port: int | None = None,
                       expected_revision: int | None = None) -> dict[str, Any]:
        if mode not in MODES:
            raise EngineError("INVALID_MODE", "Unsupported proxy mode", status_code=422)
        async with self._lock(server_id):
            server = self._server(server_id)
            if expected_revision is not None and server["revision"] != expected_revision:
                raise EngineError("REVISION_CONFLICT", "Server changed; reload before changing mode")
            new_port = self._port(proxy_port, minimum=1024) if proxy_port is not None else (7890 if mode == "CLASH_HTTP" else 18988)
            if mode == "MAC_DIRECT" and new_port in self.proxy.PROTECTED_PORTS:
                raise EngineError("PROTECTED_PORT", "Managed tinyproxy cannot bind a production port")
            if mode == "CLASH_HTTP" and not self.proxy.port_open(new_port):
                raise EngineError("DEPENDENCY_UNAVAILABLE", "External HTTP proxy is not listening", status_code=503)
            was_running = server.get("desired_state") == "RUNNING"
            # Commit the requested configuration before resource changes; a
            # failed database write leaves the existing process untouched.
            try:
                self.repo.update_server(server_id, {"mode": mode, "proxy_port": new_port,
                                                    "desired_state": "STOPPED" if mode == "DISABLED" else server["desired_state"]},
                                        expected_revision=server["revision"])
            except Exception as exc:
                raise EngineError("STORAGE_UNAVAILABLE", "Mode change was not saved", status_code=503) from exc
            self._desired[server_id] = "STOPPED" if mode == "DISABLED" else server["desired_state"]
            self._cancel_monitor(server_id)
            await self._stop_locked(server_id, "MODE_CHANGE")
            if mode == "DISABLED" or not was_running:
                return self.snapshot(server_id)
            result = await self._start_locked(server_id)
            if result["state"] != "HEALTHY":
                failed_mode = mode
                await self._stop_locked(server_id, "MODE_ROLLBACK")
                self.repo.update_server(server_id, {"mode": server["mode"], "proxy_port": server["proxy_port"]})
                result = await self._start_locked(server_id)
                result = await self._state(server_id, result["state"], "MODE_CHANGE_ROLLED_BACK", rollback_success=result["state"] == "HEALTHY", failed_mode=failed_mode)
            self._ensure_monitor(server_id)
            return result

    async def probe(self, server_id: str) -> dict[str, Any]:
        async with self._lock(server_id):
            self._server(server_id)
            handle = self._runs.get(server_id)
            if not handle:
                return self.snapshot(server_id)
            return await self._probe_locked(server_id, handle)

    async def test_connection(self, server_id: str, kind: str = "proxy") -> dict[str, Any]:
        """Explicit wizard test of a saved STOPPED profile, always cleaning its child."""
        async with self._lock(server_id):
            server = self._server(server_id)
            if server.get("desired_state") != "STOPPED" or self._runs.get(server_id):
                raise EngineError("ACTIVE_RESOURCE", "Stop the profile before running an isolated connection test")
            if server["remote_proxy_port"] in {17890, 17891}:
                raise EngineError("PROTECTED_PRODUCTION_PORT", "Testing an existing production port is not authorized")
            if server.get("mode") == "DISABLED":
                raise EngineError("DISABLED_MODE", "Select a proxy exit before testing")
            # _start_locked does not persist RUNNING and no monitor is installed.
            # The lock prevents a concurrent normal start from escaping cleanup.
            self._desired[server_id] = "STOPPED"
            result: dict[str, Any] | None = None
            try:
                evidence = await self._start_locked(server_id)
                connection_ok = bool(evidence.get("process_alive") and evidence.get("ssh_connected"))
                proxy_ok = bool(evidence.get("state") == "HEALTHY" and not evidence.get("stale"))
                result = {"server_id": server_id, "kind": kind, "passed": connection_ok if kind == "connection" else proxy_ok,
                        "connection_ok": connection_ok, "proxy_ok": proxy_ok,
                          "runtime": evidence, "observed_at": _now(), "stopped_after_test": False}
            finally:
                await self._stop_locked(server_id, "TEST_FINISHED")
            result["stopped_after_test"] = True
            result["final_runtime"] = self.snapshot(server_id)
            return result

    async def diagnostic_probe(self, server_id: str, target_url: str) -> dict[str, Any]:
        """Probe an approved URL using the existing owned ControlMaster only."""
        async with self._lock(server_id):
            server = self._server(server_id)
            handle = self._runs.get(server_id)
            if not handle or handle.process.returncode is not None:
                raise EngineError("CONNECTION_REQUIRED", "Enable this managed channel before running diagnostics")
            async with self._probe_capacity():
                connected = await self._control_check(handle)
                ssh_started = time.monotonic()
                listener = await self._remote_listener(handle, self._port(server["remote_proxy_port"], minimum=1024)) if connected else "UNKNOWN"
                ssh_latency_ms = (time.monotonic() - ssh_started) * 1000 if connected else None
                started = time.monotonic()
                probe = await self._e2e_probe(handle, dict(server, health_url=target_url)) if listener == "LISTENING" else HealthProbe.unavailable("PROBE_UNAVAILABLE")
                elapsed = (time.monotonic() - started) * 1000
            return {"server_id": server_id, "target_url": target_url, "observed_at": _now(),
                    "ownership": "MANAGED", "mode": server["mode"], "local_proxy_port": server["proxy_port"],
                    "remote_proxy_port": server["remote_proxy_port"], "ssh_connected": connected,
                    "ssh_latency_ms": ssh_latency_ms,
                    "remote_listener": listener, "http_reachable": probe.transport_ok,
                    "request_elapsed_ms": elapsed, **probe.as_dict(),
                    "llm_completion_verified": False,
                    "disclaimer": "HTTP 可达仅证明本次代理链路请求完成，不代表模型生成或鉴权成功。"}

    async def codex_credential_check(self, server_id: str, source: str, consent: bool) -> dict[str, Any]:
        """Read key status remotely through the current owned channel only."""
        if source != SOURCE:
            raise EngineError("INVALID_CREDENTIAL_SOURCE", "Select the remote Codex auth.json source", status_code=422)
        if consent is not True:
            raise EngineError("CONSENT_REQUIRED", "Confirm the remote credential readability check first", status_code=403)
        async with self._lock(server_id):
            self._server(server_id)
            handle = self._runs.get(server_id)
            connected = False
            check = CodexCredentialCheck.unavailable("CONNECTION_REQUIRED")
            if handle and handle.process.returncode is None:
                generation = handle.generation
                async with self._probe_capacity():
                    # Capacity can wait. Recheck authority after waiting and
                    # before the remote read, then reject stale completions.
                    if self._generation.get(server_id) != generation:
                        check = CodexCredentialCheck.unavailable("CONNECTION_CHANGED")
                    else:
                        await self._assert_owned(handle)
                        connected = await self._control_check(handle)
                        if connected:
                            await self._assert_owned(handle)
                            try:
                                rc, output, _ = await self._execute(
                                    self._probe_argv(handle) + [build_remote_codex_command()], 8)
                                check = CodexCredentialCheck.from_remote(output, rc)
                            except OSError:
                                check = CodexCredentialCheck.unavailable("REMOTE_CHECK_FAILED")
                            if (self._runs.get(server_id) is not handle
                                    or self._generation.get(server_id) != generation
                                    or handle.process.returncode is not None):
                                connected = False
                                check = CodexCredentialCheck.unavailable("CONNECTION_CHANGED")
                            else:
                                await self._assert_owned(handle)
            return {"server_id": server_id, "ownership": "MANAGED", "ssh_connected": connected,
                    "observed_at": _now(), **check.as_dict()}

    async def codex_model_preview(self, server_id: str, source: str) -> dict[str, Any]:
        """Read only selected remote config metadata; do not read credentials."""
        return await self._codex_model_check(server_id, source)

    async def codex_model_test(self, server_id: str, source: str, consent: bool, base_url: str,
                               model: str, wire_api: str, expected_revision: int) -> dict[str, Any]:
        """Run exactly one explicitly authorized generation request remotely."""
        if consent is not True:
            raise EngineError("CONSENT_REQUIRED", "Confirm the model request and its recipient first", status_code=403)
        return await self._codex_model_check(server_id, source, (base_url, model, wire_api, expected_revision))

    async def _codex_model_check(self, server_id: str, source: str,
                                 invocation: tuple[str, str, str, int] | None = None) -> dict[str, Any]:
        if source != SOURCE:
            raise EngineError("INVALID_CREDENTIAL_SOURCE", "Select remote Codex auth.json", status_code=422)
        async with self._lock(server_id):
            server = self._server(server_id)
            result_type = ModelTestResult if invocation is not None else ModelPreview
            result = result_type.unavailable("CONNECTION_REQUIRED")
            handle = self._runs.get(server_id)
            connected = False
            command = build_remote_model_preview_command()
            if invocation is not None:
                base_url, model, wire_api, revision = invocation
                if type(revision) is not int or revision != server["revision"]:
                    raise EngineError("REVISION_CONFLICT", "Server configuration changed; review it again")
                # Validate even direct engine calls before authority or reads.
                try:
                    command = build_remote_model_test_command(base_url, model, wire_api,
                                                              self._port(server["remote_proxy_port"], minimum=1024))
                except ValueError:
                    raise EngineError("INVALID_MODEL_TEST", "Review the model request parameters", status_code=422) from None
                last = self._model_test_started.get(server_id)
                if last is not None and time.monotonic() - last < 30:
                    raise EngineError("MODEL_TEST_COOLDOWN", "Wait 30 seconds between model tests", status_code=429)
            if handle and handle.process.returncode is None:
                generation = handle.generation
                async with self._probe_capacity():
                    if (self._runs.get(server_id) is not handle or self._generation.get(server_id) != generation
                            or handle.process.returncode is not None):
                        result = result_type.unavailable("CONNECTION_CHANGED")
                    else:
                        if invocation is not None and self._server(server_id)["revision"] != invocation[3]:
                            raise EngineError("REVISION_CONFLICT", "Server configuration changed; review it again")
                        await self._assert_owned(handle)
                        connected = await self._control_check(handle)
                        if connected:
                            await self._assert_owned(handle)
                            if invocation is not None and self._server(server_id)["revision"] != invocation[3]:
                                raise EngineError("REVISION_CONFLICT", "Server configuration changed; review it again")
                            if invocation is not None:
                                self._model_test_started[server_id] = time.monotonic()
                            try:
                                rc, output, _ = await self._execute(self._probe_argv(handle) + [command],
                                                                   25 if invocation is not None else 8)
                                result = result_type.from_remote(output, rc)
                            except OSError:
                                result = result_type.unavailable("REMOTE_CHECK_FAILED")
                            if (self._runs.get(server_id) is not handle or self._generation.get(server_id) != generation
                                    or handle.process.returncode is not None
                                    or self._server(server_id)["revision"] != server["revision"]):
                                connected = False
                                result = result_type.unavailable("CONNECTION_CHANGED")
                            else:
                                await self._assert_owned(handle)
            envelope = {"server_id": server_id, "ownership": "MANAGED", "ssh_connected": connected,
                        "observed_at": _now(), **result.as_dict()}
            if invocation is None:
                envelope["profile_revision"] = server["revision"]
            return envelope

    async def _probe_locked(self, server_id: str, handle: RunHandle) -> dict[str, Any]:
        generation = handle.generation
        async with self._probe_capacity():
            server = self._server(server_id)
            alive = handle.process.returncode is None
            connected = alive and await self._control_check(handle)
            ssh_started = time.monotonic()
            listener = await self._remote_listener(handle, self._port(server["remote_proxy_port"], minimum=1024)) if connected else "UNKNOWN"
            ssh_latency_ms = (time.monotonic() - ssh_started) * 1000 if connected else None
            probe = await self._e2e_probe(handle, server) if connected and listener == "LISTENING" else HealthProbe.unavailable("PROBE_UNAVAILABLE")
            alive = handle.process.returncode is None
            connected = connected and alive
        if self._runs.get(server_id) is not handle or self._generation.get(server_id) != generation:
            return self.snapshot(server_id)
        healthy = alive and connected and listener == "LISTENING" and probe.transport_ok and probe.http_status in server["expected_status"]
        current = self.snapshot(server_id)
        failures = 0 if healthy else int(current.get("consecutive_failures", 0)) + 1
        if healthy:
            state, reason = "HEALTHY", None
        elif not alive:
            state, reason = "DEGRADED", self._classify(" ".join(handle.stderr))
        else:
            state, reason = "DEGRADED", "HTTP_STATUS_UNEXPECTED" if probe.transport_ok else probe.error_code
        result = await self._state(server_id, state, reason, process_alive=alive, ssh_connected=connected,
                                   remote_listener=listener, proxy_health="HEALTHY" if healthy else "UNHEALTHY",
                                   http_transport_ok=probe.transport_ok,
                                   http_status=probe.http_status, total_ms=probe.total_ms, tls_completed_ms=probe.tls_completed_ms,
                                   tls_handshake_ms=probe.tls_handshake_ms, ssh_latency_ms=ssh_latency_ms, consecutive_failures=failures,
                                   http_connect_status=probe.http_connect_status,
                                   pid=handle.process.pid if alive else None, run_id=handle.run_id, generation=generation,
                                   monitoring_capability="FULL" if probe.capable else "PARTIAL", stale=False,
                                   failure_threshold_reached=failures >= int(self._settings().get("failure_threshold", 3)),
                                   last_success_at=_now() if healthy else current.get("last_success_at"),
                                   evidence=[{"kind": "process", "observed": alive}, {"kind": "ssh_control", "observed": connected},
                                             {"kind": "remote_listener", "observed": listener}, {"kind": "e2e_http", **probe.as_dict()}])
        self.repo.add_sample(server_id, {**result, "error_code": reason})
        await self._emit({"type": "server.metric", "server_id": server_id, "payload": result})
        return result

    @contextlib.asynccontextmanager
    async def _probe_capacity(self):
        async with self._probe_condition:
            while self._active_probes >= int(self._settings().get("max_concurrent_probes", 4)):
                await self._probe_condition.wait()
            self._active_probes += 1
        try:
            yield
        finally:
            async with self._probe_condition:
                self._active_probes -= 1
                self._probe_condition.notify_all()

    def _ensure_monitor(self, server_id: str) -> None:
        if not self._closed and self._desired.get(server_id) == "RUNNING" and server_id not in self._monitors:
            self._monitors[server_id] = asyncio.create_task(self._monitor(server_id), name=f"tunnel-{server_id}")

    def _cancel_monitor(self, server_id: str) -> None:
        task = self._monitors.pop(server_id, None)
        if task and task is not asyncio.current_task():
            task.cancel()

    async def _monitor(self, server_id: str) -> None:
        attempts = 0
        healthy_since = None
        try:
            while not self._closed and self._desired.get(server_id) == "RUNNING":
                async with self._lock(server_id):
                    server = self._server(server_id)
                    current = self.snapshot(server_id)
                    if current["state"] in {"AUTH_REQUIRED", "PORT_CONFLICT"}:
                        return
                    handle = self._runs.get(server_id)
                    needs_restart = not handle or handle.process.returncode is not None
                    if handle and not needs_restart:
                        current = await self._probe_locked(server_id, handle)
                        needs_restart = not current["ssh_connected"]
                    if needs_restart:
                        if not server.get("auto_reconnect"):
                            await self._state(server_id, "FAILED", "AUTO_RECONNECT_DISABLED", ssh_connected=False)
                            return
                        if attempts >= int(self._settings().get("retry_max_attempts", 10)):
                            await self._state(server_id, "FAILED", "RETRY_BUDGET_EXHAUSTED", ssh_connected=False)
                            return
                        await self._state(server_id, "RECONNECTING", "SSH_DISCONNECTED", ssh_connected=False,
                                          reconnect_count=int(current.get("reconnect_count", 0)) + 1)
                    elif current["state"] == "HEALTHY":
                        if healthy_since is None:
                            healthy_since = time.monotonic()
                        elif time.monotonic() - healthy_since >= 60:
                            attempts = 0
                    else:
                        healthy_since = None
                settings = self._settings()
                if needs_restart:
                    healthy_since = None
                    delay = min(float(settings.get("retry_base_s", 5)) * (2 ** attempts), float(settings.get("retry_max_s", 300)))
                    attempts += 1
                    await asyncio.sleep(delay * random.uniform(0.8, 1.2))
                    async with self._lock(server_id):
                        if self._desired.get(server_id) != "RUNNING" or self._closed:
                            return
                        handle = self._runs.get(server_id)
                        if handle:
                            await self._dispose(handle)
                        await self._start_locked(server_id)
                else:
                    await asyncio.sleep(float(settings.get("health_interval_s", 15)) * random.uniform(0.8, 1.2))
        except asyncio.CancelledError:
            pass
        except Exception as exc:  # noqa: BLE001 - supervision must publish persistence and dependency faults.
            with contextlib.suppress(Exception):
                await self._state(server_id, "FAILED", getattr(exc, "code", "MONITOR_FAILED"), stale=True)
        finally:
            if self._monitors.get(server_id) is asyncio.current_task():
                self._monitors.pop(server_id, None)

    async def restore(self, recover: bool = False) -> list[dict[str, Any]]:
        results = []
        for server in self.repo.list_servers():
            enabled = server.get("restore_on_login") or (recover and server.get("auto_reconnect"))
            if server.get("management") == "MANAGED" and enabled and server.get("desired_state") == "RUNNING":
                result = await self.start(server["id"])
                # A supervisor restart can race the old SSH master while its
                # remote reverse-forward is being torn down. Retry only this
                # app-owned recovery path; never kill or adopt the competing
                # listener. Persistent conflicts remain PORT_CONFLICT.
                if recover and result.get("state") == "PORT_CONFLICT":
                    for delay in (1.0, 2.0, 4.0):
                        await asyncio.sleep(delay)
                        async with self._lock(server["id"]):
                            current = self.repo.get_server(server["id"])
                            if self._closed or not current or current.get("desired_state") != "RUNNING":
                                result = self.snapshot(server["id"])
                                break
                            self._cancel_monitor(server["id"])
                            result = await self._start_locked(server["id"])
                            self._ensure_monitor(server["id"])
                        if result.get("state") != "PORT_CONFLICT":
                            break
                results.append(result)
        return results

    async def close(self) -> None:
        self._closed = True
        tasks = list(self._monitors.values())
        for server_id in list(self._monitors):
            self._cancel_monitor(server_id)
        await asyncio.gather(*tasks, return_exceptions=True)
        for server_id in list(self._runs):
            async with self._lock(server_id):
                await self._dispose(self._runs[server_id])
        await self.proxy.close()

    async def _signature(self, process: asyncio.subprocess.Process) -> str | None:
        if process.returncode is not None:
            return None
        rc, out, _ = await self._execute(["/bin/ps", "-p", str(process.pid), "-o", "lstart="], 2)
        return _digest(out.strip()) if rc == 0 and out.strip() else None

    async def _assert_owned(self, handle: RunHandle) -> None:
        identity = (handle.process, handle.process.pid, handle.nonce, handle.argv, handle.config_path, handle.control_socket)
        if self._runs.get(handle.server_id) is not handle or self._owned.get(handle.run_id) != identity:
            raise EngineError("OWNERSHIP_MISMATCH", "Process ownership no longer matches; refusing to signal")
        if handle.process.returncode is not None:
            return
        if not handle.signature or await self._signature(handle.process) != handle.signature:
            # ps can observe an exiting child before asyncio receives SIGCHLD.
            # Confirm exit without signalling; a still-running mismatch fails
            # closed and is never used as authority to terminate a PID.
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(handle.process.wait(), timeout=0.1)
            if handle.process.returncode is not None:
                return
            raise EngineError("OWNERSHIP_MISMATCH", "Process identity changed; refusing to signal")
        if handle.config_path.is_symlink() or _digest(handle.config_path.read_bytes()) != handle.config_digest:
            raise EngineError("OWNERSHIP_MISMATCH", "Generated SSH configuration changed; refusing control")
        if handle.socket_identity and handle.control_socket.exists():
            info = handle.control_socket.lstat()
            if (info.st_dev, info.st_ino) != handle.socket_identity or not stat.S_ISSOCK(info.st_mode):
                raise EngineError("OWNERSHIP_MISMATCH", "Control socket identity changed; refusing control")

    async def _dispose(self, handle: RunHandle) -> None:
        await self._assert_owned(handle)
        if handle.process.returncode is None:
            if handle.socket_identity and handle.control_socket.exists():
                await self._execute([self.ssh_executable, "-F", str(handle.config_path), "-S", str(handle.control_socket),
                                     "-O", "exit", handle.alias], 3)
            if handle.process.returncode is None:
                await self._assert_owned(handle)
                with contextlib.suppress(ProcessLookupError):
                    handle.process.terminate()
                try:
                    await asyncio.wait_for(handle.process.wait(), 3)
                except TimeoutError:
                    await self._assert_owned(handle)
                    with contextlib.suppress(ProcessLookupError):
                        handle.process.kill()
                    await handle.process.wait()
        await asyncio.gather(*handle.drains, return_exceptions=True)
        self._runs.pop(handle.server_id, None)
        self._owned.pop(handle.run_id, None)
        await self._release(handle.server_id, handle.generation)
        for path in (handle.config_path, handle.control_socket):
            if not path.is_symlink():
                with contextlib.suppress(FileNotFoundError):
                    path.unlink()

    async def _release(self, server_id: str, generation: int) -> None:
        for key, value in list(self._reservations.items()):
            if value == (server_id, generation):
                del self._reservations[key]
        await self.proxy.release(server_id)

    async def _control_check(self, handle: RunHandle) -> bool:
        if handle.process.returncode is not None:
            return False
        await self._assert_owned(handle)
        if handle.control_socket.exists() and handle.socket_identity is None:
            info = handle.control_socket.lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
                raise EngineError("OWNERSHIP_MISMATCH", "Control socket is not a private owned socket")
            handle.socket_identity = (info.st_dev, info.st_ino)
        rc, _, _ = await self._execute([self.ssh_executable, "-F", str(handle.config_path), "-S", str(handle.control_socket),
                                       "-O", "check", handle.alias], 2)
        return rc == 0 and handle.process.returncode is None

    def _probe_argv(self, handle: RunHandle) -> list[str]:
        # If multiplexing fails, /usr/bin/false prevents a fresh independent
        # login from producing false evidence for this managed connection.
        return [self.ssh_executable, "-F", str(handle.config_path), "-S", str(handle.control_socket), "-T", "-n",
                "-o", "ControlMaster=no", "-o", "ClearAllForwardings=yes", "-o", "ProxyCommand=/usr/bin/false", handle.alias]

    async def _remote_listener(self, handle: RunHandle, remote_port: int) -> str:
        # Fixed Linux tools only.  Missing ss is a capability failure, never
        # evidence that a listener is absent.
        command = f"if command -v ss >/dev/null 2>&1; then ss -ltnH 'sport = :{remote_port}' | grep -Eq '(^|[[:space:]])127\\.0\\.0\\.1:{remote_port}([[:space:]]|$)'; else exit 69; fi"
        await self._assert_owned(handle)
        rc, _, _ = await self._execute(self._probe_argv(handle) + [command], 5)
        return "LISTENING" if rc == 0 else "NOT_LISTENING" if rc == 1 else "UNAVAILABLE"

    async def _e2e_probe(self, handle: RunHandle, server: dict[str, Any]) -> HealthProbe:
        try:
            url = str(server["health_url"])
            validate_health_url(url)
            timeout = min(float(self._settings().get("probe_timeout_s", 15)), 120)
            command = build_remote_curl_command(url, self._port(server["remote_proxy_port"], minimum=1024), timeout)
            await self._assert_owned(handle)
            rc, out, _ = await self._execute(self._probe_argv(handle) + [command], timeout + 3)
            return HealthProbe.from_curl(out.decode("ascii", "replace"), transport_exit=rc)
        except ValueError:
            return HealthProbe.unavailable("INVALID_HEALTH_URL")

    async def _drain(self, handle: RunHandle, stream: asyncio.StreamReader) -> None:
        import codecs

        from app.db.repository import redact_text

        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        buffer = ""
        private_material = False
        dropping = False

        async def emit_line(raw: str) -> None:
            nonlocal private_material
            if "BEGIN" in raw and "PRIVATE KEY" in raw:
                private_material = True
            if private_material:
                text = "[redacted private key material]"
                if "END" in raw and "PRIVATE KEY" in raw:
                    private_material = False
            else:
                text = raw
            server = self.repo.get_server(handle.server_id) or {}
            sensitive = [str(value) for value in (server.get("host"), server.get("user"),
                         server.get("identity_file_ref"), str(self.data_dir)) if value]
            text = redact_text(text, sensitive)
            handle.stderr.append(text[:1024])
            with contextlib.suppress(Exception):
                self.repo.append_log(handle.server_id, "INFO", text[:1024])
            await self._emit({"type": "server.log", "server_id": handle.server_id, "payload": {"level": "INFO", "message": text[:1024]}})

        while chunk := await stream.read(1024):
            buffer += decoder.decode(chunk)
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                if dropping:
                    await emit_line("[oversized log line suppressed]")
                    dropping = False
                else:
                    await emit_line(line)
            if len(buffer) > 8192:
                buffer = ""
                dropping = True
        buffer += decoder.decode(b"", final=True)
        if buffer or dropping:
            await emit_line("[oversized log line suppressed]" if dropping else buffer)

    async def _execute(self, argv: list[str], timeout: float) -> tuple[int, bytes, bytes]:
        process = await asyncio.create_subprocess_exec(*argv, stdin=asyncio.subprocess.DEVNULL,
                                                      stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        async def limited(stream: asyncio.StreamReader) -> bytes:
            data = bytearray()
            while chunk := await stream.read(4096):
                data.extend(chunk)
                if len(data) > 65536:
                    raise ValueError("command output exceeds limit")
            return bytes(data)
        readers = [asyncio.create_task(limited(process.stdout)), asyncio.create_task(limited(process.stderr))]
        async def cleanup():
            for reader in readers:
                reader.cancel()
            await asyncio.gather(*readers, return_exceptions=True)
            if process.returncode is None:
                process.kill()
            # Drain the exact query child's pipes after cancelling bounded
            # readers. An unread paused pipe must not hold the lifecycle lock.
            await process.communicate()
        try:
            out, err, _ = await asyncio.wait_for(asyncio.gather(*readers, process.wait()), timeout)
            return int(process.returncode or 0), out, err
        except (TimeoutError, ValueError):
            await cleanup()
            return 124, b"", b""
        except asyncio.CancelledError:
            await cleanup()
            raise

    def _profile(self, server: dict[str, Any], alias: str, run_id: str, local_port: int) -> tuple[Path, Path]:
        config = self.run_dir / f"{run_id}.conf"
        control = self.socket_dir / run_id[:10]
        if len(os.fsencode(control)) > 100:
            raise EngineError("SOCKET_PATH_TOO_LONG", "Project path is too long for a private SSH control socket")
        def quote(value: str) -> str:
            if any(ord(ch) < 32 for ch in value) or '"' in value or "\\" in value or "%" in value:
                raise EngineError("INVALID_PATH_REF", "Path reference contains unsupported characters", status_code=422)
            return '"' + value + '"'
        known_hosts = self.data_dir / "known_hosts"
        if known_hosts.is_symlink():
            raise EngineError("UNSAFE_STORAGE", "Project known_hosts must not be a symlink")
        lines = [f"Host {alias}", f"    HostName {self._validate_host(server['host'])}",
                 f"    User {self._validate_user(server['user'])}", f"    Port {self._port(server['ssh_port'])}",
                 "    BatchMode yes", "    ExitOnForwardFailure yes", "    ConnectTimeout 15",
                 "    ServerAliveInterval 30", "    ServerAliveCountMax 3", "    ControlPersist no",
                 "    StrictHostKeyChecking yes", "    ForwardAgent no", "    ForwardX11 no", "    PermitLocalCommand no",
                 "    RequestTTY no", "    LogLevel ERROR", "    PasswordAuthentication no", "    KbdInteractiveAuthentication no",
                 f"    UserKnownHostsFile {quote(str(known_hosts))} {quote(str(Path.home() / '.ssh' / 'known_hosts'))}",
                 "    GlobalKnownHostsFile /etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2",
                 f"    RemoteForward 127.0.0.1:{self._port(server['remote_proxy_port'], minimum=1024)} 127.0.0.1:{local_port}"]
        identity = server.get("identity_file_ref")
        if identity:
            if not Path(identity).is_absolute():
                raise EngineError("INVALID_PATH_REF", "Identity file must be an absolute reference", status_code=422)
            lines.extend([f"    IdentityFile {quote(str(identity))}", "    IdentitiesOnly yes"])
        private_write(config, "\n".join(lines) + "\n")
        return config, control

    @staticmethod
    def _classify(error: str) -> str:
        error = error.lower()
        if any(x in error for x in ("host key", "permission denied", "authentication failed", "sign_and_send_pubkey")):
            return "AUTH_REQUIRED"
        if "remote port forwarding failed" in error or "address already in use" in error:
            return "PORT_CONFLICT"
        return "SSH_DISCONNECTED"

    @staticmethod
    def _port(value: Any, minimum: int = 1) -> int:
        if isinstance(value, bool):
            raise EngineError("INVALID_PORT", "Invalid port", status_code=422)
        try:
            port = int(value)
        except (ValueError, TypeError) as exc:
            raise EngineError("INVALID_PORT", "Invalid port", status_code=422) from exc
        if not minimum <= port <= 65535:
            raise EngineError("INVALID_PORT", f"Port must be in {minimum}..65535", status_code=422)
        return port

    @staticmethod
    def _validate_host(host: str) -> str:
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", host):
                raise EngineError("INVALID_HOST", "Invalid SSH host", status_code=422)
            return host

    @staticmethod
    def _validate_user(user: str) -> str:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", user):
            raise EngineError("INVALID_USER", "Invalid SSH user", status_code=422)
        return user
