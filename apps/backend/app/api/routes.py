from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shlex
import shutil
from pathlib import Path
from uuid import UUID, uuid4

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response, WebSocket
from fastapi.responses import FileResponse
from pydantic import ValidationError

from app.api.discovery import collect_discovery
from app.api.security import SecurityManager, Session, session_digest
from app.db.repository import Repository, RepositoryError, redact_details, redact_text, utc_now
from app.monitoring.codex_credentials import safe_api_result
from app.monitoring.codex_model_test import safe_model_api_result, safe_model_preview_result
from app.schemas.inputs import (
    CodexCredentialCheckInput,
    CodexModelPreviewInput,
    CodexModelTestInput,
    ConfigurationInput,
    ConnectionTestInput,
    DiagnosticsInput,
    DiscoveryImportInput,
    ExportInput,
    GroupInput,
    ImportCommitInput,
    MigrationInput,
    ModeInput,
    ProxyEndpointInput,
    ServerInput,
    ServerPatch,
    SettingsInput,
    SSHPreviewInput,
    TicketInput,
)


def _error(error: Exception) -> HTTPException:
    if isinstance(error, ValidationError):
        fields = [{"field": ".".join(str(part) for part in item["loc"]), "message": item["msg"]}
                  for item in error.errors(include_input=False, include_context=False, include_url=False)]
        return HTTPException(422, {"code": "VALIDATION_ERROR", "message": "配置字段无效，请检查输入", "details": {"fields": fields}})
    if isinstance(error, RepositoryError):
        return HTTPException(error.status_code, {"code": error.code, "message": error.message, "details": error.details})
    code = getattr(error, "code", "ENGINE_ERROR")
    message = getattr(error, "message", str(error))
    status = int(getattr(error, "status_code", 409))
    return HTTPException(status, {"code": code, "message": message, "details": redact_details(getattr(error, "details", {}))})


def create_router(repo: Repository, engine=None, events=None) -> APIRouter:
    router = APIRouter(prefix="/api/v1")
    router.control_tasks: set[asyncio.Task] = set()
    previews: dict[str, dict] = {}
    discovery_snapshots: dict[str, dict] = {}

    def add_preview(value: dict) -> str:
        now = asyncio.get_running_loop().time()
        for key, item in list(previews.items()):
            if item["expires"] < now:
                previews.pop(key)
        if len(previews) >= 64:
            raise HTTPException(429, {"code": "PREVIEW_LIMIT", "message": "Too many pending import previews"})
        preview_id = str(uuid4())
        previews[preview_id] = value | {"expires": now + 600}
        return preview_id

    async def dependencies() -> dict:
        ssh_path = Path(getattr(engine, "ssh_executable", "/usr/bin/ssh"))
        proxy_path = getattr(getattr(engine, "proxy", None), "tinyproxy_executable", None)
        available_space = shutil.disk_usage(repo.data_dir).free
        clash_state = "NOT_LISTENING"
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", 7890), timeout=0.5)
            writer.close()
            await writer.wait_closed()
            clash_state = "TCP_REACHABLE"
        except (OSError, TimeoutError):
            pass
        return {"ssh": {"state": "AVAILABLE" if ssh_path.is_file() and os.access(ssh_path, os.X_OK) else "UNAVAILABLE"},
                "storage": {"state": "AVAILABLE", "free_bytes": available_space},
                "tinyproxy": {"state": "AVAILABLE" if proxy_path and Path(proxy_path).is_file() else "UNAVAILABLE"},
                "clash": {"state": clash_state, "ownership": "OBSERVED_EXTERNAL", "end_to_end_health": "UNKNOWN"},
                "direct_path": {"state": "UNVERIFIED", "reason": "System TUN and transparent proxy are not controlled"},
                "observed_at": utc_now()}

    def security_for(request: Request) -> SecurityManager:
        security = getattr(request.app.state, "security", None)
        if security is None:
            raise HTTPException(503, {"code": "DEPENDENCY_UNAVAILABLE", "message": "Session authority is unavailable"})
        return security

    def session_for(request: Request) -> Session:
        session = getattr(request.state, "session", None)
        if session is None:
            raise HTTPException(401, {"code": "SESSION_REQUIRED", "message": "Open Tunnel Manager to establish a session"})
        return session

    def server_or_404(server_id: str) -> dict:
        try:
            UUID(server_id)
        except ValueError as error:
            raise HTTPException(422, {"code": "INVALID_ID", "message": "Server id must be a UUID"}) from error
        server = repo.get_server(server_id)
        if server is None:
            raise HTTPException(404, {"code": "NOT_FOUND", "message": "Server does not exist"})
        return server

    def fresh_runtime(server_id: str) -> dict | None:
        return engine.snapshot(server_id) if engine and hasattr(engine, "snapshot") else repo.get_runtime(server_id)

    async def publish(message: dict):
        if events is not None and hasattr(events, "publish"):
            result = events.publish(message)
            if asyncio.iscoroutine(result):
                await result

    async def run_action(operation: dict, server: dict, action: str, mode: str | None = None,
                         proxy_port: int | None = None):
        operation_id = operation["id"]
        try:
            repo.update_operation(operation_id, "RUNNING")
            if action == "mode" and repo.get_server(server["id"])["revision"] != server["revision"]:
                raise RepositoryError("REVISION_CONFLICT", "Server changed before mode operation began")
            if engine is None:
                raise RepositoryError("DEPENDENCY_UNAVAILABLE", "Tunnel engine is unavailable", 503)
            if action == "start":
                repo.update_server(server["id"], {"desired_state": "RUNNING"}, server["revision"])
                result = await engine.start(server["id"])
            elif action == "stop":
                if server["management"] != "MANAGED":
                    raise RepositoryError("EXTERNAL_RESOURCE", "Only app-owned tunnels can be stopped", 403)
                repo.update_server(server["id"], {"desired_state": "STOPPED"}, server["revision"])
                result = await engine.stop(server["id"])
            elif action == "restart":
                if server["management"] != "MANAGED":
                    raise RepositoryError("EXTERNAL_RESOURCE", "Only app-owned tunnels can be restarted", 403)
                result = await engine.restart(server["id"])
            elif action == "probe":
                result = await engine.probe(server["id"])
            elif action == "mode":
                result = await engine.set_mode(server["id"], mode, proxy_port, expected_revision=server["revision"])
            else:
                raise RepositoryError("INVALID_ACTION", "Unsupported action", 422)
            if result and isinstance(result, dict) and result.get("runtime"):
                repo.save_runtime(result["runtime"])
            elif engine and hasattr(engine, "snapshot"):
                snapshot = engine.snapshot(server["id"])
                if snapshot:
                    repo.save_runtime(snapshot)
            if isinstance(result, dict) and result.get("reason_code") == "MODE_CHANGE_ROLLED_BACK":
                final_operation = repo.update_operation(operation_id, "FAILED", error_code="MODE_CHANGE_ROLLED_BACK",
                                                        outcome={"message": "目标出口检查失败，已恢复原出口", "runtime": redact_details(result)})
                repo.audit(action, server["id"], "FAILED", {"operation_id": operation_id, "reason_code": "MODE_CHANGE_ROLLED_BACK"})
                await publish({"type": "operation.updated", "server_id": server["id"], "payload": final_operation})
                return
            if isinstance(result, dict) and result.get("state") in ("FAILED", "AUTH_REQUIRED", "PORT_CONFLICT"):
                raise RepositoryError(result.get("reason_code") or result["state"], "Tunnel action did not reach a usable state")
            result = redact_details(result or {})
            final_operation = repo.update_operation(operation_id, "SUCCEEDED", outcome=result)
            repo.audit(action, server["id"], "SUCCEEDED", {"operation_id": operation_id})
            await publish({"type": "operation.updated", "server_id": server["id"], "payload": final_operation})
        except (RepositoryError, RuntimeError, OSError, ValueError, TimeoutError) as error:
            final_operation = repo.update_operation(operation_id, "FAILED", error_code=getattr(error, "code", "ENGINE_ERROR"),
                                                    outcome={"message": redact_details(str(error))})
            await publish({"type": "operation.updated", "server_id": server["id"], "payload": final_operation})
            repo.audit(action, server["id"], "REJECTED", {"error": getattr(error, "code", "ENGINE_ERROR")})

    @router.get("/sessions/current")
    async def current_session(request: Request):
        session = session_for(request)
        return {"csrf": session.csrf, "expires_at": session.expires_at}

    @router.post("/sessions/exchange")
    async def exchange_session(request: Request, response: Response, payload: TicketInput):
        security = security_for(request)
        session = security.exchange(payload.ticket)
        if session is None:
            raise HTTPException(401, {"code": "INVALID_BOOTSTRAP_TICKET", "message": "Ticket is expired or already used"})
        security.set_session_cookie(response, session)
        return {"csrf": session.csrf, "expires_at": session.expires_at}

    @router.delete("/sessions/current")
    async def delete_session(request: Request, response: Response):
        session = session_for(request)
        security_for(request).revoke(session.token)
        security_for(request).clear_session_cookie(response)
        return {"status": "REVOKED"}

    @router.post("/ws-tickets")
    async def ws_ticket(request: Request):
        session = session_for(request)
        try:
            return {"ticket": security_for(request).issue_ws_ticket(session), "expires_in": 30}
        except RuntimeError as error:
            raise HTTPException(429, {"code": "CAPACITY_LIMIT", "message": "Pending tickets are at capacity; retry later"}) from error

    @router.get("/overview")
    async def overview(request: Request):
        session_for(request)
        servers = repo.list_servers()
        runtimes = {server["id"]: fresh_runtime(server["id"]) for server in servers}
        return {"servers": servers, "runtimes": runtimes, "groups": repo.list_groups(), "dependencies": await dependencies()}

    @router.get("/system/dependencies")
    async def system_dependencies(request: Request):
        session_for(request)
        return await dependencies()

    @router.get("/discovery")
    async def discovery(request: Request):
        session_for(request)
        result = await collect_discovery(repo)
        result["discovery_id"] = str(uuid4())
        now = asyncio.get_running_loop().time()
        for key, snapshot in list(discovery_snapshots.items()):
            if snapshot["expires"] < now:
                discovery_snapshots.pop(key)
        if len(discovery_snapshots) >= 32:
            raise HTTPException(429, {"code": "DISCOVERY_LIMIT", "message": "Too many pending discovery snapshots"})
        discovery_snapshots[result["discovery_id"]] = {"value": result, "expires": asyncio.get_running_loop().time() + 600}
        return result

    @router.post("/discovery/import", status_code=201)
    async def discovery_import(request: Request, payload: DiscoveryImportInput):
        session_for(request)
        snapshot = discovery_snapshots.get(payload.discovery_id or "")
        if not snapshot or snapshot["expires"] < asyncio.get_running_loop().time():
            raise HTTPException(409, {"code": "DISCOVERY_EXPIRED", "message": "Refresh discovery before importing"})
        candidates = snapshot["value"]["ssh_config"]["candidates"]
        if any(index < 0 or index >= len(candidates) for index in payload.indexes):
            raise HTTPException(422, {"code": "INVALID_SELECTION", "message": "Discovery candidate index is invalid"})
        try:
            values = []
            for index in dict.fromkeys(payload.indexes):
                candidate = candidates[index]
                values.append({"name": candidate.get("ssh_alias") or candidate["host"], "host": candidate["host"],
                               "ssh_alias": candidate.get("ssh_alias"), "user": candidate["user"],
                               "ssh_port": candidate["ssh_port"], "identity_file_ref": candidate.get("identity_file_ref"),
                               "remote_proxy_port": candidate.get("remote_proxy_port") or 17892,
                               "proxy_port": candidate.get("proxy_port") or 18988,
                               "mode": "DISABLED", "management": "OBSERVED_EXTERNAL"})
            created = repo.import_servers(values)
            repo.audit("discovery.import", None, "SUCCEEDED", {"count": len(created), "started": False})
            await publish({"type": "servers.changed", "payload": {"count": len(created)}})
            return {"servers": created, "started": False, "ownership": "OBSERVED_EXTERNAL"}
        except Exception as error:
            raise _error(error) from error

    @router.get("/proxy-endpoints")
    async def proxy_endpoints(request: Request):
        session_for(request)
        return repo.list_proxy_endpoints()

    @router.post("/proxy-endpoints", status_code=201)
    async def create_endpoint(request: Request, payload: ProxyEndpointInput):
        session_for(request)
        value = payload.model_dump()
        value["ownership"] = "APP_OWNED" if value["kind"] == "MANAGED_TINYPROXY" else "OBSERVED_EXTERNAL"
        return repo.create_proxy_endpoint(value)

    @router.get("/servers")
    async def list_servers(request: Request, q: str = "", group: str | None = None,
                           state: str | None = None, mode: str | None = None):
        session_for(request)
        values = repo.list_servers()
        if q:
            values = [item for item in values if q.lower() in (item["name"] + item["host"] + item["user"]).lower()]
        if group:
            values = [item for item in values if item["group_id"] == group]
        if mode:
            values = [item for item in values if item["mode"] == mode]
        if state:
            values = [item for item in values if (fresh_runtime(item["id"]) or {}).get("state") == state]
        return values

    @router.post("/servers", status_code=201)
    async def create_server(request: Request, payload: ServerInput):
        session = session_for(request)
        try:
            result = repo.create_server(payload.model_dump())
            repo.audit("server.create", result["id"], "ACCEPTED", {"actor": session_digest(session)})
            await publish({"type": "server.created", "server_id": result["id"], "payload": result})
            return result
        except Exception as error:
            raise _error(error) from error

    @router.get("/servers/{server_id}")
    async def get_server(request: Request, server_id: str):
        session_for(request)
        return server_or_404(server_id)

    @router.patch("/servers/{server_id}")
    async def patch_server(request: Request, server_id: str, payload: ServerPatch,
                           if_match: str | None = Header(default=None)):
        session_for(request)
        server = server_or_404(server_id)
        if not if_match:
            raise HTTPException(428, {"code": "REVISION_REQUIRED", "message": "If-Match revision is required"})
        revision = None
        if if_match:
            try:
                revision = int(if_match.strip('"'))
            except ValueError as error:
                raise HTTPException(422, {"code": "INVALID_REVISION", "message": "If-Match must contain a revision"}) from error
        try:
            changes = payload.model_dump(exclude_unset=True)
            changes = {key: value for key, value in changes.items() if value != server.get(key)}
            if "mode" in changes:
                raise RepositoryError("MODE_ACTION_REQUIRED", "Use the controlled mode change action", 409)
            runtime = repo.get_runtime(server_id) or {}
            lifecycle_fields = {"host", "ssh_port", "user", "identity_file_ref", "remote_proxy_port", "proxy_port", "ssh_alias"}
            if (server["desired_state"] == "RUNNING" or runtime.get("process_alive")) and lifecycle_fields.intersection(changes):
                raise RepositoryError("ACTIVE_RESOURCE", "Stop the managed tunnel before editing its connection settings")
            updated = repo.update_server(server_id, changes, revision)
            repo.audit("server.update", server_id, "SUCCEEDED", {"fields": list(changes)})
            await publish({"type": "server.updated", "server_id": server_id, "payload": updated})
            return updated
        except Exception as error:
            raise _error(error) from error

    @router.delete("/servers/{server_id}")
    async def delete_server(request: Request, server_id: str):
        session_for(request)
        server_or_404(server_id)
        try:
            repo.delete_server(server_id)
            repo.audit("server.delete", server_id, "SUCCEEDED", {})
            await publish({"type": "server.deleted", "server_id": server_id, "payload": {"id": server_id}})
            return {"status": "DELETED"}
        except Exception as error:
            raise _error(error) from error

    @router.get("/groups")
    async def get_groups(request: Request):
        session_for(request)
        return repo.list_groups()

    @router.post("/groups", status_code=201)
    async def create_group(request: Request, payload: GroupInput):
        session_for(request)
        try:
            group = repo.create_group(payload.name)
            repo.audit("group.create", None, "SUCCEEDED", {"group_id": group["id"]})
            await publish({"type": "groups.changed", "payload": {"group_id": group["id"]}})
            return group
        except Exception as error:
            raise _error(error) from error

    @router.delete("/groups/{group_id}")
    async def delete_group(request: Request, group_id: str):
        session_for(request)
        try:
            repo.delete_group(group_id)
            repo.audit("group.delete", None, "SUCCEEDED", {"group_id": group_id})
            await publish({"type": "groups.changed", "payload": {"group_id": group_id}})
            return {"status": "DELETED"}
        except Exception as error:
            raise _error(error) from error

    async def action(request: Request, server_id: str, action_name: str, body: dict | None = None,
                     idempotency_key: str | None = None):
        session = session_for(request)
        server = server_or_404(server_id)
        if server["management"] != "MANAGED":
            raise HTTPException(403, {"code": "EXTERNAL_RESOURCE", "message": "This observed resource is not app-owned"})
        try:
            operation, created = repo.create_operation(server_id, action_name, session_digest(session), idempotency_key, body or {})
            if created:
                task = asyncio.create_task(run_action(operation, server, action_name))
                router.control_tasks.add(task)
                task.add_done_callback(router.control_tasks.discard)
            return {"operation_id": operation["id"], "server_id": server_id, "status": operation["status"],
                    "accepted_at": operation["accepted_at"], "correlation_id": operation["correlation_id"]}
        except Exception as error:
            raise _error(error) from error

    @router.post("/servers/{server_id}/actions/start", status_code=202)
    async def start(request: Request, server_id: str, idempotency_key: str | None = Header(default=None, alias="Idempotency-Key")):
        return await action(request, server_id, "start", {}, idempotency_key)

    @router.post("/servers/{server_id}/actions/stop", status_code=202)
    async def stop(request: Request, server_id: str, idempotency_key: str | None = Header(default=None, alias="Idempotency-Key")):
        return await action(request, server_id, "stop", {}, idempotency_key)

    @router.post("/servers/{server_id}/actions/restart", status_code=202)
    async def restart(request: Request, server_id: str, idempotency_key: str | None = Header(default=None, alias="Idempotency-Key")):
        return await action(request, server_id, "restart", {}, idempotency_key)

    @router.put("/servers/{server_id}/mode", status_code=202)
    async def mode(request: Request, server_id: str, payload: ModeInput,
                   if_match: str | None = Header(default=None)):
        session = session_for(request)
        server = server_or_404(server_id)
        if server["management"] != "MANAGED":
            raise HTTPException(403, {"code": "EXTERNAL_RESOURCE", "message": "Observed resource mode cannot be changed"})
        if not if_match:
            raise HTTPException(428, {"code": "REVISION_REQUIRED", "message": "If-Match revision is required for mode changes"})
        try:
            revision = int(if_match.strip('"'))
            if revision != server["revision"]:
                raise RepositoryError("REVISION_CONFLICT", "Server changed; reload before changing mode")
            operation, created = repo.create_operation(server_id, "mode", session_digest(session), None, payload.model_dump())
            if created:
                task = asyncio.create_task(run_action(operation, server, "mode", payload.mode, payload.proxy_port))
                router.control_tasks.add(task)
                task.add_done_callback(router.control_tasks.discard)
            return {"operation_id": operation["id"], "server_id": server_id, "status": operation["status"]}
        except Exception as error:
            raise _error(error) from error

    @router.get("/servers/{server_id}/runtime")
    async def runtime(request: Request, server_id: str):
        session_for(request)
        server_or_404(server_id)
        return fresh_runtime(server_id)

    @router.post("/servers/{server_id}/probes", status_code=202)
    async def probe(request: Request, server_id: str, idempotency_key: str | None = Header(default=None, alias="Idempotency-Key")):
        return await action(request, server_id, "probe", {}, idempotency_key)

    @router.post("/servers/{server_id}/preflight")
    async def preflight(request: Request, server_id: str, payload: ModeInput | None = None):
        session_for(request)
        server = server_or_404(server_id)
        if payload is not None:
            server = {**server, "mode": payload.mode,
                      "proxy_port": payload.proxy_port if payload.proxy_port is not None else (7890 if payload.mode == "CLASH_HTTP" else 18988)}
        conflicts = [item["id"] for item in repo.list_servers() if item["id"] != server_id
                     and item["host"] == server["host"] and item["user"] == server["user"]
                     and item["ssh_port"] == server["ssh_port"] and item["remote_proxy_port"] == server["remote_proxy_port"]
                     and item["desired_state"] == "RUNNING"]
        deps = await dependencies()
        reasons = []
        if server["management"] != "MANAGED":
            reasons.append("EXTERNAL_RESOURCE")
        if conflicts:
            reasons.append("PORT_CONFLICT")
        if server["remote_proxy_port"] in {17890, 17891}:
            reasons.append("PROTECTED_PRODUCTION_PORT")
        if server["mode"] == "DISABLED":
            reasons.append("DISABLED_MODE")
        if deps["ssh"]["state"] != "AVAILABLE":
            reasons.append("SSH_UNAVAILABLE")
        if server["mode"] == "MAC_DIRECT" and deps["tinyproxy"]["state"] != "AVAILABLE":
            reasons.append("TINYPROXY_UNAVAILABLE")
        local_port = server["proxy_port"]
        local_open = False
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", local_port), timeout=0.2)
            writer.close()
            await writer.wait_closed()
            local_open = True
        except (OSError, TimeoutError):
            pass
        proxy_snapshot = engine.proxy.snapshot() if engine and hasattr(engine, "proxy") else {}
        owned_ports = {item["port"] for item in proxy_snapshot.get("managed_tinyproxy", []) if item.get("alive")}
        if server["mode"] == "MAC_DIRECT":
            if local_port in {7890, 18888, 17890, 17891}:
                reasons.append("PROTECTED_PORT")
            elif local_open and local_port not in owned_ports:
                reasons.append("LOCAL_PORT_CONFLICT")
        elif server["mode"] == "CLASH_HTTP" and not local_open:
            reasons.append("DEPENDENCY_UNAVAILABLE")
        current_runtime = fresh_runtime(server_id) or {}
        return {"server_id": server_id, "ownership": server["management"], "dependencies": deps,
                "local_reservation_conflicts": conflicts, "remote_listener": "UNKNOWN",
                "reason": "Remote preflight requires an app-owned connection; no remote change was attempted",
                "can_start": not reasons, "blocking_reasons": reasons,
                "current_runtime": current_runtime, "proposed_mode": server["mode"],
                "local_proxy": {"port": local_port, "tcp_reachable": local_open, "owned": local_port in owned_ports, "http_health": "UNKNOWN"},
                "ordinary_ssh_login_affected": False, "production_control_enabled": False}

    @router.post("/servers/{server_id}/tests")
    async def connection_test(request: Request, server_id: str, payload: ConnectionTestInput):
        session_for(request)
        server = server_or_404(server_id)
        if server["management"] != "MANAGED":
            raise HTTPException(403, {"code": "EXTERNAL_RESOURCE", "message": "External profiles cannot be controlled"})
        if engine is None or not hasattr(engine, "test_connection"):
            raise HTTPException(503, {"code": "DEPENDENCY_UNAVAILABLE", "message": "Connection test engine is unavailable"})
        try:
            result = await engine.test_connection(server_id, payload.kind)
            repo.audit("server.test", server_id, "SUCCEEDED" if result["passed"] else "FAILED", {"kind": payload.kind, "stopped_after_test": result["stopped_after_test"]})
            await publish({"type": "server.test", "server_id": server_id, "payload": result})
            return result
        except Exception as error:
            raise _error(error) from error

    @router.post("/servers/{server_id}/diagnostics")
    async def server_diagnostics(request: Request, server_id: str, payload: DiagnosticsInput):
        session_for(request)
        server = server_or_404(server_id)
        if server["management"] != "MANAGED":
            raise HTTPException(403, {"code": "EXTERNAL_RESOURCE", "message": "External profiles cannot be controlled"})
        if engine is None or not hasattr(engine, "diagnostic_probe"):
            raise HTTPException(503, {"code": "DEPENDENCY_UNAVAILABLE", "message": "Diagnostics engine is unavailable"})
        try:
            result = await engine.diagnostic_probe(server_id, payload.target_url)
            repo.audit("server.diagnostics", server_id, "SUCCEEDED" if result["http_reachable"] else "FAILED", {"target": "hubway.cc/v1", "http_status": result.get("http_status")})
            return result
        except Exception as error:
            raise _error(error) from error

    @router.post("/servers/{server_id}/credentials/codex/check")
    async def codex_credential_check(request: Request, server_id: str, payload: CodexCredentialCheckInput):
        session_for(request)
        if payload.consent is not True:
            raise HTTPException(403, {"code": "CONSENT_REQUIRED", "message": "请先确认读取远端 Codex API Key 状态"})
        server = server_or_404(server_id)
        if server["management"] != "MANAGED":
            raise HTTPException(403, {"code": "EXTERNAL_RESOURCE", "message": "外部连接仅供观察，不能检查凭据"})
        if engine is None or not hasattr(engine, "codex_credential_check"):
            raise HTTPException(503, {"code": "DEPENDENCY_UNAVAILABLE", "message": "凭据检查功能暂不可用"})
        try:
            result = safe_api_result(await engine.codex_credential_check(server_id, payload.source, payload.consent), server_id)
            # Persist status enums only. Credential material and source paths
            # are excluded from logs, SQLite, events, and diagnostic exports.
            repo.audit("server.credentials.codex.check", server_id,
                       "SUCCEEDED" if result["credential_state"] == "READABLE" else "FAILED",
                       {"source": payload.source, "credential_state": result["credential_state"]})
            return result
        except Exception as error:  # noqa: BLE001 - fixed response prevents secret reflection
            # Credential failures must not pass exception strings or details
            # through the generic formatter: even a faulty dependency might
            # put sensitive remote output in its exception text.
            safe_errors = {
                "OWNERSHIP_MISMATCH": (409, "连接归属已改变，未读取凭据"),
                "EXTERNAL_RESOURCE": (403, "外部连接仅供观察，不能检查凭据"),
                "SERVER_NOT_FOUND": (404, "服务器配置不存在"),
                "CONSENT_REQUIRED": (403, "请先确认读取远端 Codex API Key 状态"),
                "INVALID_CREDENTIAL_SOURCE": (422, "请选择远端 Codex auth.json 来源"),
            }
            code = getattr(error, "code", None)
            if isinstance(code, str) and code in safe_errors:
                status, message = safe_errors[code]
                raise HTTPException(status, {"code": code, "message": message}) from None
            raise HTTPException(503, {"code": "CHECK_UNAVAILABLE", "message": "凭据检查暂不可用，请稍后重试"}) from None

    def model_test_error(error: Exception) -> HTTPException:
        safe_errors = {
            "OWNERSHIP_MISMATCH": (409, "连接归属已改变，请重新检查"),
            "EXTERNAL_RESOURCE": (403, "外部连接仅供观察，不能进行模型测试"),
            "SERVER_NOT_FOUND": (404, "服务器配置不存在"),
            "CONSENT_REQUIRED": (403, "请先确认密钥接收方与模型测试费用"),
            "INVALID_CREDENTIAL_SOURCE": (422, "请选择远端 Codex auth.json 来源"),
            "INVALID_MODEL_TEST": (422, "请检查 API 地址、模型与协议"),
            "REVISION_CONFLICT": (409, "服务器配置已改变，请重新预览"),
            "MODEL_TEST_COOLDOWN": (429, "两次模型测试需间隔至少 30 秒"),
        }
        code = getattr(error, "code", None)
        if isinstance(code, str) and code in safe_errors:
            status, message = safe_errors[code]
            return HTTPException(status, {"code": code, "message": message})
        return HTTPException(503, {"code": "CHECK_UNAVAILABLE", "message": "模型测试暂不可用，请稍后重试"})

    @router.post("/servers/{server_id}/model-test/preview")
    async def codex_model_preview(request: Request, server_id: str, payload: CodexModelPreviewInput):
        session_for(request)
        server = server_or_404(server_id)
        if server["management"] != "MANAGED":
            raise HTTPException(403, {"code": "EXTERNAL_RESOURCE", "message": "外部连接仅供观察，不能读取模型配置"})
        if engine is None or not hasattr(engine, "codex_model_preview"):
            raise HTTPException(503, {"code": "DEPENDENCY_UNAVAILABLE", "message": "模型配置预览暂不可用"})
        try:
            return safe_model_preview_result(await engine.codex_model_preview(server_id, payload.source), server_id)
        except Exception as error:  # noqa: BLE001 - never reflect config/raw output
            raise model_test_error(error) from None

    @router.post("/servers/{server_id}/model-test")
    async def codex_model_test(request: Request, server_id: str, payload: CodexModelTestInput):
        session_for(request)
        if payload.consent is not True:
            raise HTTPException(403, {"code": "CONSENT_REQUIRED", "message": "请先确认密钥接收方与模型测试费用"})
        server = server_or_404(server_id)
        if server["management"] != "MANAGED":
            raise HTTPException(403, {"code": "EXTERNAL_RESOURCE", "message": "外部连接仅供观察，不能进行模型测试"})
        if payload.expected_revision != server["revision"]:
            raise HTTPException(409, {"code": "REVISION_CONFLICT", "message": "服务器配置已改变，请重新预览"})
        if engine is None or not hasattr(engine, "codex_model_test"):
            raise HTTPException(503, {"code": "DEPENDENCY_UNAVAILABLE", "message": "模型测试暂不可用"})
        try:
            result = safe_model_api_result(await engine.codex_model_test(
                server_id, payload.source, payload.consent, payload.base_url, payload.model,
                payload.wire_api, payload.expected_revision), server_id)
            # Status only: no URL, model, output, provider body, path, or key is
            # retained in SQLite, logs, events, or diagnostic exports.
            repo.audit("server.model-test", server_id, "SUCCEEDED" if result["state"] == "SUCCESS" else "FAILED",
                       {"source": payload.source, "state": result["state"], "http_status": result["http_status"]})
            return result
        except Exception as error:  # noqa: BLE001 - fixed response prevents secret reflection
            raise model_test_error(error) from None

    @router.get("/servers/{server_id}/metrics")
    async def metrics(request: Request, server_id: str, limit: int = Query(500, ge=1, le=10000)):
        session_for(request)
        server_or_404(server_id)
        return repo.samples(server_id, limit)

    @router.get("/servers/{server_id}/metrics/history")
    async def metrics_history(request: Request, server_id: str, range: str = Query("1h", pattern="^(5m|1h|24h|7d)$")):
        session_for(request)
        server_or_404(server_id)
        return repo.samples_in_range(server_id, range)

    @router.get("/servers/{server_id}/events")
    async def events_for_server(request: Request, server_id: str, limit: int = Query(200, ge=1, le=1000)):
        session_for(request)
        server_or_404(server_id)
        return repo.state_events(server_id, limit)

    @router.get("/servers/{server_id}/logs")
    async def logs(request: Request, server_id: str, limit: int = Query(200, ge=1, le=1000), q: str = ""):
        session_for(request)
        server_or_404(server_id)
        return repo.logs(server_id, limit, q)

    @router.get("/operations/{operation_id}")
    async def operation(request: Request, operation_id: str):
        session_for(request)
        value = repo.get_operation(operation_id)
        if value is None:
            raise HTTPException(404, {"code": "NOT_FOUND", "message": "Operation does not exist"})
        return value

    @router.get("/settings")
    async def get_settings(request: Request):
        session_for(request)
        return repo.settings()

    @router.patch("/settings")
    async def patch_settings(request: Request, payload: SettingsInput):
        session_for(request)
        try:
            updated = repo.update_settings(payload.model_dump(exclude_unset=True))
            await asyncio.to_thread(repo.purge_history)
            repo.audit("settings.update", None, "SUCCEEDED", {"fields": list(payload.model_fields_set)})
            await publish({"type": "settings.changed", "payload": updated})
            return updated
        except Exception as error:
            raise _error(error) from error

    @router.get("/audit-events")
    async def audits(request: Request, limit: int = Query(200, ge=1, le=1000)):
        session_for(request)
        return repo.audit_events(limit)

    @router.get("/activity")
    async def activity(request: Request, limit: int = Query(30, ge=1, le=200)):
        session_for(request)
        return repo.activity_events(limit)

    @router.post("/imports/ssh-config/preview")
    async def ssh_preview(request: Request, payload: SSHPreviewInput):
        session_for(request)
        content = payload.content
        source = "inline"
        if payload.path:
            path = Path(payload.path).expanduser()
            if any(parent.is_symlink() for parent in (path, *path.parents)):
                raise HTTPException(422, {"code": "INVALID_IMPORT", "message": "SSH config path contains symbolic links"})
            # Only inspect explicit regular files; never evaluate SSH config (Match exec).
            allowed = {Path.home() / ".ssh" / "config", Path.cwd() / ".ssh" / "config"}
            if (not path.is_absolute() or path.is_symlink() or path not in allowed or not path.is_file()
                    or path.stat().st_size > 1048576):
                raise HTTPException(422, {"code": "INVALID_IMPORT", "message": "SSH config path is not an allowed regular file"})
            source = str(path.name)
            content = path.read_text(encoding="utf-8", errors="replace")
        if "PRIVATE KEY" in (content or ""):
            raise HTTPException(422, {"code": "PRIVATE_KEY_REJECTED", "message": "SSH import accepts configuration directives only"})
        candidates, warnings = [], []
        current: dict[str, str] | None = None
        seen: set[str] = set()
        in_match = False
        for raw in (content or "").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                parts = shlex.split(line, comments=True, posix=True)
            except ValueError:
                warnings.append("A line could not be parsed")
                continue
            if not parts:
                continue
            key = parts[0].lower()
            if key == "host":
                if current and current.get("host") and "*" not in current["host"] and "?" not in current["host"]:
                    candidates.append(current)
                current = {"ssh_alias": parts[1]} if len(parts) == 2 else None
                seen = {"ssh_alias"} if current else set()
                in_match = False
            elif key == "match":
                if current and current.get("host"):
                    candidates.append(current)
                warnings.append("Conditional Match block ignored; review the explicit candidate fields")
                in_match = True
                current = None
            elif current is not None and not in_match and key not in seen and len(parts) >= 2 and key in ("hostname", "port", "user", "identityfile"):
                current[{"hostname": "host", "port": "ssh_port", "user": "user", "identityfile": "identity_file_ref"}[key]] = parts[1]
                seen.add(key)
            elif key in ("match", "include", "proxycommand", "proxyjump"):
                warnings.append(f"Unsupported SSH directive omitted: {parts[0]}")
        if current and current.get("host") and "*" not in current["host"] and "?" not in current["host"]:
            candidates.append(current)
        normalized = []
        for candidate in candidates:
            try:
                value = ServerInput.model_validate({"name": candidate.get("ssh_alias", candidate["host"]),
                                                    "host": candidate["host"], "ssh_alias": candidate.get("ssh_alias"),
                                                    "ssh_port": int(candidate.get("ssh_port", 22)),
                                                    "user": candidate.get("user", ""),
                                                    "identity_file_ref": candidate.get("identity_file_ref")}).model_dump()
                normalized.append(value)
            except (ValueError, TypeError, KeyError):
                warnings.append(f"Unsupported or invalid host omitted: {candidate.get('ssh_alias', '[unknown]')}")
        digest = hashlib.sha256((content or "").encode()).hexdigest()
        preview_id = add_preview({"candidates": normalized, "warnings": warnings, "hash": digest,
                                  "source_path": str(path) if payload.path else None})
        return {"preview_id": preview_id, "source": source, "source_sha256": digest, "candidates": normalized, "warnings": warnings}

    @router.post("/imports/{preview_id}/commit")
    async def ssh_commit(request: Request, preview_id: str, payload: ImportCommitInput):
        session_for(request)
        preview = previews.get(preview_id)
        if not preview or preview["expires"] < asyncio.get_running_loop().time():
            raise HTTPException(404, {"code": "PREVIEW_EXPIRED", "message": "Import preview is expired"})
        if payload.expected_hash and payload.expected_hash != preview["hash"]:
            raise HTTPException(409, {"code": "PREVIEW_CHANGED", "message": "Import content changed"})
        if preview.get("source_path"):
            path = Path(preview["source_path"])
            if any(parent.is_symlink() for parent in (path, *path.parents)) or not path.is_file() or path.stat().st_size > 1048576:
                raise HTTPException(409, {"code": "PREVIEW_CHANGED", "message": "Source configuration changed or became unsafe"})
            digest = hashlib.sha256(path.read_text(encoding="utf-8", errors="replace").encode()).hexdigest()
            if digest != preview["hash"]:
                raise HTTPException(409, {"code": "PREVIEW_CHANGED", "message": "Source configuration changed; preview again"})
        if any(index < 0 or index >= len(preview["candidates"]) for index in payload.indexes):
            raise HTTPException(422, {"code": "INVALID_SELECTION", "message": "Import candidate index is invalid"})
        try:
            created = repo.import_servers([preview["candidates"][index] for index in payload.indexes])
            del previews[preview_id]
            repo.audit("ssh.import", None, "SUCCEEDED", {"count": len(created)})
            await publish({"type": "servers.changed", "payload": {"count": len(created)}})
            return {"servers": created, "started": False}
        except Exception as error:
            raise _error(error) from error

    @router.post("/configuration/export")
    async def config_export(request: Request, payload: ExportInput):
        session_for(request)
        groups = repo.list_groups()
        servers = []
        for item in repo.list_servers():
            value = {key: item[key] for key in ServerInput.model_fields}
            servers.append(value)
        content = {"schema_version": 1, "groups": [{"id": item["id"], "name": item["name"]} for item in groups],
                   "servers": servers, "settings": repo.settings()}
        if not payload.include_connection_details:
            sensitive = repo._sensitive()
            for group in content["groups"]:
                group["name"] = redact_text(group["name"], sensitive)
            for item in content["servers"]:
                item["name"] = redact_text(item["name"], sensitive)
                item["host"] = "[redacted]"
                item["user"] = "[redacted]"
                item["identity_file_ref"] = None
                item["ssh_alias"] = None
                item["health_url"] = "https://example.com/"
        artifact = repo.save_artifact(content, "configuration-export")
        repo.audit("configuration.export", None, "SUCCEEDED", {"connection_details": payload.include_connection_details})
        return artifact

    @router.post("/configuration/import/preview")
    async def configuration_preview(request: Request, payload: ConfigurationInput):
        session_for(request)
        preview_id = add_preview({"config": payload.model_dump()})
        return {"preview_id": preview_id, "servers": len(payload.servers), "warnings": []}

    @router.post("/configuration/import/{preview_id}/commit")
    async def configuration_commit(request: Request, preview_id: str):
        session_for(request)
        preview = previews.get(preview_id)
        if not preview or "config" not in preview or preview["expires"] < asyncio.get_running_loop().time():
            raise HTTPException(404, {"code": "PREVIEW_EXPIRED", "message": "Configuration preview is expired"})
        try:
            config = preview["config"]
            backup = repo.backup()
            servers = repo.import_configuration(config)
            del previews[preview_id]
            repo.audit("configuration.import", None, "SUCCEEDED", {"count": len(servers), "backup": backup.name})
            await publish({"type": "servers.changed", "payload": {"count": len(servers)}})
            return {"servers": servers, "backup": str(backup.name), "started": False}
        except Exception as error:
            raise _error(error) from error

    @router.post("/diagnostics/exports")
    async def diagnostics(request: Request):
        session_for(request)
        servers = [{"id": item["id"], "name": item["name"], "mode": item["mode"], "management": item["management"],
                    "runtime": fresh_runtime(item["id"]), "logs": repo.logs(item["id"], 100)} for item in repo.list_servers()]
        artifact = repo.save_artifact({"schema_version": 1, "created_at": utc_now(), "servers": redact_details(servers, repo._sensitive())}, "diagnostics")
        repo.audit("diagnostics.export", None, "SUCCEEDED", {})
        return artifact

    @router.get("/artifacts/{artifact_id}")
    async def artifact(request: Request, artifact_id: str):
        session_for(request)
        path = repo.get_artifact(artifact_id)
        if path is None:
            raise HTTPException(404, {"code": "NOT_FOUND", "message": "Artifact does not exist"})
        return FileResponse(path, filename=path.name, media_type="application/json")

    @router.post("/migrations/proposals")
    async def migration_proposal(request: Request, payload: MigrationInput):
        session_for(request)
        server = server_or_404(payload.server_id)
        proposal = {
            "proposal_id": str(uuid4()), "state": "PREVIEW_ONLY", "server_id": server["id"],
            "profile_revision": server["revision"], "expires_in": 600,
            "resource": {"management": server["management"], "remote_proxy_port": server["remote_proxy_port"],
                         "proxy_mode": server["mode"], "local_proxy_port": server["proxy_port"]},
            "impact": {"estimated_downtime": "UNKNOWN_UNTIL_AUTHORIZED_REHEARSAL", "production_control": "blocked",
                       "scope": "仅包含单独获批的 SSH 通道及其原有托管服务",
                       "ordinary_ssh_login": "方案不修改 SSH 配置或远程环境"},
            "prerequisites": ["以最新只读证据确认原进程及其托管服务",
                              "记录原启动配置指纹和恢复步骤",
                              "先通过隔离端口的 SSH、TLS 和端到端代理验收",
                              "取得明确指名原资源与方案校验值的授权"],
            "steps": ["仅预览和备份获批配置的必要元数据",
                      "仅禁用获批的原托管服务，避免重复重连",
                      "重新核实资源归属后，仅停止获批的原通道",
                      "启动应用自有替代通道，验证远程监听及端到端请求"],
            "rollback": ["仅停止 Tunnel Manager 创建的替代通道",
                         "通过已记录的原管理者恢复原托管服务配置",
                         "验证原通道和代理健康，保留所有失败证据"],
            "blocked_reason": "RESOURCE_SPECIFIC_PRODUCTION_AUTHORIZATION_REQUIRED",
            "execution_enabled": False,
        }
        proposal["plan_sha256"] = hashlib.sha256(
            json.dumps(proposal, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        repo.audit("migration.preview", server["id"], "PREVIEW_ONLY", {"plan_sha256": proposal["plan_sha256"]})
        return proposal

    @router.post("/migrations/{proposal_id}/execute")
    async def migration_execute(request: Request, proposal_id: str):
        session_for(request)
        raise HTTPException(403, {"code": "FEATURE_NOT_ENABLED", "message": "Production migration requires a separate approved phase"})

    return router


async def authenticate_ws(security: SecurityManager, websocket: WebSocket) -> Session | None:
    return await security.authenticate_websocket(websocket)
