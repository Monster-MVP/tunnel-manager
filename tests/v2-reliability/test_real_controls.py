"""Real system OpenSSH/API controls; no production target or synthetic health."""

import asyncio
import contextlib

import pytest

from tests.integration.test_fault_recovery import action, free_port, runtime


async def finished(client, operation_id):
    deadline = asyncio.get_running_loop().time() + 12
    while asyncio.get_running_loop().time() < deadline:
        response = await client.get(f"/api/v1/operations/{operation_id}")
        assert response.status_code == 200
        operation = response.json()
        if operation["status"] in {"FAILED", "SUCCEEDED"}:
            return operation
        await asyncio.sleep(.03)
    pytest.fail(f"Operation exceeded bounded audit deadline: {operation}")


@pytest.mark.asyncio
async def test_preflight_is_read_only_and_never_calls_a_socket_health_proof(live_network):
    _, client, server, status, proxy, _, connections = live_network
    before = (await client.get(f"/api/v1/servers/{server['id']}")).json()
    result = (await client.post(f"/api/v1/servers/{server['id']}/preflight",
                               json={"mode": "CLASH_HTTP", "proxy_port": server["proxy_port"]})).json()
    after = (await client.get(f"/api/v1/servers/{server['id']}")).json()
    assert before == after and not connections and status["requests"] == 0
    assert result["can_start"] and result["local_proxy"]["tcp_reachable"]
    assert result["local_proxy"]["http_health"] == "UNKNOWN"
    assert result["remote_listener"] == "UNKNOWN" and proxy.is_serving()
    assert (await runtime(client, server))["state"] == "STOPPED"


@pytest.mark.asyncio
async def test_wizard_api_proves_request_and_cleans_exact_tunnel(live_network):
    _, client, server, status, proxy, _, _ = live_network
    path = f"/api/v1/servers/{server['id']}/tests"
    result = (await client.post(path, json={"kind": "proxy"})).json()
    assert result["passed"] and result["runtime"]["state"] == "HEALTHY"
    assert result["runtime"]["http_status"] == 200 and status["requests"] > 0
    assert result["stopped_after_test"] and not result["final_runtime"]["process_alive"]
    assert result["final_runtime"]["state"] == "STOPPED"
    assert (await client.get(f"/api/v1/servers/{server['id']}")).json()["desired_state"] == "STOPPED"
    _, writer = await asyncio.open_connection("127.0.0.1", server["proxy_port"])
    writer.close()
    await writer.wait_closed()
    with pytest.raises(OSError):
        await asyncio.open_connection("127.0.0.1", server["remote_proxy_port"])
    assert proxy.is_serving()


@pytest.mark.asyncio
async def test_wizard_api_keeps_ssh_success_distinct_from_http_failure(live_network):
    _, client, server, status, _, _, _ = live_network
    status["code"] = 503
    connection = (await client.post(f"/api/v1/servers/{server['id']}/tests",
                                    json={"kind": "connection"})).json()
    proxy = (await client.post(f"/api/v1/servers/{server['id']}/tests",
                               json={"kind": "proxy"})).json()
    assert connection["passed"] and connection["connection_ok"] and not connection["proxy_ok"]
    assert not proxy["passed"] and proxy["runtime"]["http_status"] == 503
    assert proxy["runtime"]["remote_listener"] == "LISTENING"
    assert proxy["stopped_after_test"] and (await runtime(client, server))["state"] == "STOPPED"


@pytest.mark.asyncio
async def test_mode_failure_is_failed_operation_with_verified_previous_exit(live_network):
    _, client, server, _, old_proxy, _, _ = live_network
    assert (await action(client, server, "start"))["status"] == "SUCCEEDED"

    async def broken_exit(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 503 Fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    broken = await asyncio.start_server(broken_exit, "127.0.0.1", 0)
    try:
        current = (await client.get(f"/api/v1/servers/{server['id']}")).json()
        accepted = await client.put(f"/api/v1/servers/{server['id']}/mode",
            json={"mode": "CLASH_HTTP", "proxy_port": broken.sockets[0].getsockname()[1]},
            headers={"If-Match": str(current["revision"])})
        assert accepted.status_code == 202
        operation = await finished(client, accepted.json()["operation_id"])
        assert operation["status"] == "FAILED" and operation["error_code"] == "MODE_CHANGE_ROLLED_BACK"
        restored = (await client.get(f"/api/v1/servers/{server['id']}")).json()
        fresh = await runtime(client, server)
        assert restored["proxy_port"] == server["proxy_port"] and restored["mode"] == "CLASH_HTTP"
        assert fresh["state"] == "HEALTHY" and fresh["http_status"] == 200 and not fresh["stale"]
        assert fresh["rollback_success"] and old_proxy.is_serving() and broken.is_serving()
        activity = (await client.get("/api/v1/activity?limit=30")).json()
        assert any(item["action"] == "mode" and item["result"] == "FAILED" for item in activity)
    finally:
        broken.close()
        await broken.wait_closed()


@pytest.mark.asyncio
async def test_unavailable_mode_preserves_current_master_and_configuration(live_network):
    _, client, server, _, proxy, _, _ = live_network
    assert (await action(client, server, "start"))["status"] == "SUCCEEDED"
    prior = await runtime(client, server)
    profile = (await client.get(f"/api/v1/servers/{server['id']}")).json()
    accepted = await client.put(f"/api/v1/servers/{server['id']}/mode",
        json={"mode": "CLASH_HTTP", "proxy_port": free_port()},
        headers={"If-Match": str(profile["revision"])})
    operation = await finished(client, accepted.json()["operation_id"])
    assert operation["status"] == "FAILED" and operation["error_code"] == "DEPENDENCY_UNAVAILABLE"
    assert (await runtime(client, server))["pid"] == prior["pid"]
    assert (await client.get(f"/api/v1/servers/{server['id']}")).json() == profile
    assert proxy.is_serving()


@pytest.mark.asyncio
async def test_concurrent_mode_requests_reject_stale_revision_without_duplicate_masters(live_network):
    _, client, server, _, proxy, _, connections = live_network
    assert (await action(client, server, "start"))["status"] == "SUCCEEDED"
    current = (await client.get(f"/api/v1/servers/{server['id']}")).json()
    responses = await asyncio.gather(*(client.put(f"/api/v1/servers/{server['id']}/mode",
        json={"mode": "CLASH_HTTP", "proxy_port": server["proxy_port"]},
        headers={"If-Match": str(current["revision"])}) for _ in range(6)))
    assert all(response.status_code in {202, 409} for response in responses)
    operations = await asyncio.gather(*(finished(client, response.json()["operation_id"])
                                        for response in responses if response.status_code == 202))
    assert sum(operation["status"] == "SUCCEEDED" for operation in operations) == 1
    assert all(operation["status"] == "SUCCEEDED" or operation["error_code"] == "REVISION_CONFLICT"
               for operation in operations)
    assert (await runtime(client, server))["state"] == "HEALTHY" and proxy.is_serving()
    assert sum(not connection.is_closed() for connection in connections) == 1


@pytest.mark.asyncio
async def test_stopping_does_not_leave_current_proxy_health_marked_healthy(live_network):
    _, client, server, _, _, _, _ = live_network
    assert (await action(client, server, "start"))["status"] == "SUCCEEDED"
    assert (await runtime(client, server))["proxy_health"] == "HEALTHY"
    assert (await action(client, server, "stop"))["status"] == "SUCCEEDED"
    stopped = await runtime(client, server)
    assert stopped["state"] == "STOPPED" and not stopped["process_alive"]
    assert stopped["proxy_health"] != "HEALTHY", stopped
    assert stopped.get("http_connect_status") is None and stopped.get("ssh_latency_ms") is None
    assert stopped.get("tls_handshake_ms") is None
