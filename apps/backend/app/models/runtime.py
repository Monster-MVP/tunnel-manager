from datetime import UTC, datetime


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def stopped_runtime(server_id: str) -> dict:
    return {
        "server_id": server_id,
        "state": "STOPPED",
        "reason_code": None,
        "generation": 0,
        "run_id": None,
        "process_alive": False,
        "ssh_connected": False,
        "remote_listener": "UNKNOWN",
        "http_status": None,
        "total_ms": None,
        "tls_completed_ms": None,
        "tls_handshake_ms": None,
        "consecutive_failures": 0,
        "reconnect_count": 0,
        "last_disconnected_at": None,
        "last_recovered_at": None,
        "observed_at": utc_now(),
        "stale": True,
        "pid": None,
        "direct_path_verification": "UNVERIFIED",
        "monitoring_capability": "UNVERIFIED",
        "evidence": [],
    }
