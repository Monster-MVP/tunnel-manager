"""Health probe parsing with explicit transport and timing evidence."""

from __future__ import annotations

import math
import shlex
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class HealthProbe:
    capable: bool
    transport_ok: bool
    http_status: int | None = None
    total_ms: float | None = None
    tls_completed_ms: float | None = None
    tls_handshake_ms: float | None = None
    error_code: str | None = None
    http_connect_status: int | None = None

    @classmethod
    def unavailable(cls, code: str) -> HealthProbe:
        return cls(False, False, error_code=code)

    @classmethod
    def from_curl(cls, output: str, transport_exit: int = 0) -> HealthProbe:
        if transport_exit != 0:
            return cls(transport_exit not in {69, 127}, False,
                       error_code="PROBE_UNAVAILABLE" if transport_exit in {69, 127} else "PROXY_UNHEALTHY")
        fields = output.strip().split()
        if len(fields) not in (4, 5):
            return cls(True, False, error_code="PROBE_PARSE_ERROR")
        try:
            status = int(fields[0])
            total = float(fields[1]) * 1000
            appconnect = float(fields[2]) * 1000
            connect = float(fields[3]) * 1000
            http_connect = int(fields[4]) if len(fields) == 5 else 0
        except ValueError:
            return cls(True, False, error_code="PROBE_PARSE_ERROR")
        if not 100 <= status <= 599 or (http_connect != 0 and not 100 <= http_connect <= 599) or not all(math.isfinite(x) and x >= 0 for x in (total, appconnect, connect)):
            return cls(True, False, error_code="PROBE_PARSE_ERROR")
        return cls(True, True, status, total, appconnect if appconnect > 0 else None,
                   max(0, appconnect - connect) if appconnect > 0 else None,
                   http_connect_status=http_connect or None)

    def as_dict(self) -> dict[str, object]:
        return {
            "capable": self.capable,
            "transport_ok": self.transport_ok,
            "http_status": self.http_status,
            "total_ms": self.total_ms,
            "tls_completed_ms": self.tls_completed_ms,
            "tls_handshake_ms": self.tls_handshake_ms,
            "error_code": self.error_code,
            "http_connect_status": self.http_connect_status,
        }


def validate_health_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("health URL must be an http(s) URL")
    if parsed.username or parsed.password or any(ord(ch) < 32 for ch in url):
        raise ValueError("health URL contains forbidden credentials/control characters")
    if len(url) > 2048:
        raise ValueError("health URL is too long")


def build_remote_curl_command(url: str, remote_proxy_port: int, timeout_s: float = 15) -> str:
    validate_health_url(url)
    if not 1 <= int(remote_proxy_port) <= 65535:
        raise ValueError("invalid proxy port")
    timeout = max(1.0, min(float(timeout_s), 120.0))
    # curl -q must be first so a user's ~/.curlrc cannot alter a probe.
    args = [
        "curl",
        "-q",
        "-sS",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code} %{time_total} %{time_appconnect} %{time_connect} %{http_connect}",
        "--connect-timeout",
        f"{timeout:g}",
        "--max-time",
        f"{timeout:g}",
        "--noproxy",
        "",
        "--proto",
        "=http,https",
        "--max-redirs",
        "0",
        "-x",
        f"http://127.0.0.1:{int(remote_proxy_port)}",
        url,
    ]
    return " ".join(shlex.quote(arg) for arg in args)
