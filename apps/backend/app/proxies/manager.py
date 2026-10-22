"""Managed tinyproxy lifecycle and read-only external HTTP dependencies."""

from __future__ import annotations

import asyncio
import os
import socket
import uuid
from dataclasses import dataclass, field
from pathlib import Path


class ProxyError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class ProxyProcess:
    process: asyncio.subprocess.Process
    port: int
    config_path: Path
    users: set[str] = field(default_factory=set)


def private_directory(path: Path) -> None:
    if path.is_symlink():
        raise ProxyError("UNSAFE_STORAGE", "Runtime directory is a symbolic link")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    stat = path.stat()
    if stat.st_uid != os.getuid() or stat.st_mode & 0o077:
        raise ProxyError("UNSAFE_STORAGE", "Runtime directory must be private and owned by this user")


def private_write(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(text)


class ProxyManager:
    """Only children spawned here are controllable; Clash is never controlled."""

    PROTECTED_PORTS = frozenset({7890, 18888, 17890, 17891})

    def __init__(self, data_dir: Path, tinyproxy_executable: str | None = None) -> None:
        self.proxy_dir = Path(data_dir) / "proxies"
        private_directory(self.proxy_dir)
        self.tinyproxy_executable = str(Path(tinyproxy_executable).resolve()) if tinyproxy_executable else None
        self._managed: dict[int, ProxyProcess] = {}
        self._lock = asyncio.Lock()

    async def ensure_for_mode(self, mode: str, requested_port: int = 18988, server_id: str = "") -> int:
        async with self._lock:
            port = int(requested_port)
            if mode == "CLASH_HTTP":
                if not self.port_open(port):
                    raise ProxyError("DEPENDENCY_UNAVAILABLE", "External HTTP proxy is not listening on loopback")
                return port
            if mode != "MAC_DIRECT":
                raise ProxyError("INVALID_MODE", "Unsupported proxy mode")
            if not 1024 <= port <= 65535 or port in self.PROTECTED_PORTS:
                raise ProxyError("PROTECTED_PORT", "Managed proxy must use an isolated, non-production port")
            managed = self._managed.get(port)
            if managed and managed.process.returncode is None:
                managed.users.add(server_id)
                return port
            if managed:
                del self._managed[port]
            # Actual tinyproxy bind decides races; a failed bind never stops
            # the competing process and never records its PID as owned.
            if self.port_open(port):
                raise ProxyError("PORT_CONFLICT", "Local proxy port is already in use")
            if not self.tinyproxy_executable:
                raise ProxyError("DEPENDENCY_UNAVAILABLE", "Bundled tinyproxy executable is not configured")
            run = uuid.uuid4().hex[:12]
            config = self.proxy_dir / f"tinyproxy-{port}-{run}.conf"
            private_write(
                config,
                "\n".join([
                    f"Port {port}", "Listen 127.0.0.1", "Allow 127.0.0.1",
                    "DisableViaHeader Yes", "LogLevel Critical", "Timeout 30", "MaxClients 128",
                    f'PidFile "{self.proxy_dir / (run + ".pid")}"',
                    f'LogFile "{self.proxy_dir / (run + ".log")}"',
                ]) + "\n",
            )
            try:
                process = await asyncio.create_subprocess_exec(
                    self.tinyproxy_executable, "-d", "-c", str(config),
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
            except OSError as exc:
                raise ProxyError("DEPENDENCY_UNAVAILABLE", "Unable to start bundled tinyproxy") from exc
            managed = ProxyProcess(process, port, config, {server_id})
            deadline = asyncio.get_running_loop().time() + 3
            while process.returncode is None and not self.port_open(port):
                if asyncio.get_running_loop().time() >= deadline:
                    await self._stop(managed)
                    raise ProxyError("PROXY_START_FAILED", "Managed tinyproxy did not become ready")
                await asyncio.sleep(0.05)
            if process.returncode is not None:
                raise ProxyError("PROXY_START_FAILED", "Managed tinyproxy exited before becoming ready")
            self._managed[port] = managed
            return port

    async def release(self, server_id: str) -> None:
        async with self._lock:
            for port, managed in list(self._managed.items()):
                managed.users.discard(server_id)
                if not managed.users:
                    await self._stop(managed)
                    self._managed.pop(port, None)

    async def close(self) -> None:
        async with self._lock:
            for managed in list(self._managed.values()):
                await self._stop(managed)
            self._managed.clear()

    async def _stop(self, managed: ProxyProcess) -> None:
        if self._managed.get(managed.port) not in (None, managed):
            raise ProxyError("OWNERSHIP_MISMATCH", "Proxy ownership changed; refusing to signal")
        process = managed.process
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=3)
            except TimeoutError:
                if process.returncode is None:
                    process.kill()
                await process.wait()

    def snapshot(self) -> dict[str, object]:
        return {"managed_tinyproxy": [{"port": p, "alive": m.process.returncode is None} for p, m in self._managed.items()]}

    @staticmethod
    def port_open(port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.1)
            return sock.connect_ex(("127.0.0.1", port)) == 0
