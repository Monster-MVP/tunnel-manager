from __future__ import annotations

import argparse
import asyncio
import ctypes
import fcntl
import json
import os
import socket
import stat
import sys
from pathlib import Path

import uvicorn

from app.main import create_app


def private_directory(path: Path) -> Path:
    absolute = path.absolute()
    for parent in (absolute, *absolute.parents):
        if parent.is_symlink():
            raise ValueError("Runtime paths must not contain symlinks")
    absolute.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = absolute.stat()
    if metadata.st_uid != os.getuid() or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("Runtime directory must be owned by the current user")
    absolute.chmod(0o700)
    return absolute


def peer_uid(sock) -> int | None:
    if sys.platform == "darwin":
        uid = ctypes.c_uint()
        gid = ctypes.c_uint()
        libc = ctypes.CDLL(None)
        if libc.getpeereid(sock.fileno(), ctypes.byref(uid), ctypes.byref(gid)) == 0:
            return int(uid.value)
    elif hasattr(socket, "SO_PEERCRED"):
        import struct

        return struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
    return None


async def run(args) -> None:
    original_parent = args.expected_parent or os.getppid()
    if args.watch_parent and os.getppid() != original_parent:
        raise SystemExit("Supervisor exited before backend startup")
    os.umask(0o077)
    data_dir = private_directory(Path(args.data_dir))
    runtime_dir = private_directory(Path(args.runtime_dir))
    lock_path = runtime_dir / "backend.lock"
    lock = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lock)
        raise SystemExit("Tunnel Manager backend is already running")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", args.port))
    listener.listen(128)
    port = listener.getsockname()[1]
    app = create_app(
        data_dir,
        Path(args.web_dir) if args.web_dir else None,
        origin=f"http://127.0.0.1:{port}",
        tinyproxy_executable=args.tinyproxy_executable,
        recover_desired=args.recover_owned_state,
    )
    configuration = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning",
                                   access_log=False, timeout_graceful_shutdown=5)
    server = uvicorn.Server(configuration)
    control_path = runtime_dir / "control.sock"
    if len(os.fsencode(control_path)) > 100:
        raise ValueError("Runtime directory is too long for a macOS Unix socket")
    if control_path.exists() or control_path.is_symlink():
        if control_path.is_symlink() or not stat.S_ISSOCK(control_path.lstat().st_mode):
            raise ValueError("Unsafe preexisting control path")
        control_path.unlink()

    async def control(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            if peer_uid(writer.get_extra_info("socket")) != os.getuid():
                return
            line = await asyncio.wait_for(reader.readline(), 2)
            if len(line) > 2048:
                return
            request = json.loads(line)
            if not isinstance(request, dict):
                return
            command = request.get("command")
            if command == "ticket":
                try:
                    response = {"ticket": app.state.security.issue_bootstrap_ticket(), "port": port}
                except RuntimeError:
                    response = {"error": "CAPACITY_LIMIT"}
            elif command == "status":
                response = {"alive": True, "port": port, "pid": os.getpid()}
            elif command == "shutdown":
                server.should_exit = True
                response = {"stopping": True}
            else:
                response = {"error": "UNKNOWN_COMMAND"}
            writer.write(json.dumps(response).encode() + b"\n")
            await writer.drain()
        except (TimeoutError, ValueError, ConnectionError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    ipc = await asyncio.start_unix_server(control, path=str(control_path), limit=4096)
    control_path.chmod(0o600)
    endpoint = runtime_dir / "endpoint.json"
    if endpoint.is_symlink():
        raise ValueError("Unsafe endpoint file")
    endpoint_fd = os.open(endpoint, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(endpoint_fd, "w") as stream:
        stream.write(json.dumps({"pid": os.getpid(), "port": port, "origin": f"http://127.0.0.1:{port}"}))
    try:
        async with ipc:
            async def parent_guard():
                while not server.should_exit:
                    await asyncio.sleep(1)
                    if args.watch_parent and os.getppid() != original_parent:
                        server.should_exit = True

            guard = asyncio.create_task(parent_guard())
            try:
                await server.serve(sockets=[listener])
            finally:
                guard.cancel()
                await asyncio.gather(guard, return_exceptions=True)
    finally:
        ipc.close()
        await ipc.wait_closed()
        control_path.unlink(missing_ok=True)
        endpoint.unlink(missing_ok=True)
        listener.close()
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)


def main() -> None:
    parser = argparse.ArgumentParser(description="Tunnel Manager private local service")
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--runtime-dir", required=True)
    parser.add_argument("--web-dir")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--tinyproxy-executable")
    parser.add_argument("--watch-parent", action="store_true")
    parser.add_argument("--expected-parent", type=int)
    parser.add_argument("--recover-owned-state", action="store_true")
    args = parser.parse_args()
    if args.port in {7890, 18888, 17890, 17891}:
        parser.error("Production ports are protected")
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
