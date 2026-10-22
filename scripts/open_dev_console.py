"""Open the isolated development console through its private one-time ticket."""

from __future__ import annotations

import argparse
import json
import os
import socket
import stat
import webbrowser
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]


def development_socket(runtime: Path) -> Path:
    runtime = runtime.absolute()
    if not runtime.is_relative_to(ROOT / ".run") or runtime in {ROOT / ".run", ROOT / ".run/app"}:
        raise ValueError("Use a dedicated project-local development runtime, not the App runtime")
    for component in (runtime, *runtime.parents):
        if component.is_symlink() or component.resolve() != component:
            raise ValueError("Development runtime must not contain symlinks")
        info = component.stat()
        if info.st_uid != os.getuid():
            raise ValueError("Development runtime must be owned by the current user")
        if component == ROOT:
            break
    if stat.S_IMODE(runtime.stat().st_mode) & 0o077:
        raise ValueError("Development runtime must be private")
    path = runtime / "control.sock"
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError("Development IPC must be a private owned socket")
    return path


def bootstrap_url(runtime: Path) -> str:
    path = development_socket(runtime)
    with socket.socket(socket.AF_UNIX) as channel:
        channel.settimeout(4)
        channel.connect(str(path))
        channel.sendall(b'{"command":"ticket"}\n')
        data = b""
        while b"\n" not in data:
            chunk = channel.recv(4096)
            if not chunk or len(data) + len(chunk) > 8192:
                raise ValueError("Invalid development IPC response")
            data += chunk
    result = json.loads(data.split(b"\n", 1)[0])
    if not isinstance(result, dict):
        raise TypeError("Invalid development IPC response")
    port, ticket = result.get("port"), result.get("ticket")
    if (type(port) is not int or not 1 <= port <= 65535 or not isinstance(ticket, str)
            or not 20 <= len(ticket) <= 128 or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for char in ticket)):
        raise ValueError("Development console is not ready")
    return f"http://127.0.0.1:{port}/#ticket={quote(ticket, safe='')}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Open the isolated development console without printing its ticket")
    parser.add_argument("--runtime-dir", type=Path, default=ROOT / ".run/dev")
    args = parser.parse_args()
    try:
        url = bootstrap_url(args.runtime_dir)
        if not webbrowser.open(url, new=2):
            raise ValueError("Browser could not be opened")
    except (OSError, TypeError, ValueError):
        parser.exit(1, "Cannot open the development console; check the isolated backend and private runtime.\n")
    print("Development console opened; its one-time ticket was not printed or saved.")


if __name__ == "__main__":
    main()
