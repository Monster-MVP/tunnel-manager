"""Bounded, read-only local discovery.

This module deliberately parses SSH config text instead of invoking ``ssh -G``;
``Match exec`` and ``ProxyCommand`` are never evaluated. Process and launchd
observations are hints with provenance, never proof of connectivity or ownership.
"""
from __future__ import annotations

import asyncio
import hashlib
import re
import shlex
from datetime import UTC, datetime
from pathlib import Path

from app.schemas.inputs import ServerInput


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _parse_ssh(path: Path) -> tuple[list[dict], list[str], str, str | None]:
    if any(component.is_symlink() for component in (path, *path.parents)):
        return [], ["配置文件路径包含符号链接，未读取"], "uninspected", None
    if not path.exists():
        return [], ["配置文件不存在"], "absent", None
    if not path.is_file():
        return [], ["配置路径不是常规文件"], "uninspected", None
    try:
        if path.stat().st_size > 1_048_576:
            return [], ["配置文件超过 1 MiB 限制"], "inaccessible", None
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], ["配置文件读取失败"], "inaccessible", None
    candidates: list[dict] = []
    warnings: list[str] = []
    current: dict[str, str] | None = None
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Config discovery accepts simple literal Host blocks only.
        try:
            parts = shlex.split(line, comments=True)
        except ValueError:
            warnings.append("配置行格式无法解析，已忽略")
            continue
        if len(parts) < 2:
            continue
        key, value = parts[0].lower(), parts[1]
        if key == "host":
            if current and current.get("host"):
                candidates.append(current)
            current = {"ssh_alias": value} if len(parts) == 2 and "*" not in value and "?" not in value else None
            if current is None:
                warnings.append("通配 Host 块未导入；全局继承字段需要手动核对")
            seen = {"ssh_alias"} if current else set()
            continue
        if key == "match":
            if current and current.get("host"):
                candidates.append(current)
            current = None
            warnings.append("Match 条件块已忽略；未执行任何本地命令")
            continue
        if current is None or key in seen:
            continue
        mapping = {"hostname": "host", "port": "ssh_port", "user": "user", "identityfile": "identity_file_ref"}
        if key in mapping:
            # IdentityFile is metadata only; never read its contents.
            current[mapping[key]] = value
            seen.add(key)
        elif key == "remoteforward" and len(parts) == 3:
            remote = re.fullmatch(r"(?:127\.0\.0\.1:)?(\d+)", parts[1])
            local = re.fullmatch(r"(?:127\.0\.0\.1|localhost):(\d+)", parts[2])
            if remote and local and 1024 <= int(remote[1]) <= 65535 and 1024 <= int(local[1]) <= 65535:
                current["remote_proxy_port"] = remote[1]
                current["proxy_port"] = local[1]
        elif key in {"include", "proxycommand", "proxyjump", "localcommand"}:
            warnings.append(f"{parts[0]} 指令未导入")
    if current and current.get("host"):
        candidates.append(current)
    safe: list[dict] = []
    for item in candidates:
        if not item.get("host") or not item.get("user"):
            warnings.append(f"{item.get('ssh_alias', '[未命名]')} 缺少主机或用户")
            continue
        try:
            port = int(item.get("ssh_port", "22"))
            if not 1 <= port <= 65535 or any(ord(ch) < 32 for ch in item["host"] + item["user"]):
                raise ValueError
        except ValueError:
            warnings.append(f"{item.get('ssh_alias', '[未命名]')} 端口或字段无效")
            continue
        try:
            checked = ServerInput.model_validate({"name": item.get("ssh_alias") or item["host"], "host": item["host"],
                                                  "ssh_alias": item.get("ssh_alias"), "ssh_port": port, "user": item["user"],
                                                  "identity_file_ref": item.get("identity_file_ref")}).model_dump()
        except ValueError:
            warnings.append("含有未支持字段的主机配置已忽略")
            continue
        safe.append({"ssh_alias": checked.get("ssh_alias"), "host": checked["host"], "ssh_port": port,
                     "user": checked["user"], "identity_file_ref": checked.get("identity_file_ref"),
                     "remote_proxy_port": int(item["remote_proxy_port"]) if item.get("remote_proxy_port") else None,
                     "proxy_port": int(item["proxy_port"]) if item.get("proxy_port") else None,
                     "source": str(path.name), "management": "OBSERVED_EXTERNAL", "health": "UNKNOWN"})
    return safe, warnings, "observed", hashlib.sha256(text.encode()).hexdigest()


async def _command(argv: list[str], timeout: float = 1.5) -> tuple[str, str]:
    process = None
    try:
        process = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.PIPE)
        async def bounded(stream: asyncio.StreamReader, limit: int) -> tuple[bytes, bool]:
            value = bytearray()
            truncated = False
            while chunk := await stream.read(4096):
                if len(value) + len(chunk) > limit:
                    truncated = True
                value.extend(chunk[:max(0, limit - len(value))])
            return bytes(value), truncated
        out_result, err_result, _ = await asyncio.wait_for(
            asyncio.gather(bounded(process.stdout, 1_048_576), bounded(process.stderr, 2048), process.wait()), timeout)
        out, truncated = out_result
        err, _ = err_result
        return out.decode("utf-8", "replace"), "OUTPUT_TRUNCATED" if truncated else err.decode("utf-8", "replace")
    except asyncio.CancelledError:
        # This exact handle created only a read-only status query. Cancellation
        # must reap that child and propagate, never signal an observed service.
        if process is not None and process.returncode is None:
            process.kill()
            # Drain the killed child's buffered pipes as well. Waiting alone
            # can hang if a status query was cancelled during noisy output.
            await process.communicate()
        raise
    except (OSError, TimeoutError):
        if process is not None and process.returncode is None:
            process.kill()
            await process.communicate()
        return "", "不可访问"


async def collect_discovery(repo=None) -> dict:
    observed_at = _now()
    config = Path.home() / ".ssh" / "config"
    candidates, warnings, config_state, config_digest = _parse_ssh(config)
    launch_out, launch_err = await _command(["/bin/launchctl", "list"])
    launch_jobs = []
    if launch_out:
        for line in launch_out.splitlines():
            parts = line.split(None, 2)
            if len(parts) == 3 and ("ssh" in parts[2].lower() or "proxy" in parts[2].lower() or "clash" in parts[2].lower()):
                launch_jobs.append({"label": re.sub(r"[^A-Za-z0-9_.-]", "", parts[2])[:120], "pid_observed": parts[0] != "-", "ownership": "OBSERVED_EXTERNAL"})
    ps_out, ps_err = await _command(["/bin/ps", "-axo", "pid=,user=,comm="])
    processes = []
    if ps_out:
        for line in ps_out.splitlines():
            bits = line.split()
            if len(bits) >= 3 and (bits[-1].endswith("ssh") or bits[-1].endswith("tinyproxy") or "clash" in bits[-1].lower() or "mihomo" in bits[-1].lower()):
                try:
                    pid = int(bits[0])
                except ValueError:
                    continue
                processes.append({"pid": pid, "user": "[redacted]" if bits[1] else None, "program": Path(bits[-1]).name,
                                  "ownership": "OBSERVED_EXTERNAL", "health": "UNKNOWN"})
    net_out, net_err = await _command(["/usr/sbin/netstat", "-anv", "-p", "tcp"])
    listeners = []
    if net_out:
        for line in net_out.splitlines():
            if "LISTEN" not in line:
                continue
            match = re.search(r"(?:127\.0\.0\.1|::1)\.(\d+)\s", line)
            if match:
                listeners.append({"bind_host": "loopback", "port": int(match.group(1)), "ownership": "OBSERVED_EXTERNAL", "health": "UNKNOWN"})
            else:
                wildcard = re.search(r"\*\.(\d+)\s", line)
                if wildcard:
                    listeners.append({"bind_host": "wildcard", "port": int(wildcard.group(1)), "ownership": "OBSERVED_EXTERNAL", "health": "UNKNOWN"})
    configuration_files = []
    for directory in (Path.home() / "Library" / "LaunchAgents", Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons")):
        try:
            for path in sorted(directory.glob("*.plist"))[:1000]:
                if any(word in path.name.lower() for word in ("ssh", "proxy", "clash", "mihomo", "seeta", "autodl")):
                    configuration_files.append({"filename": path.name, "source": "user LaunchAgents" if directory == Path.home() / "Library" / "LaunchAgents" else directory.name,
                                                "state": "CONFIGURED", "contents": "UNINSPECTED", "health": "UNKNOWN"})
        except OSError:
            configuration_files.append({"source": directory.name, "state": "INACCESSIBLE", "health": "UNKNOWN"})
    for path in (Path.home() / "tinyproxy-autodl.conf", Path("/opt/homebrew/etc/tinyproxy.conf")):
        if any(component.is_symlink() for component in (path, *path.parents)):
            configuration_files.append({"filename": path.name, "state": "UNINSPECTED", "health": "UNKNOWN"})
            continue
        try:
            metadata = {"filename": path.name, "state": "CONFIGURED" if path.is_file() else "ABSENT",
                        "contents": "UNINSPECTED", "health": "UNKNOWN"}
            if path.is_file() and path.stat().st_size <= 1_048_576:
                fields = {}
                with path.open(encoding="utf-8", errors="replace") as stream:
                    for line in stream:
                        if len(line) > 4096:
                            continue
                        parts = line.strip().split()
                        if len(parts) == 2 and parts[0].lower() == "port" and parts[1].isdigit() and 1 <= int(parts[1]) <= 65535:
                            fields["port"] = int(parts[1])
                        elif len(parts) == 2 and parts[0].lower() == "listen":
                            fields["bind_host"] = parts[1] if parts[1] in {"127.0.0.1", "::1"} else "non-loopback"
                metadata.update(contents="SAFE_FIELDS_ONLY", fields=fields)
            configuration_files.append(metadata)
        except OSError:
            configuration_files.append({"filename": path.name, "state": "INACCESSIBLE", "health": "UNKNOWN"})
    return {
        "observed_at": observed_at,
        "provenance": {"ssh_config": "~/.ssh/config", "ssh_config_state": config_state, "launchd": "launchctl list (read-only)", "processes": "ps (read-only)", "listeners": "netstat (read-only)"},
        "ssh_config": {"state": config_state, "candidates": candidates, "warnings": sorted(set(warnings)), "sha256": config_digest},
        "launchd": {"state": "PARTIAL" if launch_err == "OUTPUT_TRUNCATED" else "OBSERVED" if launch_out else ("INACCESSIBLE" if launch_err else "NONE_OBSERVED"), "jobs": launch_jobs},
        "processes": {"state": "PARTIAL" if ps_err == "OUTPUT_TRUNCATED" else "OBSERVED" if ps_out else "INACCESSIBLE", "items": processes},
        "listeners": {"state": "PARTIAL" if net_err == "OUTPUT_TRUNCATED" else "OBSERVED" if net_out else "INACCESSIBLE", "items": listeners},
        "configuration_files": configuration_files,
        "ownership": "OBSERVED_EXTERNAL", "health": "UNKNOWN",
        "warning": "发现结果仅表示本机快照；不会接管、停止或证明远端连通性。",
    }
