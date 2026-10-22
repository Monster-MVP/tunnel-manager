"""A fixed remote-only credential readability check with a secret-free protocol.

The helper is deliberately self-contained: no auth.json body or key crosses
SSH, and neither a remote path nor an exception is included in its result.
"""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

SOURCE = "REMOTE_CODEX_AUTH_JSON"
SOURCE_LABEL = "远端 Codex auth.json"
MAX_AUTH_BYTES = 65536
REMOTE_PROTOCOL_LIMIT = 512
STATES = frozenset({
    "READABLE", "NOT_FOUND", "UNREADABLE", "TOO_LARGE", "INVALID_JSON", "INVALID_KEY",
    "OAUTH_ONLY", "MISSING_KEY", "REMOTE_TOOL_UNAVAILABLE", "CHECK_UNAVAILABLE",
})
AUTH_MODES = frozenset({"API_KEY", "OAUTH", "UNKNOWN"})
SOURCE_LOCATIONS = frozenset({"CODEX_HOME", "HOME_DEFAULT", "UNKNOWN"})

# No input is interpolated into this script. Only the selected remote user's
# CODEX_HOME and HOME are consulted; credential-bearing environments are not
# enumerated. -I prevents user Python startup/module configuration from loading.
REMOTE_READABILITY_SCRIPT = r'''
import json
import os
import stat
import sys

MAX_BYTES = 65536
location = "UNKNOWN"

def result(state, auth_mode="UNKNOWN", key_readable=None):
    return {"version": 1, "state": state, "auth_mode": auth_mode,
            "source_location": location, "key_readable": key_readable}

def unique_object(pairs):
    value = {}
    for name, item in pairs:
        if name in value:
            raise ValueError("duplicate field")
        value[name] = item
    return value

def reject_constant(value):
    raise ValueError("invalid JSON constant")

def check():
    global location
    codex_home = os.getenv("CODEX_HOME")
    home = os.getenv("HOME")
    if codex_home is not None:
        location = "CODEX_HOME"
        if not os.path.isabs(codex_home):
            return result("UNREADABLE")
        directory = codex_home
    elif home and os.path.isabs(home):
        directory = os.path.join(home, ".codex")
        location = "HOME_DEFAULT"
    else:
        return result("UNREADABLE")
    # Walk using directory file descriptors, so parent or file symlinks cannot
    # redirect this read, including a swap between checking and opening a path.
    parts = directory.split(os.sep)
    if any(part == ".." for part in parts):
        return result("UNREADABLE")
    directory_fd = None
    file_fd = None
    try:
        directory_fd = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for part in parts:
            if part and part != ".":
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                  dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = next_fd
        file_fd = os.open("auth.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                          dir_fd=directory_fd)
        info = os.fstat(file_fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o077
                or not info.st_mode & stat.S_IRUSR):
            return result("UNREADABLE")
        if info.st_size > MAX_BYTES:
            return result("TOO_LARGE")
        content = bytearray()
        while len(content) <= MAX_BYTES:
            chunk = os.read(file_fd, min(4096, MAX_BYTES + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        if len(content) > MAX_BYTES:
            return result("TOO_LARGE")
        after = os.fstat(file_fd)
        if (after.st_size != info.st_size or after.st_mtime_ns != info.st_mtime_ns
                or after.st_mode != info.st_mode):
            return result("UNREADABLE")
    except FileNotFoundError:
        return result("NOT_FOUND", key_readable=False)
    except (OSError, ValueError):
        return result("UNREADABLE")
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if directory_fd is not None:
            os.close(directory_fd)
    try:
        document = json.loads(content.decode("utf-8"), object_pairs_hook=unique_object,
                              parse_constant=reject_constant)
        if not isinstance(document, dict):
            return result("INVALID_JSON")
    except (ValueError, UnicodeError, RecursionError):
        return result("INVALID_JSON")
    mode = document.get("auth_mode")
    api_mode = isinstance(mode, str) and mode.lower() in {"api_key", "apikey"}
    oauth_mode = ((isinstance(mode, str) and mode.lower() in {"oauth", "chatgpt"})
                  or isinstance(document.get("tokens"), dict))
    key = document.get("OPENAI_API_KEY")
    if key is None:
        if oauth_mode:
            return result("OAUTH_ONLY", "OAUTH", False)
        return result("MISSING_KEY", "API_KEY" if api_mode else "UNKNOWN", False)
    if (not isinstance(key, str) or not key or len(key) > 4096
            or any(ord(char) < 33 or ord(char) > 126 for char in key)):
        return result("INVALID_KEY", "API_KEY", False)
    return result("READABLE", "API_KEY", True)

try:
    payload = check()
except Exception:
    payload = result("UNREADABLE")
sys.stdout.write(json.dumps(payload, separators=(",", ":"), ensure_ascii=True) + "\n")
'''.strip()


def build_remote_codex_command() -> str:
    """Use a fixed system interpreter; missing Python is a capability failure."""
    command = "/usr/bin/python3 -I -c " + shlex.quote(REMOTE_READABILITY_SCRIPT)
    return "if [ -x /usr/bin/python3 ]; then " + command + "; else exit 69; fi"


@dataclass(frozen=True)
class CodexCredentialCheck:
    state: str
    auth_mode: str = "UNKNOWN"
    source_location: str = "UNKNOWN"
    key_readable: bool | None = None
    reason_code: str | None = None

    @classmethod
    def unavailable(cls, reason: str) -> CodexCredentialCheck:
        return cls("CHECK_UNAVAILABLE", reason_code=reason)

    @classmethod
    def from_remote(cls, output: bytes, exit_code: int) -> CodexCredentialCheck:
        """Accept an exact, bounded whitelist; never reflect remote output."""
        if exit_code in {69, 127}:
            return cls("REMOTE_TOOL_UNAVAILABLE", reason_code="REMOTE_PYTHON_UNAVAILABLE")
        if exit_code != 0:
            return cls.unavailable("CHECK_TIMEOUT" if exit_code == 124 else "REMOTE_CHECK_FAILED")
        if len(output) > REMOTE_PROTOCOL_LIMIT:
            return cls.unavailable("INVALID_REMOTE_RESULT")
        try:
            def unique_object(pairs):
                value = {}
                for name, item in pairs:
                    if name in value:
                        raise ValueError("duplicate field")
                    value[name] = item
                return value

            value = json.loads(output.decode("ascii"), object_pairs_hook=unique_object)
            if (not isinstance(value, dict)
                    or set(value) != {"version", "state", "auth_mode", "source_location", "key_readable"}
                    or type(value["version"]) is not int or value["version"] != 1
                    or not isinstance(value["state"], str) or value["state"] not in STATES
                    or value["state"] in {"CHECK_UNAVAILABLE", "REMOTE_TOOL_UNAVAILABLE"}
                    or not isinstance(value["auth_mode"], str) or value["auth_mode"] not in AUTH_MODES
                    or not isinstance(value["source_location"], str) or value["source_location"] not in SOURCE_LOCATIONS
                    or (value["key_readable"] is not None and type(value["key_readable"]) is not bool)):
                raise ValueError("invalid protocol")
            state, mode, readable = value["state"], value["auth_mode"], value["key_readable"]
            expected_readable = True if state == "READABLE" else False if state in {
                "NOT_FOUND", "INVALID_KEY", "OAUTH_ONLY", "MISSING_KEY"} else None
            if readable is not expected_readable:
                raise ValueError("inconsistent protocol")
            if ((state in {"READABLE", "INVALID_KEY"} and mode != "API_KEY")
                    or (state == "OAUTH_ONLY" and mode != "OAUTH")
                    or (state in {"NOT_FOUND", "UNREADABLE", "TOO_LARGE", "INVALID_JSON"} and mode != "UNKNOWN")):
                raise ValueError("inconsistent protocol")
            return cls(state, mode, value["source_location"], readable)
        except (ValueError, UnicodeError, RecursionError, KeyError, TypeError):
            return cls.unavailable("INVALID_REMOTE_RESULT")

    def as_dict(self) -> dict[str, Any]:
        return {"source": SOURCE, "source_label": SOURCE_LABEL,
                "credential_state": self.state, "auth_mode": self.auth_mode,
                "source_location": self.source_location, "key_readable": self.key_readable,
                "check_completed": self.state not in {"REMOTE_TOOL_UNAVAILABLE", "CHECK_UNAVAILABLE"},
                "reason_code": self.reason_code, "authentication": "NOT_TESTED",
                "model_completion": "NOT_TESTED", "llm_completion_verified": False}


def safe_api_result(value: dict[str, Any], server_id: str) -> dict[str, Any]:
    """Rebuild the response from status enums, even if an engine is faulty."""
    if not isinstance(value, dict):
        raise TypeError("invalid credential result")
    state = value.get("credential_state")
    if not isinstance(state, str) or state not in STATES:
        raise ValueError("invalid credential result")
    if state in {"CHECK_UNAVAILABLE", "REMOTE_TOOL_UNAVAILABLE"}:
        reason = value.get("reason_code")
        allowed_reasons = {"CONNECTION_REQUIRED", "CONNECTION_CHANGED", "REMOTE_CHECK_FAILED",
                           "CHECK_TIMEOUT", "INVALID_REMOTE_RESULT", "REMOTE_PYTHON_UNAVAILABLE"}
        if (not isinstance(reason, str) or reason not in allowed_reasons
                or value.get("key_readable") is not None
                or value.get("auth_mode") != "UNKNOWN" or value.get("source_location") != "UNKNOWN"
                or (state == "REMOTE_TOOL_UNAVAILABLE" and reason != "REMOTE_PYTHON_UNAVAILABLE")):
            raise ValueError("invalid credential result")
        check = CodexCredentialCheck(state, reason_code=reason)
    else:
        protocol = {"version": 1, "state": state, "auth_mode": value.get("auth_mode"),
                    "source_location": value.get("source_location"), "key_readable": value.get("key_readable")}
        check = CodexCredentialCheck.from_remote(json.dumps(protocol).encode("ascii"), 0)
        if check.state != state or value.get("reason_code") is not None:
            raise ValueError("invalid credential result")
    observed = value.get("observed_at")
    if not isinstance(observed, str) or not 20 <= len(observed) <= 40:
        raise ValueError("invalid credential result")
    timestamp = datetime.fromisoformat(observed)
    if timestamp.tzinfo is None or type(value.get("ssh_connected")) is not bool:
        raise ValueError("invalid credential result")
    if state == "READABLE" and value["ssh_connected"] is not True:
        raise ValueError("invalid credential result")
    return {"server_id": server_id, "ownership": "MANAGED", "ssh_connected": value["ssh_connected"],
            "observed_at": timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z"), **check.as_dict()}
