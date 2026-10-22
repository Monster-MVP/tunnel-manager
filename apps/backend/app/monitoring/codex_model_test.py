"""Explicit, one-shot model testing; secrets and provider output stay remote.

Only fixed enums cross SSH. The selected key is used in a verified TLS request
through the existing reverse proxy, after the user reviews its HTTPS recipient.
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from app.monitoring.codex_credentials import REMOTE_READABILITY_SCRIPT, SOURCE

CONFIG_STATES = frozenset({"READY", "NOT_FOUND", "UNREADABLE", "INVALID_CONFIG", "UNSUPPORTED_PROVIDER",
                           "REMOTE_TOOL_UNAVAILABLE", "CHECK_UNAVAILABLE"})
MODEL_STATES = frozenset({"SUCCESS", "AUTH_REJECTED", "PERMISSION_DENIED", "RATE_LIMITED", "MODEL_UNAVAILABLE",
                         "NETWORK_ERROR", "TLS_ERROR", "TIMEOUT", "INVALID_RESPONSE", "EMPTY_OUTPUT", "INCOMPLETE",
                         "CREDENTIAL_UNAVAILABLE", "CHECK_UNAVAILABLE", "UPSTREAM_ERROR"})
CREDENTIAL_STATES = frozenset({"READABLE", "NOT_FOUND", "UNREADABLE", "TOO_LARGE", "INVALID_JSON", "INVALID_KEY",
                              "OAUTH_ONLY", "MISSING_KEY", "NOT_CHECKED"})
REASONS = frozenset({"CONNECTION_REQUIRED", "CONNECTION_CHANGED", "REMOTE_CHECK_FAILED", "CHECK_TIMEOUT",
                    "INVALID_REMOTE_RESULT", "REMOTE_PYTHON_UNAVAILABLE", "DESTINATION_NOT_PUBLIC",
                    "MODEL_TEST_SUCCESS", *MODEL_STATES, *CREDENTIAL_STATES})
PROTOCOL_LIMIT = 1024


def validate_model_base_url(value: str) -> str:
    """Require an explicit public HTTPS origin, with a simple base path."""
    if (not isinstance(value, str) or not 1 <= len(value) <= 512
            or any(not 33 <= ord(char) <= 126 for char in value)):
        raise ValueError("Select a public HTTPS API base URL")
    parsed = urlsplit(value)
    host = parsed.hostname or ""
    labels = host.split(".")
    if (parsed.scheme != "https" or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or parsed.port not in (None, 443)
            or len(labels) < 2 or not re.fullmatch(r"[A-Za-z]{2,63}", labels[-1])
            or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in labels)
            or labels[-1].lower() in {"local", "internal", "localhost", "test", "invalid", "example", "lan", "home", "onion", "localdomain"}
            or not re.fullmatch(r"(?:/[A-Za-z0-9_.-]+)*/?", parsed.path)
            or re.search(r"(?:^|[/_.:-])(?:sk[-_][A-Za-z0-9_-]{16,}|eyJ[A-Za-z0-9_-]{16,})", parsed.path)
            or any(part in {".", ".."} for part in parsed.path.split("/"))):
        raise ValueError("Select a public HTTPS API base URL without credentials, query, or fragments")
    return "https://" + host.lower() + parsed.path.rstrip("/")


def validate_model(value: str) -> str:
    if (not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,119}", value)
            or re.search(r"(?:^|[/_.:-])(?:sk[-_][A-Za-z0-9_-]{16,}|eyJ[A-Za-z0-9_-]{16,})", value)):
        raise ValueError("Use a plain model identifier")
    return value


# This helper reads no auth.json. Its deliberately narrow TOML reader accepts
# ordinary root strings and provider tables, ignores unrelated values, and
# reports unsupported syntax rather than returning arbitrary config content.
REMOTE_PREVIEW_SCRIPT = r'''
import json
import os
import re
import stat
import sys
from urllib.parse import urlsplit

def result(state, base_url=None, model=None, wire_api=None):
    return {"version":1,"config_state":state,"base_url":base_url,"model":model,"wire_api":wire_api}

def strip_comment(line):
    quote = None
    escape = False
    for index, char in enumerate(line):
        if quote:
            if escape:
                escape = False
            elif char == "\\" and quote == '"':
                escape = True
            elif char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == "#":
            return line[:index].strip()
    return line.strip()

def string(value):
    if value.startswith('"') and value.endswith('"'):
        parsed = json.loads(value)
    elif value.startswith("'") and value.endswith("'") and "'" not in value[1:-1]:
        parsed = value[1:-1]
    else:
        raise ValueError("unsupported string")
    if not isinstance(parsed, str):
        raise ValueError("not a string")
    return parsed

def safe_url(value):
    if not isinstance(value,str) or not 1 <= len(value) <= 512 or any(not 33<=ord(c)<=126 for c in value):
        raise ValueError("invalid URL")
    parsed = urlsplit(value)
    host = parsed.hostname or ""
    labels = host.split(".")
    if (parsed.scheme != "https" or parsed.username is not None or parsed.password is not None
        or parsed.query or parsed.fragment or parsed.port not in (None,443)
        or len(labels)<2 or not re.fullmatch(r"[A-Za-z]{2,63}",labels[-1])
        or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?",part) for part in labels)
        or labels[-1].lower() in {"local","internal","localhost","test","invalid","example","lan","home","onion","localdomain"}
        or not re.fullmatch(r"(?:/[A-Za-z0-9_.-]+)*/?",parsed.path)
        or re.search(r"(?:^|[/_.:-])(?:sk[-_][A-Za-z0-9_-]{16,}|eyJ[A-Za-z0-9_-]{16,})",parsed.path)
        or any(part in {".",".."} for part in parsed.path.split("/"))):
        raise ValueError("invalid URL")
    return "https://" + host.lower() + parsed.path.rstrip("/")

def preview():
    codex_home = os.getenv("CODEX_HOME")
    home = os.getenv("HOME")
    directory = codex_home if codex_home is not None else os.path.join(home,".codex") if home else ""
    if not os.path.isabs(directory) or ".." in directory.split(os.sep):
        return result("UNREADABLE")
    directory_fd = file_fd = None
    try:
        directory_fd = os.open(os.sep,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        for part in directory.split(os.sep):
            if part and part != ".":
                next_fd = os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = next_fd
        file_fd = os.open("config.toml",os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory_fd)
        info = os.fstat(file_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or not info.st_mode & stat.S_IRUSR:
            return result("UNREADABLE")
        if info.st_size > 65536:
            return result("INVALID_CONFIG")
        content = bytearray()
        while len(content)<=65536:
            chunk = os.read(file_fd,min(4096,65537-len(content)))
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(file_fd)
        if len(content)>65536 or after.st_size != info.st_size or after.st_mtime_ns != info.st_mtime_ns or after.st_mode != info.st_mode:
            return result("INVALID_CONFIG")
    except FileNotFoundError:
        return result("NOT_FOUND")
    except (OSError,ValueError):
        return result("UNREADABLE")
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if directory_fd is not None:
            os.close(directory_fd)
    try:
        text = content.decode("utf-8")
        try:
            import tomllib
        except ImportError:
            tomllib = None
        section = ""
        fields = {}
        # tomllib handles every quoting/dotted-key/multiline detail when the
        # remote Python supports it. Profiles require manual selection because
        # this SSH session cannot establish an editor's active CLI profile.
        if tomllib is not None:
            document = tomllib.loads(text)
            if "profile" in document or "profiles" in document:
                return result("UNSUPPORTED_PROVIDER")
            for name in {"model","model_provider"}:
                if name in document:
                    fields[("",name)] = document[name]
            providers = document.get("model_providers",{})
            if not isinstance(providers,dict):
                raise ValueError("invalid providers")
            for name,provider in providers.items():
                if not isinstance(provider,dict):
                    raise ValueError("invalid provider")
                for field in {"base_url","wire_api"}:
                    if field in provider:
                        fields[("[model_providers."+name+"]",field)] = provider[field]
        for raw in text.splitlines() if tomllib is None else []:
            line = strip_comment(raw)
            if not line:
                continue
            if '"' * 3 in line or "'" * 3 in line:
                raise ValueError("unsupported multiline")
            if line.startswith("["):
                if "profile" in line:
                    return result("UNSUPPORTED_PROVIDER")
                if "model_providers" in line and not re.fullmatch(r"\[model_providers\.[A-Za-z0-9_-]+\]",line):
                    raise ValueError("unsupported provider table")
                section = line
                continue
            match = re.fullmatch(r"(model|model_provider|base_url|wire_api)\s*=\s*(.+)",line)
            if not match:
                if re.match(r"[\"']?(?:model|model_provider|model_providers|base_url|wire_api|profile|profiles)(?:[\"'\s.=]|$)",line):
                    raise ValueError("unsupported relevant syntax")
                continue
            name,value = match.groups()
            if ((not section and name in {"model","model_provider"}) or
                (re.fullmatch(r"\[model_providers\.[A-Za-z0-9_-]+\]",section) and name in {"base_url","wire_api"})):
                key = (section,name)
                if key in fields:
                    raise ValueError("duplicate field")
                fields[key] = string(value)
        provider = fields.get(("","model_provider"),"openai")
        if not isinstance(provider,str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}",provider):
            raise ValueError("invalid provider")
        model = fields.get(("","model"))
        if model is not None and (not isinstance(model,str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,119}",model)
                                 or re.search(r"(?:^|[/_.:-])(?:sk[-_][A-Za-z0-9_-]{16,}|eyJ[A-Za-z0-9_-]{16,})",model)):
            raise ValueError("invalid model")
        table = "[model_providers."+provider+"]"
        base_url = fields.get((table,"base_url"),"https://api.openai.com/v1" if provider == "openai" else None)
        wire_api = fields.get((table,"wire_api"),"responses")
        if base_url is None or not isinstance(wire_api,str) or wire_api not in {"responses","chat"}:
            return result("UNSUPPORTED_PROVIDER")
        base_url = safe_url(base_url)
        return result("READY",base_url,model,wire_api)
    except (ValueError,UnicodeError,RecursionError,TypeError):
        return result("INVALID_CONFIG")

try:
    payload = preview()
except Exception:
    payload = result("UNREADABLE")
sys.stdout.write(json.dumps(payload,separators=(",",":"),ensure_ascii=True)+"\n")
'''.strip()

# Reuse the reviewed fd-based reader, but retain its validated key only in this
# remote process. The previous readability protocol and endpoint stay intact.
_READER_PREFIX = REMOTE_READABILITY_SCRIPT.split("\ntry:\n    payload = check()", 1)[0]
_READER_PREFIX = _READER_PREFIX.replace('return result("READABLE", "API_KEY", True)',
                                      'return result("READABLE", "API_KEY", True), key')

REMOTE_MODEL_SCRIPT = _READER_PREFIX + r'''

import http.client
import ipaddress
import math
import re
import signal
import socket
import ssl
import time
from urllib.parse import urlsplit

def model_result(state,credential_state="NOT_CHECKED",http_status=None,total_ms=None,reason_code=None):
    return {"version":1,"state":state,"credential_state":credential_state,
            "http_status":http_status,"total_ms":total_ms,"reason_code":reason_code or state}

def valid_atom(value):
    return isinstance(value,str) and 1<=len(value)<=200 and value.isascii() and all(33<=ord(c)<=126 for c in value)

def completion(document,wire_api):
    if not isinstance(document,dict) or not valid_atom(document.get("id")) or not valid_atom(document.get("model")):
        return "INVALID_RESPONSE"
    if "error" in document:
        return "INVALID_RESPONSE"
    if wire_api == "responses":
        if document.get("object") != "response":
            return "INVALID_RESPONSE"
        if document.get("status") in {"incomplete","in_progress","queued","cancelled"}:
            return "INCOMPLETE"
        if document.get("status") != "completed" or document.get("incomplete_details"):
            return "INVALID_RESPONSE"
        output = document.get("output")
        if not isinstance(output,list):
            return "INVALID_RESPONSE"
        text = []
        for item in output:
            if not isinstance(item,dict):
                return "INVALID_RESPONSE"
            if item.get("type") == "message" and item.get("role") == "assistant":
                if item.get("status") not in {None,"completed"}:
                    return "INCOMPLETE"
                content = item.get("content")
                if not isinstance(content,list):
                    return "INVALID_RESPONSE"
                for part in content:
                    if isinstance(part,dict) and part.get("type") == "output_text":
                        if not isinstance(part.get("text"),str):
                            return "INVALID_RESPONSE"
                        text.append(part["text"])
        return "SUCCESS" if any(value.strip() for value in text) else "EMPTY_OUTPUT"
    if document.get("object") != "chat.completion":
        return "INVALID_RESPONSE"
    choices = document.get("choices")
    if not isinstance(choices,list) or len(choices)!=1 or not isinstance(choices[0],dict):
        return "INVALID_RESPONSE"
    choice = choices[0]
    if choice.get("finish_reason") in {"length","content_filter","tool_calls","function_call"}:
        return "INCOMPLETE"
    if choice.get("finish_reason") != "stop":
        return "INVALID_RESPONSE"
    message = choice.get("message")
    if not isinstance(message,dict) or message.get("role") != "assistant" or message.get("tool_calls"):
        return "INVALID_RESPONSE"
    text = message.get("content")
    if not isinstance(text,str):
        return "INVALID_RESPONSE"
    return "SUCCESS" if text.strip() else "EMPTY_OUTPUT"

class PinnedTLSProxyConnection(http.client.HTTPConnection):
    def __init__(self,proxy_port,target_host,target_ip,context):
        super().__init__("127.0.0.1",proxy_port,timeout=10)
        self.target_host = target_host
        self.context = context
        self.set_tunnel(target_ip,443)
    def _tunnel(self):
        # Python <3.12 did not bracket IPv6 CONNECT authorities. Build this
        # tiny fixed handshake ourselves, without proxy-auth/custom headers.
        host = self._tunnel_host
        authority = ("["+host+"]" if ":" in host else host)+":443"
        self.send(("CONNECT "+authority+" HTTP/1.1\r\nHost: "+authority+"\r\n\r\n").encode("ascii"))
        response = self.response_class(self.sock,method="CONNECT")
        try:
            version,code,message = response._read_status()
            if code != 200:
                raise OSError("proxy CONNECT failed")
            for count in range(101):
                line = response.fp.readline(65537)
                if len(line)>65536 or count == 100:
                    raise OSError("proxy headers too large")
                if line in (b"\r\n",b"\n"):
                    break
                if not line:
                    raise OSError("proxy headers incomplete")
        finally:
            response.close()
    def connect(self):
        super().connect()
        self.sock = self.context.wrap_socket(self.sock,server_hostname=self.target_host)

def run_model_test(request):
    started = time.monotonic()
    status = None
    credential_state = "NOT_CHECKED"
    connection = None
    def done(state,reason=None):
        return model_result(state,credential_state,status,round((time.monotonic()-started)*1000,3),reason)
    try:
        base_url = request["base_url"]
        model = request["model"]
        wire_api = request["wire_api"]
        proxy_port = request["remote_proxy_port"]
        parsed = urlsplit(base_url)
        host = parsed.hostname or ""
        labels = host.split(".")
        if (not isinstance(base_url,str) or not 1<=len(base_url)<=512 or any(not 33<=ord(c)<=126 for c in base_url)
            or parsed.scheme != "https" or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or parsed.port not in (None,443)
            or len(labels)<2 or not re.fullmatch(r"[A-Za-z]{2,63}",labels[-1])
            or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?",p) for p in labels)
            or labels[-1].lower() in {"local","internal","localhost","test","invalid","example","lan","home","onion","localdomain"}
            or not re.fullmatch(r"(?:/[A-Za-z0-9_.-]+)*/?",parsed.path)
            or re.search(r"(?:^|[/_.:-])(?:sk[-_][A-Za-z0-9_-]{16,}|eyJ[A-Za-z0-9_-]{16,})",parsed.path)
            or any(p in {".",".."} for p in parsed.path.split("/"))
            or not isinstance(model,str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,119}",model)
            or re.search(r"(?:^|[/_.:-])(?:sk[-_][A-Za-z0-9_-]{16,}|eyJ[A-Za-z0-9_-]{16,})",model)
            or wire_api not in {"responses","chat"} or type(proxy_port) is not int or not 1024<=proxy_port<=65535):
            return done("CHECK_UNAVAILABLE","INVALID_REMOTE_RESULT")
        # Resolve before opening auth.json. Reject every private/mixed answer;
        # CONNECT a pinned public IP and validate TLS against the reviewed host.
        addresses = list(dict.fromkeys(item[4][0] for item in socket.getaddrinfo(host,443,type=socket.SOCK_STREAM)))
        if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
            return done("CHECK_UNAVAILABLE","DESTINATION_NOT_PUBLIC")
        checked = check()
        if not isinstance(checked,tuple):
            credential_state = checked["state"]
            return done("CREDENTIAL_UNAVAILABLE",credential_state)
        metadata,key = checked
        credential_state = metadata["state"]
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        connection = PinnedTLSProxyConnection(proxy_port,host,addresses[0],context)
        if wire_api == "responses":
            body = {"model":model,"input":"Reply with OK only.","stream":False,"store":False,"max_output_tokens":128}
            endpoint = "/responses"
        else:
            body = {"model":model,"messages":[{"role":"user","content":"Reply with OK only."}],
                    "stream":False,"max_completion_tokens":128}
            endpoint = "/chat/completions"
        connection.request("POST",parsed.path.rstrip("/")+endpoint,
                           body=json.dumps(body,separators=(",",":")),
                           headers={"Host":host,"Authorization":"Bearer "+key,
                                    "Content-Type":"application/json","Accept":"application/json","Accept-Encoding":"identity"})
        response = connection.getresponse()
        status = response.status
        if status == 401:
            return done("AUTH_REJECTED")
        if status == 403:
            return done("PERMISSION_DENIED")
        if status == 429:
            return done("RATE_LIMITED")
        if 300<=status<400:
            return done("UPSTREAM_ERROR")
        if response.getheader("Content-Encoding","").lower() not in {"","identity"}:
            return done("INVALID_RESPONSE")
        content_type = response.getheader("Content-Type","").split(";",1)[0].strip().lower()
        if content_type != "application/json":
            return done("INVALID_RESPONSE" if status == 200 else "UPSTREAM_ERROR")
        output = response.read(131073)
        if len(output)>131072:
            return done("INVALID_RESPONSE")
        try:
            document = json.loads(output.decode("utf-8"),object_pairs_hook=unique_object,parse_constant=reject_constant)
        except (ValueError,UnicodeError,RecursionError):
            return done("INVALID_RESPONSE")
        if status != 200:
            error = document.get("error") if isinstance(document,dict) else None
            code = error.get("code") if isinstance(error,dict) else None
            return done("MODEL_UNAVAILABLE" if code in {"model_not_found","model_not_supported"} else "UPSTREAM_ERROR")
        return done(completion(document,wire_api))
    except ssl.SSLError:
        return done("TLS_ERROR")
    except (TimeoutError,socket.timeout):
        return done("TIMEOUT")
    except (OSError,http.client.HTTPException):
        return done("NETWORK_ERROR")
    except Exception:
        return done("CHECK_UNAVAILABLE","REMOTE_CHECK_FAILED")
    finally:
        if connection is not None:
            connection.close()

def deadline(signum,frame):
    raise TimeoutError("deadline")

signal.signal(signal.SIGALRM,deadline)
signal.alarm(20)
try:
    payload = run_model_test(REQUEST)
except Exception:
    payload = model_result("CHECK_UNAVAILABLE",reason_code="REMOTE_CHECK_FAILED")
finally:
    signal.alarm(0)
sys.stdout.write(json.dumps(payload,separators=(",",":"),ensure_ascii=True)+"\n")
'''


def _command(script: str) -> str:
    return "if [ -x /usr/bin/python3 ]; then /usr/bin/python3 -I -c " + shlex.quote(script) + "; else exit 69; fi"


def build_remote_model_preview_command() -> str:
    return _command(REMOTE_PREVIEW_SCRIPT)


def build_remote_model_test_command(base_url: str, model: str, wire_api: str, remote_proxy_port: int) -> str:
    base_url, model = validate_model_base_url(base_url), validate_model(model)
    if wire_api not in {"responses", "chat"} or type(remote_proxy_port) is not int or not 1024 <= remote_proxy_port <= 65535:
        raise ValueError("Invalid model test parameters")
    request = {"base_url": base_url, "model": model, "wire_api": wire_api, "remote_proxy_port": remote_proxy_port}
    return _command("REQUEST = " + repr(request) + "\n" + REMOTE_MODEL_SCRIPT)


def _decode(output: bytes) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate field")
            result[key] = value
        return result
    if len(output) > PROTOCOL_LIMIT:
        raise ValueError("oversized protocol")
    value = json.loads(output.decode("ascii"), object_pairs_hook=unique)
    if not isinstance(value, dict) or type(value.get("version")) is not int or value["version"] != 1:
        raise ValueError("invalid protocol")
    return value


@dataclass(frozen=True)
class ModelPreview:
    config_state: str
    base_url: str | None = None
    model: str | None = None
    wire_api: str | None = None
    reason_code: str | None = None

    @classmethod
    def unavailable(cls, reason: str) -> ModelPreview:
        return cls("CHECK_UNAVAILABLE", reason_code=reason)

    @classmethod
    def from_remote(cls, output: bytes, exit_code: int) -> ModelPreview:
        if exit_code in {69, 127}:
            return cls("REMOTE_TOOL_UNAVAILABLE", reason_code="REMOTE_PYTHON_UNAVAILABLE")
        if exit_code:
            return cls.unavailable("CHECK_TIMEOUT" if exit_code == 124 else "REMOTE_CHECK_FAILED")
        try:
            value = _decode(output)
            state = value.get("config_state")
            if set(value) != {"version", "config_state", "base_url", "model", "wire_api"} or state not in CONFIG_STATES - {"REMOTE_TOOL_UNAVAILABLE", "CHECK_UNAVAILABLE"}:
                raise ValueError("invalid protocol")
            if state == "READY":
                base_url = validate_model_base_url(value["base_url"])
                model = validate_model(value["model"]) if value["model"] is not None else None
                if value["wire_api"] not in {"responses", "chat"}:
                    raise ValueError("invalid protocol")
                return cls(state, base_url, model, value["wire_api"])
            if any(value[field] is not None for field in ("base_url", "model", "wire_api")):
                raise ValueError("invalid protocol")
            return cls(state)
        except (ValueError, UnicodeError, RecursionError, KeyError, TypeError):
            return cls.unavailable("INVALID_REMOTE_RESULT")

    def as_dict(self) -> dict:
        return {"source": SOURCE, "config_state": self.config_state, "base_url": self.base_url,
                "model": self.model, "wire_api": self.wire_api, "reason_code": self.reason_code}


@dataclass(frozen=True)
class ModelTestResult:
    state: str
    credential_state: str = "NOT_CHECKED"
    http_status: int | None = None
    total_ms: float | None = None
    reason_code: str | None = None

    @classmethod
    def unavailable(cls, reason: str) -> ModelTestResult:
        return cls("CHECK_UNAVAILABLE", reason_code=reason)

    @classmethod
    def from_remote(cls, output: bytes, exit_code: int) -> ModelTestResult:
        if exit_code in {69, 127}:
            return cls.unavailable("REMOTE_PYTHON_UNAVAILABLE")
        if exit_code:
            return cls.unavailable("CHECK_TIMEOUT" if exit_code == 124 else "REMOTE_CHECK_FAILED")
        try:
            import math
            value = _decode(output)
            if (set(value) != {"version", "state", "credential_state", "http_status", "total_ms", "reason_code"}
                    or value["state"] not in MODEL_STATES or value["credential_state"] not in CREDENTIAL_STATES
                    or value["reason_code"] not in REASONS):
                raise ValueError("invalid protocol")
            status, elapsed, state, credential = value["http_status"], value["total_ms"], value["state"], value["credential_state"]
            if (status is not None and (type(status) is not int or not 100 <= status <= 599)
                    or elapsed is not None and (type(elapsed) not in {int, float} or not math.isfinite(elapsed) or not 0 <= elapsed <= 30000)):
                raise ValueError("invalid protocol")
            expected_reason = credential if state == "CREDENTIAL_UNAVAILABLE" else state
            if (state != "CHECK_UNAVAILABLE" and value["reason_code"] != expected_reason
                    or state == "CHECK_UNAVAILABLE" and value["reason_code"] not in {
                        "CONNECTION_REQUIRED", "CONNECTION_CHANGED", "REMOTE_CHECK_FAILED", "CHECK_TIMEOUT",
                        "INVALID_REMOTE_RESULT", "REMOTE_PYTHON_UNAVAILABLE", "DESTINATION_NOT_PUBLIC"}):
                raise ValueError("inconsistent reason")
            if ((state == "SUCCESS" and (status != 200 or credential != "READABLE" or elapsed is None))
                    or (state == "AUTH_REJECTED" and (status != 401 or credential != "READABLE"))
                    or (state == "PERMISSION_DENIED" and status != 403)
                    or (state == "RATE_LIMITED" and status != 429)
                    or (state == "CREDENTIAL_UNAVAILABLE" and (status is not None or credential in {"READABLE", "NOT_CHECKED"}))
                    or (status is not None and credential != "READABLE")
                    or (state in {"SUCCESS", "AUTH_REJECTED", "PERMISSION_DENIED", "RATE_LIMITED", "MODEL_UNAVAILABLE",
                                  "INVALID_RESPONSE", "EMPTY_OUTPUT", "INCOMPLETE", "UPSTREAM_ERROR"} and status is None)):
                raise ValueError("inconsistent protocol")
            return cls(state, credential, status, elapsed, value["reason_code"])
        except (ValueError, UnicodeError, RecursionError, KeyError, TypeError):
            return cls.unavailable("INVALID_REMOTE_RESULT")

    def as_dict(self) -> dict:
        return {"source": SOURCE, "state": self.state, "credential_state": self.credential_state,
                "http_status": self.http_status, "total_ms": self.total_ms, "reason_code": self.reason_code,
                "authentication": "VERIFIED" if self.state == "SUCCESS" else "REJECTED" if self.state == "AUTH_REJECTED" else "NOT_TESTED" if self.credential_state != "READABLE" else "UNKNOWN",
                "model_completion": "SUCCEEDED" if self.state == "SUCCESS" else "NOT_TESTED" if self.credential_state != "READABLE" else "FAILED",
                "llm_completion_verified": self.state == "SUCCESS"}


def _safe_envelope(value: dict, server_id: str) -> dict:
    observed = value.get("observed_at")
    if not isinstance(observed, str) or not 20 <= len(observed) <= 40 or type(value.get("ssh_connected")) is not bool:
        raise ValueError("invalid envelope")
    timestamp = datetime.fromisoformat(observed)
    if timestamp.tzinfo is None:
        raise ValueError("invalid timestamp")
    return {"server_id": server_id, "ownership": "MANAGED", "ssh_connected": value["ssh_connected"],
            "observed_at": timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z")}


def safe_model_preview_result(value: dict[str, Any], server_id: str) -> dict:
    state = value.get("config_state")
    if state in {"CHECK_UNAVAILABLE", "REMOTE_TOOL_UNAVAILABLE"}:
        reason = value.get("reason_code")
        if reason not in {"CONNECTION_REQUIRED", "CONNECTION_CHANGED", "REMOTE_CHECK_FAILED", "CHECK_TIMEOUT", "INVALID_REMOTE_RESULT", "REMOTE_PYTHON_UNAVAILABLE"}:
            raise ValueError("invalid preview reason")
        if state == "REMOTE_TOOL_UNAVAILABLE" and reason != "REMOTE_PYTHON_UNAVAILABLE":
            raise ValueError("invalid preview reason")
        if any(value.get(field) is not None for field in ("base_url", "model", "wire_api")):
            raise ValueError("invalid preview")
        preview = ModelPreview(state, reason_code=reason)
    else:
        preview = ModelPreview.from_remote(json.dumps({"version": 1, **{field: value.get(field) for field in ("config_state", "base_url", "model", "wire_api")}}).encode(), 0)
        if preview.config_state != state or value.get("reason_code") is not None:
            raise ValueError("invalid preview")
    if type(value.get("profile_revision")) is not int or value["profile_revision"] < 1:
        raise ValueError("invalid revision")
    if preview.config_state == "READY" and value["ssh_connected"] is not True:
        raise ValueError("invalid connection")
    return {**_safe_envelope(value, server_id), "profile_revision": value["profile_revision"], **preview.as_dict()}


def safe_model_api_result(value: dict[str, Any], server_id: str) -> dict:
    fields = ("state", "credential_state", "http_status", "total_ms", "reason_code")
    result = ModelTestResult.from_remote(json.dumps({"version": 1, **{field: value.get(field) for field in fields}}).encode(), 0)
    if result.state != value.get("state") or result.reason_code != value.get("reason_code"):
        raise ValueError("invalid model result")
    if result.state == "SUCCESS" and value["ssh_connected"] is not True:
        raise ValueError("invalid model connection")
    return {**_safe_envelope(value, server_id), **result.as_dict()}
