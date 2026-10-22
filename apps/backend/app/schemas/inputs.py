from __future__ import annotations

import ipaddress
import re
from pathlib import PurePath
from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

Mode = Literal["MAC_DIRECT", "CLASH_HTTP", "DISABLED"]
State = Literal["STOPPED", "STARTING", "HEALTHY", "DEGRADED", "RECONNECTING", "FAILED", "AUTH_REQUIRED", "PORT_CONFLICT"]
Management = Literal["MANAGED", "OBSERVED_EXTERNAL"]


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def safe_text(value: str) -> str:
    if not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("A nonempty value without control characters is required")
    return value


class ServerInput(Input):
    name: str = Field(min_length=1, max_length=120)
    host: str = Field(min_length=1, max_length=253)
    ssh_alias: str | None = Field(default=None, max_length=120)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    user: str = Field(min_length=1, max_length=64)
    identity_file_ref: str | None = Field(default=None, max_length=1024)
    group_id: str | None = None
    remote_proxy_port: int = Field(default=17892, ge=1024, le=65535)
    mode: Mode = "MAC_DIRECT"
    proxy_port: int = Field(default=18988, ge=1024, le=65535)
    auto_reconnect: bool = True
    restore_on_login: bool = False
    management: Management = "MANAGED"
    health_url: str = Field(default="https://example.com/", max_length=2048)
    expected_status: list[int] = Field(default_factory=lambda: [200], min_length=1, max_length=20)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return safe_text(value)

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        safe_text(value)
        if value.startswith("-") or any(char.isspace() for char in value):
            raise ValueError("Host cannot be an SSH option or contain whitespace")
        try:
            ipaddress.ip_address(value)
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", value):
                raise ValueError("Host must be a hostname or IP address")
        return value

    @field_validator("user", "ssh_alias")
    @classmethod
    def validate_ssh_atom(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", value):
            raise ValueError("Use a plain SSH user or alias without options or shell syntax")
        return value

    @field_validator("identity_file_ref")
    @classmethod
    def validate_identity(cls, value: str | None) -> str | None:
        if value is not None:
            safe_text(value)
            if not PurePath(value).is_absolute() or ".." in PurePath(value).parts:
                raise ValueError("Identity reference must be an absolute path without traversal")
            if any(char in value for char in ("%", "$", "`")):
                raise ValueError("Identity path expansion is not supported")
        return value

    @field_validator("group_id")
    @classmethod
    def validate_group_id(cls, value: str | None) -> str | None:
        if value is not None:
            UUID(value)
        return value

    @field_validator("health_url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        safe_text(value)
        try:
            parsed = urlsplit(value)
            hostname = parsed.hostname
            _ = parsed.port
        except ValueError as error:
            raise ValueError("Invalid health URL format") from error
        if parsed.scheme not in ("http", "https") or not hostname:
            raise ValueError("Health URL must use HTTP or HTTPS with a host")
        if parsed.username or parsed.password or parsed.fragment or parsed.query:
            raise ValueError("Health URL cannot contain credentials, query secrets, or fragments")
        try:
            _ = parsed.port
        except ValueError as error:
            raise ValueError("Invalid health URL port") from error
        return value

    @field_validator("expected_status")
    @classmethod
    def validate_statuses(cls, value: list[int]) -> list[int]:
        if any(code < 100 or code > 599 for code in value):
            raise ValueError("Expected HTTP statuses must be in 100..599")
        return list(dict.fromkeys(value))


class ServerPatch(Input):
    name: str | None = None
    host: str | None = None
    ssh_alias: str | None = None
    ssh_port: int | None = None
    user: str | None = None
    identity_file_ref: str | None = None
    group_id: str | None = None
    remote_proxy_port: int | None = None
    mode: Mode | None = None
    proxy_port: int | None = None
    auto_reconnect: bool | None = None
    restore_on_login: bool | None = None
    health_url: str | None = None
    expected_status: list[int] | None = None


class GroupInput(Input):
    name: str = Field(min_length=1, max_length=120)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return safe_text(value)


class ModeInput(Input):
    mode: Mode
    proxy_port: int | None = Field(default=None, ge=1024, le=65535)


class SettingsInput(Input):
    theme: Literal["system", "light", "dark"] = "system"
    health_interval_s: float = Field(default=15, ge=2, le=3600)
    connect_timeout_s: float = Field(default=15, ge=1, le=120)
    probe_timeout_s: float = Field(default=15, ge=1, le=120)
    failure_threshold: int = Field(default=3, ge=1, le=20)
    retry_base_s: float = Field(default=5, ge=1, le=300)
    retry_max_s: float = Field(default=300, ge=5, le=3600)
    retry_max_attempts: int = Field(default=10, ge=1, le=100)
    raw_retention_days: int = Field(default=30, ge=1, le=365)
    audit_retention_days: int = Field(default=90, ge=7, le=3650)
    max_concurrent_probes: int = Field(default=4, ge=1, le=32)

    @model_validator(mode="after")
    def validate_retry(self) -> SettingsInput:
        if self.retry_max_s < self.retry_base_s:
            raise ValueError("Maximum retry delay must be at least the base delay")
        return self


class TicketInput(Input):
    ticket: str = Field(min_length=16, max_length=256)


class SSHPreviewInput(Input):
    content: str | None = Field(default=None, max_length=1048576)
    path: str | None = Field(default=None, max_length=1024)

    @model_validator(mode="after")
    def one_source(self) -> SSHPreviewInput:
        if (self.content is None) == (self.path is None):
            raise ValueError("Provide exactly one of content or path")
        return self


class ImportCommitInput(Input):
    indexes: list[int] = Field(min_length=1, max_length=1000)
    expected_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class DiscoveryImportInput(Input):
    """Select read-only discovery candidates to save as STOPPED profiles."""

    indexes: list[int] = Field(min_length=1, max_length=1000)
    discovery_id: str | None = Field(default=None, max_length=128)


class DiagnosticsInput(Input):
    target_url: str = Field(default="https://hubway.cc/v1", max_length=2048)

    @field_validator("target_url")
    @classmethod
    def validate_target(cls, value: str) -> str:
        safe_text(value)
        try:
            parsed = urlsplit(value)
            hostname = parsed.hostname
            port = parsed.port
        except ValueError as error:
            raise ValueError("Diagnostics target has an invalid URL format") from error
        if parsed.scheme != "https" or hostname != "hubway.cc" or port not in (None, 443) or parsed.path.rstrip("/") != "/v1" or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Diagnostics target must be the allowlisted https://hubway.cc/v1 endpoint")
        return value.rstrip("/")


class ConnectionTestInput(Input):
    kind: Literal["connection", "proxy"] = "proxy"


class CodexCredentialCheckInput(Input):
    source: Literal["REMOTE_CODEX_AUTH_JSON"]
    consent: StrictBool


class CodexModelPreviewInput(Input):
    source: Literal["REMOTE_CODEX_AUTH_JSON"]


class CodexModelTestInput(Input):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)
    source: Literal["REMOTE_CODEX_AUTH_JSON"]
    consent: StrictBool
    base_url: StrictStr
    model: StrictStr
    wire_api: Literal["responses", "chat"]
    expected_revision: StrictInt = Field(ge=1)

    @field_validator("base_url")
    @classmethod
    def validate_model_url(cls, value: str) -> str:
        from app.monitoring.codex_model_test import validate_model_base_url
        return validate_model_base_url(value)

    @field_validator("model")
    @classmethod
    def validate_model_name(cls, value: str) -> str:
        from app.monitoring.codex_model_test import validate_model
        return validate_model(value)


class ExportInput(Input):
    include_connection_details: bool = False


class ConfigurationGroup(GroupInput):
    id: str | None = None

    @field_validator("id")
    @classmethod
    def valid_id(cls, value: str | None) -> str | None:
        if value is not None:
            UUID(value)
        return value


class ConfigurationInput(Input):
    schema_version: Literal[1] = 1
    servers: list[ServerInput] = Field(max_length=1000)
    groups: list[ConfigurationGroup] = Field(default_factory=list, max_length=1000)
    settings: SettingsInput | None = None


class MigrationInput(Input):
    server_id: str

    @field_validator("server_id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        UUID(value)
        return value


class ProxyEndpointInput(Input):
    name: str = Field(min_length=1, max_length=120)
    kind: Literal["MANAGED_TINYPROXY", "EXTERNAL_TINYPROXY", "EXTERNAL_HTTP"] = "EXTERNAL_HTTP"
    bind_host: Literal["127.0.0.1", "::1"] = "127.0.0.1"
    port: int = Field(ge=1024, le=65535)
