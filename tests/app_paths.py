"""Explicit project-bounded app selection for isolated frozen-bundle tests."""

from __future__ import annotations

import os
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]


def app_bundle_path() -> Path:
    override = os.environ.get("TUNNEL_MANAGER_TEST_APP")
    if override is None:
        # Preserve the historical default, including each test's existing
        # missing-bundle assertion or skip behavior.
        return PROJECT / "var/dist/Tunnel Manager.app"
    path = Path(override)
    if not path.is_absolute():
        path = PROJECT / path
    try:
        selected = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ValueError("Test app override must select an existing project-local .app directory") from error
    if not selected.is_relative_to(PROJECT) or selected.suffix != ".app" or not selected.is_dir():
        raise ValueError("Test app override must select an existing project-local .app directory")
    return selected
