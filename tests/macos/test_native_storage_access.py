"""Invalid storage capability input must not create a background service."""

from __future__ import annotations

import pathlib
import subprocess
import uuid

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
EXECUTABLE = ROOT / "var/dist/Tunnel Manager.app/Contents/MacOS/TunnelManager"


@pytest.mark.parametrize("bookmark", [b"", b"invalid bookmark", b"x" * 65537])
def test_invalid_native_storage_capability_fails_before_runtime_writes(bookmark):
    if not EXECUTABLE.is_file():
        pytest.skip("Native application has not been built")
    runtime = ROOT / ".run" / ("bad-" + uuid.uuid4().hex[:6])
    data = ROOT / "var/tmp" / ("bad-bookmark-" + uuid.uuid4().hex[:6])
    result = subprocess.run(
        [
            str(EXECUTABLE),
            "--service-host",
            "--storage-access-stdin",
            "--runtime-dir",
            str(runtime),
            "--data-dir",
            str(data),
        ],
        input=bookmark,
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 78
    assert not runtime.exists()
    assert not data.exists()
