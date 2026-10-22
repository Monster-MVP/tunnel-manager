"""Exercise the real signed bundle's self-contained project installer helpers."""

from __future__ import annotations

import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]
APP = ROOT / "var/dist/Tunnel Manager.app"
BACKEND = APP / "Contents/Resources/backend/tunnel-backend/tunnel-backend"
TARGET = ROOT / "var/install/Tunnel Manager.app"


def command(*arguments: str) -> str:
    result = subprocess.run([str(BACKEND), *arguments], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def test_real_install_upgrade_rollback_uninstall() -> dict:
    assert not TARGET.exists(), "This isolated installer check requires an absent installed project copy"
    existing = set((ROOT / "var/install").glob("rollback-*"))
    assert command("--package-install") == str(TARGET)
    subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(TARGET)], check=True)
    command("--package-install")
    created = set(TARGET.parent.glob("rollback-*")) - existing
    assert len(created) == 1
    checkpoint = created.pop()
    assert checkpoint.stat().st_mode & 0o777 == 0o700
    assert (checkpoint / "Tunnel Manager.app").is_dir()
    assert command("--package-rollback", str(checkpoint)) == str(TARGET)
    subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(TARGET)], check=True)
    command("--package-uninstall")
    assert not TARGET.exists()
    assert APP.is_dir()
    result = {
        "passed": [
            "self_contained_install",
            "verified_upgrade_checkpoint",
            "signed_app_rollback",
            "owned_uninstall_retains_original_bundle",
        ],
        "checkpoint": str(checkpoint.relative_to(ROOT)),
    }
    (ROOT / "var/reports/macos-installation-smoke.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    print(json.dumps(test_real_install_upgrade_rollback_uninstall()))
