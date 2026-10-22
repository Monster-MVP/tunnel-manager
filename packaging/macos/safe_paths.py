"""Fail closed before writing or deleting project-owned packaging paths."""

from __future__ import annotations

import json
import os
import pathlib
import plistlib
import shutil
import subprocess
import sys

if getattr(sys, "frozen", False):
    storage = pathlib.Path(sys.executable).absolute().parents[2] / "storage.json"
    ROOT = pathlib.Path(json.loads(storage.read_text())["project_root"]).absolute()
else:
    ROOT = pathlib.Path(__file__).absolute().parents[2]
OWNED_PREFIXES = (
    ROOT / "var/build",
    ROOT / "var/dist",
    ROOT / "var/install",
    ROOT / "var/cache",
    ROOT / "var/tmp",
)


def check_path(value: str | pathlib.Path) -> pathlib.Path:
    path = pathlib.Path(value).absolute()
    if not any(path == prefix or prefix in path.parents for prefix in OWNED_PREFIXES):
        raise ValueError("Packaging path is outside project-owned directories")
    if path.resolve() != path:
        raise ValueError("Packaging path contains a symbolic link")
    for component in (path, *path.parents):
        if component.is_symlink():
            raise ValueError("Packaging path contains a symbolic link")
        if component.exists() and component.stat().st_uid != os.getuid():
            raise ValueError("Packaging path is not owned by the current user")
        if component == ROOT:
            break
    return path


def verify_app(path: pathlib.Path, *, signature: bool = True) -> None:
    check_path(path)
    info_path = path / "Contents/Info.plist"
    if (
        info_path.is_symlink()
        or (path / "Contents").is_symlink()
        or (path / "Contents/Resources").is_symlink()
    ):
        raise ValueError("Application metadata contains a symbolic link")
    with info_path.open("rb") as stream:
        if plistlib.load(stream).get("CFBundleIdentifier") != "com.tunnelmanager.app":
            raise ValueError("Refusing an application with an unexpected bundle identifier")
    manifest_path = path / "Contents/Resources/install-manifest.json"
    if manifest_path.is_symlink():
        raise ValueError("Unsafe manifest")
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("owner") != "Tunnel Manager" or manifest.get("project_root") != str(ROOT):
        raise ValueError("Application ownership manifest does not match this project")
    for entry in path.rglob("*"):
        if entry.is_symlink():
            resolved = entry.resolve(strict=True)
            if path not in resolved.parents:
                raise ValueError("Application contains an escaping symbolic link")
        elif entry.stat().st_uid != os.getuid():
            raise ValueError("Application content is owned by another account")
    if signature:
        subprocess.run(
            ["/usr/bin/codesign", "--verify", "--deep", "--strict", str(path)],
            check=True,
            capture_output=True,
        )


def remove(path: pathlib.Path) -> None:
    checked = check_path(path)
    if checked.exists():
        if checked.suffix == ".app":
            verify_app(checked, signature=False)
        if checked.is_dir():
            shutil.rmtree(checked)
        else:
            checked.unlink()


if __name__ == "__main__":
    action, *arguments = sys.argv[1:]
    for argument in arguments:
        checked = check_path(argument)
        if action == "check":
            pass
        elif action == "remove":
            remove(checked)
        elif action == "manifest":
            destination = checked / "Contents/Resources/install-manifest.json"
            if destination.is_symlink() or destination.parent.is_symlink():
                raise ValueError("Unsafe application manifest path")
            destination.write_text(
                json.dumps(
                    {
                        "owner": "Tunnel Manager",
                        "project_root": str(ROOT),
                        "version": "2.0.0",
                        "build": "2",
                        "retained_data": "var/data/app",
                        "service_label": "com.tunnelmanager.service",
                        "distribution": "ad_hoc_local_test",
                        "minimum_macos": "13.0",
                        "tested_macos": "27.0.1",
                        "architecture": "arm64",
                        "runtime": "self_contained_onedir",
                    },
                    indent=2,
                )
                + "\n"
            )
        else:
            raise ValueError("Unknown safe-path action")
