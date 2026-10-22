"""Verified project-local installation, removal and database-matched rollback."""

from __future__ import annotations

import datetime
import json
import os
import pathlib
import shutil
import sqlite3
import subprocess
import time
import uuid

from safe_paths import ROOT, check_path, remove, verify_app


def running(app: pathlib.Path) -> bool:
    return (
        subprocess.run(
            [str(app / "Contents/MacOS/TunnelManager"), "--service-status"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        == 0
    )


def require_unregistered(app: pathlib.Path) -> None:
    result = subprocess.run(
        [str(app / "Contents/MacOS/TunnelManager"), "--login-status"],
        capture_output=True,
        text=True,
        check=True,
    )
    status = json.loads(result.stdout).get("status")
    if status == "not_found":
        # A never-opened local test bundle may not yet be known to ServiceManagement.
        # Accept only launchd's specific "service missing" result in the existing GUI domain.
        observation = subprocess.run(
            ["/bin/launchctl", "print", f"gui/{os.getuid()}/com.tunnelmanager.service"],
            capture_output=True,
            text=True,
            check=False,
        )
        if (
            observation.returncode == 113
            and 'Could not find service "com.tunnelmanager.service"' in observation.stderr
        ):
            return
    if status != "not_registered":
        raise ValueError(
            "Disable Tunnel Manager's own login item in its menu before changing the installed copy"
        )


def checked_database(path: pathlib.Path) -> pathlib.Path:
    expected = ROOT / "var/data/app"
    if path.parent != expected or path.resolve() != path or path.is_symlink():
        raise ValueError("Database path contains a symbolic link or is outside app data")
    for parent in path.parents:
        if parent.is_symlink():
            raise ValueError("Database path contains a symbolic link")
        if parent == ROOT:
            break
    return path


def sqlite_backup(checkpoint: pathlib.Path) -> None:
    database = checked_database(ROOT / "var/data/app/tunnel-manager.sqlite3")
    if database.exists():
        destination = checkpoint / "database.sqlite3"
        descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.close(descriptor)
        with (
            sqlite3.connect(f"file:{database}?mode=ro", uri=True) as source,
            sqlite3.connect(destination) as target,
        ):
            source.backup(target)


def install() -> pathlib.Path:
    source = check_path(ROOT / "var/dist/Tunnel Manager.app")
    target = check_path(ROOT / "var/install/Tunnel Manager.app")
    verify_app(source)
    require_unregistered(source)
    if target.exists():
        verify_app(target)
        require_unregistered(target)
    if running(source) or (target.exists() and running(target)):
        raise ValueError("Stop the app-owned background service before installing or upgrading")
    check_path(target.parent)
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = check_path(target.parent / f"staging-{uuid.uuid4().hex}.app")
    shutil.copytree(source, staging, symlinks=True)
    verify_app(staging)
    checkpoint = None
    if target.exists():
        checkpoint = check_path(
            target.parent
            / (
                "rollback-"
                + datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
                + "-"
                + uuid.uuid4().hex[:6]
            )
        )
        checkpoint.mkdir(mode=0o700)
        sqlite_backup(checkpoint)
        target.rename(checkpoint / "Tunnel Manager.app")
        (checkpoint / "checkpoint.json").write_text(
            json.dumps(
                {
                    "owner": "Tunnel Manager",
                    "project_root": str(ROOT),
                    "database_backup": (checkpoint / "database.sqlite3").exists(),
                },
                indent=2,
            )
            + "\n"
        )
    try:
        staging.rename(target)
    except BaseException:
        if checkpoint is not None:
            (checkpoint / "Tunnel Manager.app").rename(target)
        raise
    return target


def restore_database(backup: pathlib.Path) -> pathlib.Path:
    """Move the old main/WAL/SHM together, then restore a verified standalone backup."""
    check_path(backup)
    if backup.is_symlink() or backup.resolve() != backup:
        raise ValueError("Unsafe database backup path")
    with sqlite3.connect(f"file:{backup}?mode=ro", uri=True) as source:
        if source.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("Database backup failed integrity check")
    database = checked_database(ROOT / "var/data/app/tunnel-manager.sqlite3")
    sidecars = [checked_database(pathlib.Path(str(database) + suffix)) for suffix in ("-wal", "-shm")]
    database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging = checked_database(database.parent / f"restore-{uuid.uuid4().hex}.sqlite3")
    descriptor = os.open(staging, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    os.close(descriptor)
    shutil.copyfile(backup, staging)
    recovery = database.parent / f"pre-rollback-{uuid.uuid4().hex}"
    recovery.mkdir(mode=0o700)
    moved = []
    try:
        for existing in [database, *sidecars]:
            if existing.exists():
                existing.rename(recovery / existing.name)
                moved.append(existing)
        staging.rename(database)
    except BaseException:
        for original in moved:
            (recovery / original.name).rename(original)
        staging.unlink(missing_ok=True)
        raise
    return recovery


def rollback(value: str) -> pathlib.Path:
    checkpoint = check_path(pathlib.Path(value))
    metadata_path = check_path(checkpoint / "checkpoint.json")
    metadata = json.loads(metadata_path.read_text())
    if metadata.get("owner") != "Tunnel Manager" or metadata.get("project_root") != str(ROOT):
        raise ValueError("Unknown rollback checkpoint")
    source = checkpoint / "Tunnel Manager.app"
    target = check_path(ROOT / "var/install/Tunnel Manager.app")
    verify_app(source)
    require_unregistered(source)
    if target.exists():
        verify_app(target)
        require_unregistered(target)
    if running(source) or (target.exists() and running(target)):
        raise ValueError("Stop the app-owned background service before rollback")
    backup = check_path(checkpoint / "database.sqlite3")
    if metadata.get("database_backup"):
        with sqlite3.connect(f"file:{backup}?mode=ro", uri=True) as connection:
            if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise ValueError("Database backup failed integrity check")
    staging = check_path(target.parent / f"rollback-stage-{uuid.uuid4().hex}.app")
    shutil.copytree(source, staging, symlinks=True)
    verify_app(staging)
    previous = check_path(target.parent / f"pre-rollback-{uuid.uuid4().hex}.app")
    if target.exists():
        target.rename(previous)
    try:
        if metadata.get("database_backup"):
            restore_database(backup)
        staging.rename(target)
    except BaseException:
        if previous.exists():
            previous.rename(target)
        raise
    return target


def uninstall() -> pathlib.Path:
    target = check_path(ROOT / "var/install/Tunnel Manager.app")
    if target.exists():
        verify_app(target)
        require_unregistered(target)
        subprocess.run(
            [str(target / "Contents/MacOS/TunnelManager"), "--stop-service"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        deadline = time.monotonic() + 10
        while running(target) and time.monotonic() < deadline:
            time.sleep(0.1)
        if running(target):
            raise ValueError("Background service remains alive; refusing uninstall")
        remove(target)
    return target
