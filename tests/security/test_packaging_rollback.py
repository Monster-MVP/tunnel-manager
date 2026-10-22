import importlib.util
import json
import plistlib
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[2]


def test_rollback_never_replays_pre_upgrade_wal(tmp_path, monkeypatch):
    """A backup is a complete SQLite image; an older active WAL must not survive it."""
    module_dir = PROJECT / "packaging/macos"
    monkeypatch.syspath_prepend(str(module_dir))
    import safe_paths

    sandbox = tmp_path / "isolated-install"
    sandbox.mkdir()
    monkeypatch.setattr(safe_paths, "ROOT", sandbox)
    monkeypatch.setattr(safe_paths, "OWNED_PREFIXES", (sandbox / "var/install",))
    spec = importlib.util.spec_from_file_location("security_install_app", module_dir / "install_app.py")
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    monkeypatch.setattr(installer, "running", lambda _: False)
    monkeypatch.setattr(installer, "require_unregistered", lambda _: None)
    monkeypatch.setattr(installer, "verify_app", lambda path: safe_paths.verify_app(path, signature=False))

    checkpoint = sandbox / "var/install/rollback-isolated"
    app = checkpoint / "Tunnel Manager.app"
    (app / "Contents/Resources").mkdir(parents=True)
    (app / "Contents/Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": "com.tunnelmanager.app"}))
    (app / "Contents/Resources/install-manifest.json").write_text(json.dumps({
        "owner": "Tunnel Manager", "project_root": str(sandbox),
    }))
    (checkpoint / "checkpoint.json").write_text(json.dumps({
        "owner": "Tunnel Manager", "project_root": str(sandbox), "database_backup": True,
    }))
    backup = checkpoint / "database.sqlite3"
    with sqlite3.connect(backup) as connection:
        connection.execute("CREATE TABLE sentinel(value TEXT)")
        connection.execute("INSERT INTO sentinel VALUES ('expected-backup')")

    database = sandbox / "var/data/app/tunnel-manager.sqlite3"
    database.parent.mkdir(parents=True)
    child = subprocess.run([
        sys.executable, "-c",
        ("import os,sqlite3,sys; c=sqlite3.connect(sys.argv[1]); "
        "c.execute('PRAGMA journal_mode=WAL'); c.execute('PRAGMA wal_autocheckpoint=0'); "
        "c.execute('CREATE TABLE sentinel(value TEXT)'); "
        "c.execute(\"INSERT INTO sentinel VALUES ('stale-wal')\"); c.commit(); os._exit(0)"),
        str(database),
    ], cwd=PROJECT, check=False)
    assert child.returncode == 0
    assert Path(str(database) + "-wal").stat().st_size > 0
    installer.rollback(str(checkpoint))
    with sqlite3.connect(database) as restored:
        assert restored.execute("SELECT value FROM sentinel").fetchall() == [("expected-backup",)]
    recovery = list(database.parent.glob("pre-rollback-*"))
    assert len(recovery) == 1
    assert (recovery[0] / "tunnel-manager.sqlite3-wal").is_file()


def test_upgrade_sqlite_checkpoint_is_private(tmp_path, monkeypatch):
    module_dir = PROJECT / "packaging/macos"
    monkeypatch.syspath_prepend(str(module_dir))
    import safe_paths

    sandbox = tmp_path / "isolated-checkpoint"
    sandbox.mkdir()
    monkeypatch.setattr(safe_paths, "ROOT", sandbox)
    monkeypatch.setattr(safe_paths, "OWNED_PREFIXES", (sandbox / "var/install", sandbox / "var/dist"))
    spec = importlib.util.spec_from_file_location("security_checkpoint_install_app", module_dir / "install_app.py")
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    monkeypatch.setattr(installer, "running", lambda _: False)
    monkeypatch.setattr(installer, "require_unregistered", lambda _: None)
    monkeypatch.setattr(installer, "verify_app", lambda path: safe_paths.verify_app(path, signature=False))
    source = sandbox / "var/dist/Tunnel Manager.app"
    (source / "Contents/Resources").mkdir(parents=True)
    (source / "Contents/Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": "com.tunnelmanager.app"}))
    (source / "Contents/Resources/install-manifest.json").write_text(json.dumps({
        "owner": "Tunnel Manager", "project_root": str(sandbox),
    }))
    installed = sandbox / "var/install/Tunnel Manager.app"
    shutil.copytree(source, installed)
    database = sandbox / "var/data/app/tunnel-manager.sqlite3"
    database.parent.mkdir(parents=True)
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE synthetic(value TEXT)")
        connection.execute("INSERT INTO synthetic VALUES ('private-profile-metadata')")
    assert installer.install() == installed
    checkpoints = list(installed.parent.glob("rollback-*"))
    assert len(checkpoints) == 1
    checkpoint = checkpoints[0]
    backup = checkpoint / "database.sqlite3"
    assert backup.stat().st_mode & 0o077 == 0, "Full configuration backups must be owner-only"
    assert checkpoint.stat().st_mode & 0o077 == 0, "Checkpoint directory must be owner-only"
