from __future__ import annotations

import importlib.util
import pathlib
import uuid

import pytest

PROJECT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("safe_paths", PROJECT / "packaging/macos/safe_paths.py")
safe_paths = importlib.util.module_from_spec(spec)
spec.loader.exec_module(safe_paths)
ROOT, check_path, remove = safe_paths.ROOT, safe_paths.check_path, safe_paths.remove


def test_reject_symlink_ancestor_without_removing_target():
    base = ROOT / "var/tmp" / f"paths-{uuid.uuid4().hex[:8]}"
    actual = base / "actual"
    actual.mkdir(parents=True)
    marker = actual / "keep.txt"
    marker.write_text("retain")
    link = base / "link"
    link.symlink_to(actual, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic link"):
        remove(link / "keep.txt")
    assert marker.read_text() == "retain"


def test_reject_external_path():
    with pytest.raises(ValueError, match="outside"):
        check_path(pathlib.Path("/Applications/Tunnel Manager.app"))


def test_unowned_app_bundle_is_not_deleted():
    base = ROOT / "var/tmp" / f"unknown-{uuid.uuid4().hex[:8]}.app"
    base.mkdir(parents=True)
    with pytest.raises(FileNotFoundError):
        remove(base)
    assert base.is_dir()
