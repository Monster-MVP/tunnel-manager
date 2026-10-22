from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import plistlib
import shutil
import subprocess
import sys

import pytest

PROJECT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("build_metadata", PROJECT / "packaging/macos/build_metadata.py")
metadata = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metadata)


def fixture_keg(tmp_path, version="1.11.3_1"):
    keg = tmp_path / "Cellar/tinyproxy" / version
    for relative in ("bin/tinyproxy", "COPYING", "README.md", ".brew/tinyproxy.rb"):
        target = keg / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("synthetic build fixture")
    (keg / "bin/tinyproxy").chmod(0o755)
    opt = tmp_path / "opt/tinyproxy"
    opt.parent.mkdir()
    opt.symlink_to(keg, target_is_directory=True)
    return keg, opt


def test_opt_resolves_fixed_version_with_homebrew_revision(tmp_path):
    keg, opt = fixture_keg(tmp_path)
    assert metadata.tinyproxy_keg(opt) == keg


def test_opt_rejects_dependency_version_change(tmp_path):
    _, opt = fixture_keg(tmp_path, "1.12.0")
    with pytest.raises(ValueError, match="1.11.3 keg"):
        metadata.tinyproxy_keg(opt)


def test_opt_rejects_missing_license(tmp_path):
    keg, opt = fixture_keg(tmp_path)
    (keg / "COPYING").unlink()
    with pytest.raises(ValueError, match="COPYING"):
        metadata.tinyproxy_keg(opt)


def test_storage_uses_actual_project_path_and_structured_json(tmp_path, monkeypatch):
    project = tmp_path / 'project with "quotes"'
    project.mkdir()
    volume_uuid = "7D1EE27A-573A-4313-9119-D97AC90EF078"
    observed = []

    def diskutil(argv, **kwargs):
        observed.append(argv)
        if argv[0] == "/bin/df":
            return subprocess.CompletedProcess(argv, 0, "Filesystem 512-blocks Used Available Capacity Mounted on\n"
                                               "/dev/disk9s2 100 10 90 10% /Volumes/example volume\n")
        return subprocess.CompletedProcess(argv, 0, plistlib.dumps({"VolumeUUID": volume_uuid}))

    monkeypatch.setattr(metadata.subprocess, "run", diskutil)
    result = metadata.storage_metadata(project)
    assert observed == [["/bin/df", "-P", str(project)],
                        ["/usr/sbin/diskutil", "info", "-plist", "/dev/disk9s2"]]
    assert json.loads(json.dumps(result)) == {"project_root": str(project), "volume_uuid": volume_uuid}


@pytest.mark.parametrize("document", [{}, {"VolumeUUID": "invalid"}, {"VolumeUUID": None}])
def test_storage_rejects_unavailable_or_invalid_uuid(tmp_path, monkeypatch, document):
    def observation(argv, **kwargs):
        if argv[0] == "/bin/df":
            return subprocess.CompletedProcess(argv, 0, "Filesystem\n/dev/disk9s2 1 0 1 0% /\n")
        return subprocess.CompletedProcess(
            argv, 0, plistlib.dumps(document) if document.get("VolumeUUID", "missing") is not None else b"bad plist"
        )

    monkeypatch.setattr(metadata.subprocess, "run", observation)
    with pytest.raises(ValueError, match="volume"):
        metadata.storage_metadata(tmp_path)


@pytest.mark.parametrize("output", ["", "Filesystem\nserver:/remote 1 0 1 0% /Volumes/share\n",
                                    "Filesystem\n/dev/disk1 1 0 1 0% /\n/dev/disk2 1 0 1 0% /x\n"])
def test_storage_rejects_ambiguous_or_network_filesystem(tmp_path, monkeypatch, output):
    monkeypatch.setattr(metadata.subprocess, "run", lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, output))
    with pytest.raises(ValueError):
        metadata.storage_metadata(tmp_path)


def test_source_refuses_missing_or_different_archive(tmp_path):
    with pytest.raises(ValueError, match="does not download"):
        metadata.verified_source(tmp_path)
    archive = tmp_path / "var/build" / metadata.TINYPROXY_SOURCE_NAME
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"synthetic wrong source")
    with pytest.raises(ValueError, match="digest"):
        metadata.verified_source(tmp_path)


def test_stage_keeps_json_paths_and_matching_source_together(tmp_path, monkeypatch):
    project = tmp_path / 'project with "quotes"'
    archive = project / "var/build" / metadata.TINYPROXY_SOURCE_NAME
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"synthetic matching source")
    monkeypatch.setattr(metadata, "TINYPROXY_SOURCE_SHA256", hashlib.sha256(archive.read_bytes()).hexdigest())
    keg, _ = fixture_keg(tmp_path)
    destination = project / "var/dist/fixture.app/Contents/Resources"
    destination.mkdir(parents=True)
    values = {
        "project_root": str(project), "volume_uuid": "7D1EE27A-573A-4313-9119-D97AC90EF078",
        "tinyproxy_keg": str(keg), "tinyproxy_source": str(archive),
    }
    metadata.stage(values, destination)
    assert json.loads((destination / "storage.json").read_text()) == {
        key: values[key] for key in ("project_root", "volume_uuid")
    }
    assert (destination / metadata.TINYPROXY_SOURCE_NAME).read_bytes() == archive.read_bytes()
    assert (destination / "TINYPROXY-COPYING.txt").read_bytes() == (keg / "COPYING").read_bytes()
    assert (destination / "tinyproxy").stat().st_mode & 0o777 == 0o755


def test_inspect_refuses_binary_version_mismatch(tmp_path, monkeypatch):
    keg, _ = fixture_keg(tmp_path)
    monkeypatch.setattr(metadata, "storage_metadata", lambda root: {"project_root": str(root)})
    monkeypatch.setattr(metadata, "tinyproxy_keg", lambda: keg)
    monkeypatch.setattr(metadata.subprocess, "run", lambda argv, **kwargs: subprocess.CompletedProcess(
        argv, 0, "tinyproxy 1.12.0\n"
    ))
    with pytest.raises(ValueError, match="pinned version"):
        metadata.inspect(tmp_path)


def test_build_refuses_running_host_before_build_mutation():
    source = (PROJECT / "packaging/macos/build-app.sh").read_text()
    first_status = source.index('"$APP/Contents/MacOS/TunnelManager" --service-status')
    first_mutation = source.index('mkdir -p "$BUILD/backend"')
    assert first_status < source.index("BUILD_METADATA=") < first_mutation
    assert source.count('"$APP/Contents/MacOS/TunnelManager" --service-status') == 2
    assert 'build_metadata.py" inspect "$ROOT"' in source
    assert "diskutil info -plist /Volumes/" not in source


def test_running_fixture_host_exits_without_creating_build_outputs(tmp_path):
    fixture = tmp_path / "fixture-project"
    packaging = fixture / "packaging/macos"
    packaging.mkdir(parents=True)
    for name in ("build-app.sh", "safe_paths.py"):
        shutil.copyfile(PROJECT / "packaging/macos" / name, packaging / name)
    tools = fixture / ".venv/bin"
    tools.mkdir(parents=True)
    (tools / "python").symlink_to(sys.executable)
    pyinstaller = tools / "pyinstaller"
    pyinstaller.write_text("#!/bin/sh\nexit 89\n")
    pyinstaller.chmod(0o755)
    host = fixture / "var/dist/Tunnel Manager.app/Contents/MacOS/TunnelManager"
    host.parent.mkdir(parents=True)
    host.write_text('#!/bin/sh\n[ "$1" = "--service-status" ]\n')
    host.chmod(0o755)
    result = subprocess.run(["/bin/sh", str(packaging / "build-app.sh")], capture_output=True, text=True, check=False)
    assert result.returncode == 2
    assert "stop the app-owned service" in result.stderr
    assert not (fixture / "var/build").exists()
    assert not (fixture / "var/cache").exists()
    assert not (fixture / "var/tmp").exists()
    assert host.is_file()
