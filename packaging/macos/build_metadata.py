"""Read-only, machine-independent inputs for the local macOS test bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import plistlib
import re
import shutil
import subprocess
import sys
import uuid

TINYPROXY_VERSION = "1.11.3"
TINYPROXY_SOURCE_NAME = f"tinyproxy-{TINYPROXY_VERSION}.tar.xz"
TINYPROXY_SOURCE_SHA256 = "f05644fdf1211ba13754a354bebed909b5b39371b12cce8563c46929a75bedf6"
TINYPROXY_OPT = pathlib.Path("/opt/homebrew/opt/tinyproxy")


def tinyproxy_keg(opt: pathlib.Path = TINYPROXY_OPT) -> pathlib.Path:
    """Resolve Homebrew's opt link without selecting a newer dependency version."""
    try:
        keg = opt.resolve(strict=True)
    except OSError as error:
        raise ValueError("tinyproxy 1.11.3 is required at /opt/homebrew/opt/tinyproxy") from error
    if (
        not keg.is_dir()
        or keg.parent.name != "tinyproxy"
        or keg.parent.parent.name != "Cellar"
        or re.fullmatch(re.escape(TINYPROXY_VERSION) + r"(?:_[0-9]+)?", keg.name) is None
    ):
        raise ValueError("Homebrew tinyproxy opt link must resolve to a 1.11.3 keg")
    for relative in ("bin/tinyproxy", "COPYING", "README.md", ".brew/tinyproxy.rb"):
        source = keg / relative
        if not source.is_file() or source.is_symlink():
            raise ValueError(f"tinyproxy 1.11.3 keg is missing a regular {relative} file")
    if not os.access(keg / "bin/tinyproxy", os.X_OK):
        raise ValueError("tinyproxy binary is not executable")
    return keg


def verified_source(root: pathlib.Path) -> pathlib.Path:
    archive = root / "var/build" / TINYPROXY_SOURCE_NAME
    if not archive.is_file() or archive.is_symlink():
        raise ValueError(
            f"Missing matching source archive: {archive}. Place the upstream tinyproxy "
            f"{TINYPROXY_VERSION} source archive here; expected SHA-256 {TINYPROXY_SOURCE_SHA256}. "
            "The build does not download or substitute sources."
        )
    if hashlib.sha256(archive.read_bytes()).hexdigest() != TINYPROXY_SOURCE_SHA256:
        raise ValueError("tinyproxy source digest differs from the pinned 1.11.3 source")
    return archive


def storage_metadata(root: pathlib.Path) -> dict[str, str]:
    root = root.absolute()
    if not root.is_dir() or root.resolve() != root:
        raise ValueError("Project root must be an existing directory without symbolic links")
    # Resolve the actual filesystem device, including APFS Data firmlinks; a
    # parent-path mount search can select the wrong System volume under /Users.
    filesystem = subprocess.run(
        ["/bin/df", "-P", str(root)], check=True, capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"}, timeout=10,
    )
    rows = filesystem.stdout.strip().splitlines()
    if len(rows) != 2:
        raise ValueError("Unable to identify the device containing the project root")
    device = rows[1].split(maxsplit=1)[0]
    if re.fullmatch(r"/dev/disk[0-9]+(?:s[0-9]+)*", device) is None:
        raise ValueError("Project root must be stored on a mounted macOS disk volume")
    observation = subprocess.run(
        ["/usr/sbin/diskutil", "info", "-plist", device],
        check=True,
        capture_output=True,
        timeout=10,
    )
    try:
        document = plistlib.loads(observation.stdout)
        volume_uuid = document["VolumeUUID"]
        if not isinstance(volume_uuid, str) or str(uuid.UUID(volume_uuid)).upper() != volume_uuid.upper():
            raise ValueError("Invalid volume UUID")
    except (ValueError, TypeError, KeyError, plistlib.InvalidFileException) as error:
        raise ValueError("Unable to determine the UUID of the volume containing the project root") from error
    return {"project_root": str(root), "volume_uuid": volume_uuid}


def inspect(root: pathlib.Path) -> dict[str, str]:
    metadata = storage_metadata(root)
    keg = tinyproxy_keg()
    version = subprocess.run(
        [str(keg / "bin/tinyproxy"), "-v"], capture_output=True, text=True, check=True, timeout=5
    )
    if version.stdout.strip() != f"tinyproxy {TINYPROXY_VERSION}":
        raise ValueError("tinyproxy executable does not report the pinned version 1.11.3")
    source = verified_source(root)
    return {**metadata, "tinyproxy_keg": str(keg), "tinyproxy_source": str(source)}


def stage(metadata: dict[str, str], destination: pathlib.Path) -> None:
    root = pathlib.Path(metadata["project_root"])
    keg = tinyproxy_keg(pathlib.Path(metadata["tinyproxy_keg"]))
    source = verified_source(root)
    if metadata["tinyproxy_source"] != str(source):
        raise ValueError("Source metadata changed after build preflight")
    (destination / "storage.json").write_text(
        json.dumps({key: metadata[key] for key in ("project_root", "volume_uuid")}, indent=2) + "\n"
    )
    for relative, name in (
        ("bin/tinyproxy", "tinyproxy"),
        ("COPYING", "TINYPROXY-COPYING.txt"),
        ("README.md", "TINYPROXY-SOURCE-INFO.txt"),
    ):
        shutil.copyfile(keg / relative, destination / name)
    (destination / "tinyproxy").chmod(0o755)
    shutil.copyfile(source, destination / TINYPROXY_SOURCE_NAME)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("inspect", "stage"))
    parser.add_argument("path", type=pathlib.Path)
    args = parser.parse_args()
    try:
        if args.action == "inspect":
            print(json.dumps(inspect(args.path)))
        else:
            stage(json.load(sys.stdin), args.path)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(2, f"macOS build preflight failed: {error}\n")


if __name__ == "__main__":
    main()
