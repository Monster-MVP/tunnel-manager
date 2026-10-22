"""Collect local dependency versions and license text for the test bundle."""

from __future__ import annotations

import importlib.metadata
import json
import pathlib
import shutil
import sys

from build_metadata import tinyproxy_keg

ROOT = pathlib.Path(__file__).absolute().parents[2]


def generate(destination: pathlib.Path) -> None:
    notices = destination / "third-party-licenses"
    notices.mkdir()
    inventory = []
    for distribution in sorted(
        importlib.metadata.distributions(), key=lambda value: value.metadata.get("Name", "")
    ):
        name = distribution.metadata.get("Name", "unknown")
        licenses = []
        for entry in distribution.files or []:
            if ".dist-info" in str(entry) and any(
                word in entry.name.lower() for word in ("license", "copying", "notice")
            ):
                source = pathlib.Path(distribution.locate_file(entry))
                if source.is_file():
                    target = notices / (name + "-" + source.name)
                    shutil.copyfile(source, target)
                    licenses.append(target.name)
        inventory.append(
            {
                "ecosystem": "python_build_and_runtime",
                "name": name,
                "version": distribution.version,
                "license": distribution.metadata.get(
                    "License-Expression", distribution.metadata.get("License", "unspecified")
                ),
                "files": licenses,
            }
        )
    lock = json.loads((ROOT / "package-lock.json").read_text())
    for package_path, metadata in sorted(lock.get("packages", {}).items()):
        if not package_path or metadata.get("dev"):
            continue
        package = ROOT / package_path
        licenses = []
        for source in package.glob("*"):
            if source.is_file() and source.name.lower().startswith(("license", "copying", "notice")):
                target = notices / (package_path.replace("/", "_") + "-" + source.name)
                shutil.copyfile(source, target)
                licenses.append(target.name)
        inventory.append(
            {
                "ecosystem": "npm_runtime",
                "name": package_path.removeprefix("node_modules/"),
                "version": metadata.get("version"),
                "license": metadata.get("license", "unspecified"),
                "files": licenses,
            }
        )
    for source in (
        pathlib.Path(sys.base_prefix) / "LICENSE.txt",
        pathlib.Path(sys.base_prefix) / "lib/python3.12/LICENSE.txt",
    ):
        if source.is_file():
            shutil.copyfile(source, notices / "Python-LICENSE.txt")
            break
    formula = tinyproxy_keg() / ".brew/tinyproxy.rb"
    shutil.copyfile(formula, notices / "tinyproxy-homebrew-build-formula.rb")
    (destination / "THIRD-PARTY-NOTICES.json").write_text(json.dumps(inventory, indent=2) + "\n")


if __name__ == "__main__":
    generate(pathlib.Path(sys.argv[1]))
