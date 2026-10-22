"""Archive the verified local-test app and retain a SHA256 release manifest."""

from __future__ import annotations

import hashlib
import json
import subprocess

from safe_paths import ROOT, check_path, verify_app

app = check_path(ROOT / "var/dist/Tunnel Manager.app")
verify_app(app)
release = check_path(ROOT / "var/dist/release")
release.mkdir(exist_ok=True)
archive = check_path(release / "Tunnel-Manager-macOS-arm64-adhoc.zip")
subprocess.run(
    ["/usr/bin/ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", str(app), str(archive)], check=True
)
manifest = {
    "file": archive.name,
    "version": "2.0.0",
    "build": "2",
    "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
    "bytes": archive.stat().st_size,
    "distribution": "ad_hoc_local_test",
    "notarized": False,
    "architecture": "arm64",
    "minimum_macos": "13.0",
    "tested_macos": "27.0.1",
    "storage_bound_to_project": True,
}
check_path(release / "release-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
check_path(release / "SHA256SUMS.txt").write_text(f"{manifest['sha256']}  {archive.name}\n")
print(json.dumps(manifest))
