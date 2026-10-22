#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
APP="$ROOT/var/dist/Tunnel Manager.app"
[ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ]
[ -d "$APP" ] || { echo "app bundle not built" >&2; exit 2; }
plutil -lint "$APP/Contents/Info.plist" >/dev/null
plutil -lint "$APP/Contents/Library/LaunchAgents/com.tunnelmanager.service.plist" >/dev/null
[ -x "$APP/Contents/MacOS/TunnelManager" ]
[ -x "$APP/Contents/Resources/backend/tunnel-backend/tunnel-backend" ]
[ -x "$APP/Contents/Resources/tinyproxy" ]
[ -f "$APP/Contents/Resources/storage.json" ]
python3 - "$APP/Contents/Resources/storage.json" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); d = json.loads(p.read_text())
assert d["project_root"] and d["volume_uuid"]
PY
python3 - "$APP" <<'PY'
import json, pathlib, plistlib, sys
app = pathlib.Path(sys.argv[1])
info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
assert info["CFBundleShortVersionString"] == "2.0.0"
assert info["CFBundleVersion"] == "2"
assert info["CFBundleDevelopmentRegion"] == "zh"
manifest = json.loads((app / "Contents/Resources/install-manifest.json").read_text())
assert manifest["version"] == "2.0.0" and manifest["build"] == "2"
PY
codesign --verify --deep --strict "$APP"
echo "macOS bundle manifest and signature checks passed"
