#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
APP="$ROOT/var/dist/Tunnel Manager.app"
export TMPDIR="$ROOT/var/tmp"
"$ROOT/.venv/bin/python" "$ROOT/packaging/macos/safe_paths.py" check "$APP/Contents/Resources/web"
codesign --verify --deep --strict "$APP"
"$APP/Contents/MacOS/TunnelManager" --service-status >/dev/null 2>&1 && { echo "stop the app-owned service before refreshing this bundle" >&2; exit 2; }
[ -f "$ROOT/var/build/web/index.html" ] || { echo "static web build missing" >&2; exit 2; }
"$ROOT/.venv/bin/python" "$ROOT/packaging/macos/safe_paths.py" remove "$APP/Contents/Resources/web"
mkdir "$APP/Contents/Resources/web"
cp -R "$ROOT/var/build/web/." "$APP/Contents/Resources/web/"
codesign --force --deep --sign - "$APP" >/dev/null
codesign --verify --deep --strict "$APP"
