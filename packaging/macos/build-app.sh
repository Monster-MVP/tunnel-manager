#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
BUILD="$ROOT/var/build"
DIST="$ROOT/var/dist"
APP="$DIST/Tunnel Manager.app"
PYTHON="$ROOT/.venv/bin/python"
PYINSTALLER="$ROOT/.venv/bin/pyinstaller"
export PYINSTALLER_CONFIG_DIR="$ROOT/var/cache/pyinstaller"
export TMPDIR="$ROOT/var/tmp"
export CLANG_MODULE_CACHE_PATH="$ROOT/var/cache/clang"
export SWIFT_MODULE_CACHE_PATH="$ROOT/var/cache/swift"
export PYTHONPYCACHEPREFIX="$ROOT/var/cache/pycache"
export PYTHONDONTWRITEBYTECODE=1

case "$(uname -s):$(uname -m)" in Darwin:arm64) ;; *) echo "Tunnel Manager requires local macOS arm64" >&2; exit 2 ;; esac
[ -x "$PYTHON" ] || { echo "missing project-local .venv Python" >&2; exit 2; }
[ -x "$PYINSTALLER" ] || { echo "missing project-local PyInstaller" >&2; exit 2; }

"$PYTHON" "$ROOT/packaging/macos/safe_paths.py" check "$BUILD" "$DIST" "$APP" "$TMPDIR" "$PYINSTALLER_CONFIG_DIR" "$CLANG_MODULE_CACHE_PATH" "$SWIFT_MODULE_CACHE_PATH"
if [ -d "$APP" ]; then
  "$APP/Contents/MacOS/TunnelManager" --service-status >/dev/null 2>&1 && { echo "stop the app-owned service before replacing this bundle" >&2; exit 2; }
fi
BUILD_METADATA=$("$PYTHON" "$ROOT/packaging/macos/build_metadata.py" inspect "$ROOT")
mkdir -p "$BUILD/backend" "$BUILD/web" "$BUILD/pyinstaller-work" "$DIST" "$TMPDIR" "$PYINSTALLER_CONFIG_DIR" "$CLANG_MODULE_CACHE_PATH" "$SWIFT_MODULE_CACHE_PATH"
"$PYTHON" "$ROOT/packaging/macos/safe_paths.py" remove "$BUILD/backend/tunnel-backend" "$BUILD/backend/tunnel-backend.spec"
"$PYINSTALLER" --noconfirm --clean --onedir --name tunnel-backend \
  --distpath "$BUILD/backend" --workpath "$BUILD/pyinstaller-work" --specpath "$BUILD/backend" \
  --paths "$ROOT/apps/backend" --paths "$ROOT/packaging/macos" "$ROOT/packaging/macos/frozen_entry.py"

if [ -x "$ROOT/node_modules/.bin/vite" ]; then
  (cd "$ROOT" && npm_config_cache="$ROOT/var/cache/npm" "$ROOT/node_modules/.bin/vite" build --config "$ROOT/apps/web/vite.config.ts" --configLoader runner --outDir "$BUILD/web")
else
  echo "missing project-local frontend build dependencies; run npm ci first" >&2; exit 2
fi
if [ -d "$APP" ]; then
  "$APP/Contents/MacOS/TunnelManager" --service-status >/dev/null 2>&1 && { echo "stop the app-owned service before replacing this bundle" >&2; exit 2; }
  "$PYTHON" "$ROOT/packaging/macos/safe_paths.py" remove "$APP"
fi
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/backend" "$APP/Contents/Resources/web" "$APP/Contents/Library/LaunchAgents"
xcrun swiftc "$ROOT/apps/macos/TunnelManagerApp.swift" -target arm64-apple-macos13.0 -O -whole-module-optimization -module-cache-path "$SWIFT_MODULE_CACHE_PATH" \
  -framework AppKit -framework ServiceManagement -o "$APP/Contents/MacOS/TunnelManager"
cp "$ROOT/packaging/macos/Info.plist" "$APP/Contents/Info.plist"
cp -R "$BUILD/backend/tunnel-backend" "$APP/Contents/Resources/backend/"
cp -R "$BUILD/web/." "$APP/Contents/Resources/web/"
printf '%s\n' "$BUILD_METADATA" | "$PYTHON" "$ROOT/packaging/macos/build_metadata.py" stage "$APP/Contents/Resources"
"$PYTHON" "$ROOT/packaging/macos/license_notices.py" "$APP/Contents/Resources"
xcrun swiftc "$ROOT/packaging/macos/generate-icon.swift" -module-cache-path "$SWIFT_MODULE_CACHE_PATH" -o "$BUILD/generate-icon" -framework AppKit
"$BUILD/generate-icon" "$BUILD/TunnelManager.iconset"
iconutil -c icns "$BUILD/TunnelManager.iconset" -o "$APP/Contents/Resources/TunnelManager.icns"
cp "$ROOT/packaging/macos/com.tunnelmanager.service.plist" "$APP/Contents/Library/LaunchAgents/com.tunnelmanager.service.plist"

"$PYTHON" "$ROOT/packaging/macos/safe_paths.py" manifest "$APP"
codesign --force --deep --sign - "$APP" >/dev/null
plutil -lint "$APP/Contents/Info.plist" >/dev/null
plutil -lint "$APP/Contents/Library/LaunchAgents/com.tunnelmanager.service.plist" >/dev/null
printf 'Built %s\n' "$APP"
