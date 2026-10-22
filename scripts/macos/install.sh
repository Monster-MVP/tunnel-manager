#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
APP="$ROOT/var/dist/Tunnel Manager.app"
[ -d "$APP" ] || { echo "build the app first" >&2; exit 2; }
"$APP/Contents/Resources/backend/tunnel-backend/tunnel-backend" --package-install
