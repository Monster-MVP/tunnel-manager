#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
"$ROOT/var/dist/Tunnel Manager.app/Contents/Resources/backend/tunnel-backend/tunnel-backend" --package-uninstall
echo "Removed only the project-local Tunnel Manager app. Existing SSH, proxy, and launchd files were not touched."
