#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
[ $# -eq 1 ] || { echo "Usage: rollback.sh <project-local rollback checkpoint>" >&2; exit 2; }
"$ROOT/var/dist/Tunnel Manager.app/Contents/Resources/backend/tunnel-backend/tunnel-backend" --package-rollback "$1"
