"""Run an exact verification command and retain its output and exit status."""

import json
import os
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

root = Path(__file__).resolve().parents[1]
if len(sys.argv) < 3:
    raise SystemExit("Usage: record_check.py check-name command [arguments ...]")
name = sys.argv[1]
if not name.replace("-", "").replace("_", "").isalnum():
    raise SystemExit("Invalid check name")
command = sys.argv[2:]
reports = root / "var/reports"
reports.mkdir(parents=True, exist_ok=True)
started = datetime.now(UTC).isoformat()
clock = time.monotonic()
environment = os.environ.copy()
environment.update({
    "TMPDIR": str(root / "var/tmp"),
    "UV_CACHE_DIR": str(root / "var/cache/uv"),
    "npm_config_cache": str(root / "var/cache/npm"),
    "PYTHONDONTWRITEBYTECODE": "1",
    "PLAYWRIGHT_BROWSERS_PATH": str(root / "var/cache/playwright"),
})
try:
    result = subprocess.run(command, cwd=root, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, check=False)
except OSError as error:
    result = subprocess.CompletedProcess(command, 127, f"Could not execute command: {error}\n")
report = {"name": name, "command": command, "started_at": started, "duration_s": round(time.monotonic()-clock, 3), "exit_code": result.returncode, "output": result.stdout}
existing = list(reports.glob(name + "-*.json"))
destination = reports / f"{name}-{len(existing)+1}.json"
destination.write_text(json.dumps(report, indent=2))
print(result.stdout, end="")
print(f"\nCHECK {name}: exit={result.returncode}, report={destination.relative_to(root)}")
raise SystemExit(result.returncode)
