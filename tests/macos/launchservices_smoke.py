"""Open the real .app through LaunchServices and retain its background host."""

from __future__ import annotations

import argparse
import json
import pathlib
import sqlite3
import subprocess
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
APP = ROOT / "var/dist/Tunnel Manager.app"
EXECUTABLE = APP / "Contents/MacOS/TunnelManager"
ENDPOINT = ROOT / ".run/app/endpoint.json"


def status() -> dict | None:
    result = subprocess.run(
        [str(EXECUTABLE), "--service-status"], capture_output=True, text=True, check=False
    )
    return json.loads(result.stdout) if result.returncode == 0 else None


def await_ready() -> dict:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            value = status()
            endpoint = json.loads(ENDPOINT.read_text())
            if value and value["backend_alive"]:
                with urllib.request.urlopen(endpoint["origin"] + "/healthz", timeout=1) as response:
                    assert json.load(response)["alive"]
                return {"host_pid": value["pid"], "backend_pid": endpoint["pid"]}
        except (OSError, ValueError):
            pass
        time.sleep(0.1)
    raise AssertionError("LaunchServices did not produce a ready frozen backend")


def test_launchservices_open_reopen_and_menu_quit(*, preserve_running: bool = False) -> dict:
    database = ROOT / "var/data/app/tunnel-manager.sqlite3"
    if database.exists():
        with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as source:
            assert source.execute("SELECT count(*) FROM servers").fetchone()[0] == 0, (
                "GUI acceptance requires an empty app-owned profile database"
            )
    initial = status()
    assert initial is None or preserve_running, "Use --preserve-running to inspect the already-authorized app"
    opened = False
    events = []
    try:
        subprocess.run(["/usr/bin/open", str(APP)], check=True, timeout=10)
        opened = True
        first = await_ready()
        events.append("launchservices_reopens_authorized_frozen_app" if initial
                      else "launchservices_opens_frozen_app_without_terminal_server")
        if initial:
            assert first["host_pid"] == initial["pid"]
        subprocess.run(["/usr/bin/open", str(APP)], check=True, timeout=10)
        time.sleep(0.3)
        assert await_ready() == first
        events.append("repeated_open_reuses_single_background_host")
        subprocess.run(
            ["/usr/bin/osascript", "-e", 'tell application id "com.tunnelmanager.app" to quit'],
            check=True,
            timeout=10,
        )
        time.sleep(0.2)
        assert await_ready() == first
        events.append("quitting_menu_retains_browser_independent_background_host")
        subprocess.run(["/usr/bin/open", str(APP)], check=True, timeout=10)
        time.sleep(0.2)
        assert await_ready() == first
        events.append("reopen_after_menu_quit_reuses_existing_host")
    finally:
        if opened and not preserve_running:
            subprocess.run([str(EXECUTABLE), "--stop-service"], capture_output=True, text=True, check=False)
            deadline = time.monotonic() + 10
            while status() and time.monotonic() < deadline:
                time.sleep(0.1)
            try:
                subprocess.run(
                    ["/usr/bin/osascript", "-e", 'tell application id "com.tunnelmanager.app" to quit'],
                    check=False,
                    timeout=10,
                )
            except subprocess.TimeoutExpired:
                pass
    if preserve_running:
        assert await_ready() == first
    else:
        assert status() is None
    result = {"passed": events, "stopped_own_default_service": not preserve_running,
              "retained_running_app": preserve_running, "host_pid": first["host_pid"],
              "backend_pid": first["backend_pid"], "first_directory_consent": "COMPLETED_BY_USER" if initial else "PREVIOUSLY_SAVED"}
    (ROOT / "var/reports/macos-launchservices-smoke.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--preserve-running", action="store_true")
    print(json.dumps(test_launchservices_open_reopen_and_menu_quit(preserve_running=parser.parse_args().preserve_running)))
