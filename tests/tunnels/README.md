# SSH Engine Verification

Run from the project root:

```sh
.venv/bin/pytest tests/tunnels -q --basetemp=var/tmp/pytest-tunnels
```

The fixture is a real, isolated AsyncSSH server on loopback. It enables real
OpenSSH remote forwarding to high ephemeral ports. Its Linux `ss` adapter
observes an actual TCP listener on macOS; it does not invent listener state.
Actual `/usr/bin/curl` requests travel through the remote forward to a test
HTTP proxy. The Mac Direct test uses a separate app-owned Homebrew tinyproxy
process and a local HTTPS origin with a generated certificate, trusted by
the test curl only. It never disables TLS verification or reads user keys.

Coverage includes SSH control-channel readiness, remote bind failure, unknown
host-key rejection, nonce/config ownership rejection, HTTP 503 without SSH
restart, measured TLS timing, reconnect after the test SSH peer disconnects,
durable stop during retry, storage-write failure before control, concurrent
starts creating one master, unavailable-mode preflight preserving the old
master, and never stopping external proxy dependencies.

Tests use only project-local fixture state and high loopback ports. Generated
fixture keys remain in ignored test artifacts; no real key is read or copied.
These tests demonstrate isolated integration behavior, not AutoDL/Ubuntu,
physical network outage, login restoration, signing, or production migration
acceptance. Production ports 17890/17891 remain blocked until separately
authorized migration work. New managed tinyproxy cannot bind 7890 or 18888.

The engine controls live process handles and an in-memory nonce/argv registry,
checks process creation time and generated config digest, and checks the
control socket inode. Database PIDs are not authority to kill a process.
It neither discovers nor adopts pre-existing SSH or proxy processes.
