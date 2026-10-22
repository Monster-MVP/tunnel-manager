# Tunnel Manager Contributor Rules

- Work from this checkout's root. Keep dependencies, caches, test fixtures, databases,
  reports and builds in project-local var/, .run/, .venv/ and node_modules/.
- Develop the double-clickable macOS App; a terminal-started server is for development.
- External SSH/proxy/launchd resources are read-only dependencies. Never adopt or
  signal an unknown PID, restart external services, or change remote configuration.
- Only control verified process handles created and recorded as owned by this App.
  Do not kill a process to free a port or use broad pkill/killall commands.
- Preserve loopback binding, SSH host-key checking, verified TLS, Origin/CSRF/session
  guards, private IPC and directory permissions. Use absolute programs/argument arrays.
- Never read or commit user private keys, API keys, Keychain data, auth.json, full
  credential environments, database contents, tickets or directory-access bookmarks.
- Credential and model checks require separate explicit product consent. Keep keys
  remote; do not return provider bodies/generated text to the Mac. No paid retries.
- Use synthetic credentials and isolated SSH/HTTP/TLS fixtures during development.
- Keep changes scoped. Preserve failed evidence; never substitute synthetic results
  for real-server acceptance or infer health from only a PID/listening socket.
- UI changes require baseline/actual screenshots, consistent Chinese workflows,
  Light/Dark/System, multiple widths, scaling and keyboard accessibility checks.
  Use independent UI/reliability reviewers for release gates when available.
- Building/updating a running App requires a deliberate maintenance window. Do not
  overwrite its bundle or restart its channels as an incidental development action.
- Read README.md and docs/public/development.md for supported build/test workflows.
- The project owner has not selected a project license; do not invent one.
