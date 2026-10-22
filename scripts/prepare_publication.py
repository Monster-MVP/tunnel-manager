"""Create an allowlisted source snapshot without local Git history or runtime data."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROOT_FILES = {
    ".gitignore", "README.md", "package.json", "package-lock.json", "pyproject.toml", "uv.lock",
    "eslint.config.js", "playwright.config.ts", "tsconfig.json",
}
SCRIPTS = {
    "serve.py", "open_dev_console.py", "record_check.py", "v2_live_fixture.py", "v2-ui-audit.mjs",
    "model_test_ui_fixture.py", "ui-smoke.mjs", "prepare_publication.py",
}
PRIVATE_PACKAGING = {"build-credentials-candidate.py", "build-model-test-candidate.py", "import-guidance-candidate.py"}
PUBLIC_AGENT_RULES = """# Tunnel Manager Contributor Rules

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
"""
PUBLIC_PACKAGING_README = """# macOS 本机测试包

构建前提、精确命令与限制见[根 README](../../README.md)。

`build-app.sh` 仅支持本地 macOS Apple Silicon，生成
`var/dist/Tunnel Manager.app`。它从项目实际卷获取 UUID、固定检查 tinyproxy
1.11.3 及匹配源码，并保留第三方许可。App 绑定构建时项目路径和卷，使用
ad-hoc 签名，不是可移植、签名公证的正式安装包。

构建在修改输出前检查默认 App 后台是否正在运行，替换前再次检查。开发者
应在自己的 checkout 构建，不覆盖用户正在使用的 bundle 或重启外部服务。

Swift 菜单栏启动器启动独立宿主和冻结后端，再打开认证 loopback 控制台。
首次目录授权由用户亲自选择。浏览器关闭和退出菜单栏保留后台；停止后台
是明确操作。登录项通过 SMAppService 由用户显式注册，构建不注册登录项。

项目内安装、升级、回滚、卸载通过本应用菜单或 scripts/macos 下维护工具。
执行前停止自有后台并处理自己的登录项，保留一致数据库和旧签名 App。
这些工具不能控制原 SSH、tinyproxy、Clash 或其他 launchd 服务。

构建工具中的 release-app.py 仅生成本机绑定测试 ZIP；公开发布二进制前
仍需完成项目许可、第三方许可、干净 Mac、Developer ID 和公证验收。
"""


def selected(relative: Path) -> bool:
    if str(relative) in ROOT_FILES:
        return True
    if relative.parts[0] in {"apps", "shared", "tests"}:
        return True
    if relative.is_relative_to("docs/public"):
        return True
    if relative.is_relative_to("packaging/macos"):
        return relative.name not in PRIVATE_PACKAGING and relative.name != "README.md"
    if relative.is_relative_to("scripts/macos"):
        return True
    return relative.parent == Path("scripts") and relative.name in SCRIPTS


def prepare(destination: Path) -> dict:
    destination = destination.absolute()
    parent = ROOT / "var/publication"
    if not destination.is_relative_to(parent) or destination == parent or destination.resolve() != destination:
        raise ValueError("Publication must use a fresh project-local var/publication child")
    if destination.exists():
        raise ValueError("Refusing to overwrite an existing publication snapshot")
    paths = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT)
    chosen = sorted({Path(name.decode()) for name in paths.split(b"\0") if name and selected(Path(name.decode()))})
    destination.mkdir(parents=True, mode=0o700)
    for relative in chosen:
        source = ROOT / relative
        if source.is_symlink() or source.resolve() != source or not source.is_file():
            raise ValueError(f"Unsafe publication source: {relative}")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    (destination / "AGENTS.md").write_text(PUBLIC_AGENT_RULES)
    (destination / "packaging/macos/README.md").write_text(PUBLIC_PACKAGING_README)
    records = []
    for path in sorted(destination.rglob("*")):
        if path.is_file():
            records.append({"path": str(path.relative_to(destination)), "bytes": path.stat().st_size,
                            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    report = {"kind": "allowlisted_public_source_snapshot", "history_included": False,
              "private_audit_included": False, "runtime_data_included": False, "files": records}
    report_path = destination.parent / (destination.name + "-inventory.json")
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    return {"destination": str(destination.relative_to(ROOT)), "files": len(records),
            "inventory": str(report_path.relative_to(ROOT)), "history_included": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    arguments = parser.parse_args()
    print(json.dumps(prepare(arguments.destination), indent=2))
