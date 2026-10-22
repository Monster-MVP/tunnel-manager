"""Frozen service entry plus self-contained project-local packaging actions."""

import sqlite3
import subprocess
import sys

if len(sys.argv) > 1 and sys.argv[1].startswith("--package-"):
    from install_app import install, rollback, uninstall

    try:
        action = sys.argv[1]
        if action == "--package-install" and len(sys.argv) == 2:
            print(install())
        elif action == "--package-uninstall" and len(sys.argv) == 2:
            print(uninstall())
        elif action == "--package-rollback" and len(sys.argv) == 3:
            print(rollback(sys.argv[2]))
        else:
            raise ValueError("Unknown packaging action")
    except (OSError, ValueError, KeyError, sqlite3.Error, subprocess.SubprocessError) as error:
        messages = {
            "Disable Tunnel Manager's own login item": "请先关闭 Tunnel Manager 的登录自动启动，再修改已安装副本。",
            "Stop the app-owned background service": "请先停止 Tunnel Manager 的后台服务，再安装、升级或回滚应用。",
            "Background service remains alive": "本应用后台服务尚未退出，已取消卸载。请停止后台服务后重试。",
            "symbolic link": "检测到符号链接或不安全路径，操作已取消。请使用项目目录内的原始文件。",
            "outside": "目标路径超出项目内允许范围，操作已取消。",
            "owned": "应用文件的所属用户不匹配，操作已取消。",
            "ownership manifest": "应用归属清单与当前项目不匹配，操作已取消。",
            "bundle identifier": "应用标识不匹配，操作已取消。",
            "integrity check": "数据库备份未通过完整性检查，回滚已取消。",
            "Unknown rollback": "无法识别此回滚检查点，请选择本项目生成的检查点。",
        }
        message = next((value for key, value in messages.items() if key in str(error)), None)
        if message is None:
            message = "项目内应用操作未完成。请检查应用签名、磁盘访问和诊断日志后重试。"
        print(message, file=sys.stderr)
        raise SystemExit(2)
else:
    from app.bootstrap import main

    main()
