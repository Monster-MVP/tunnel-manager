# macOS 本机测试包

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
