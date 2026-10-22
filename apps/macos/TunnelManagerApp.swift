import AppKit
import Foundation
import ServiceManagement
import Darwin

struct LaunchLayout {
    let bundle: URL
    let projectRoot: URL
    let dataDir: URL
    let runtimeDir: URL
    let backend: URL
    let web: URL
    let tinyproxy: URL
    let volumeUUID: String

    init(bundle: URL = Bundle.main.bundleURL, dataOverride: String? = nil, runtimeOverride: String? = nil) throws {
        self.bundle = bundle
        let rootFile = bundle.appendingPathComponent("Contents/Resources/storage.json")
        let storage = try JSONSerialization.jsonObject(with: Data(contentsOf: rootFile)) as? [String: Any]
        let configured = storage?["project_root"] as? String ?? ""
        guard !configured.isEmpty else { throw LayoutError.storageUnavailable }
        self.projectRoot = URL(fileURLWithPath: configured, isDirectory: true)
        self.volumeUUID = storage?["volume_uuid"] as? String ?? ""
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: projectRoot.path, isDirectory: &isDir), isDir.boolValue else {
            throw LayoutError.storageUnavailable
        }
        self.dataDir = dataOverride.map { URL(fileURLWithPath: $0, isDirectory: true) } ?? projectRoot.appendingPathComponent("var/data/app", isDirectory: true)
        self.runtimeDir = runtimeOverride.map { URL(fileURLWithPath: $0, isDirectory: true) } ?? projectRoot.appendingPathComponent(".run/app", isDirectory: true)
        self.backend = bundle.appendingPathComponent("Contents/Resources/backend/tunnel-backend/tunnel-backend")
        self.web = bundle.appendingPathComponent("Contents/Resources/web", isDirectory: true)
        self.tinyproxy = bundle.appendingPathComponent("Contents/Resources/tinyproxy")
        for path in [self.dataDir, self.runtimeDir] {
            guard path.path.hasPrefix(projectRoot.path + "/"), path.resolvingSymlinksInPath().path == path.path else { throw LayoutError.invalidPath }
        }
        try validateStorage()
    }

    func validateStorage() throws {
        guard !volumeUUID.isEmpty,
              let observed = try projectRoot.resourceValues(forKeys: [.volumeUUIDStringKey]).volumeUUIDString,
              observed == volumeUUID,
              projectRoot.resolvingSymlinksInPath().path == projectRoot.path else {
            throw LayoutError.storageUnavailable
        }
        try rejectSymlinkAncestors(projectRoot)
    }
}

enum LayoutError: Error { case storageUnavailable, invalidPath }

final class StorageAccess {
    let url: URL
    let bookmark: Data
    private let scoped: Bool
    init(bookmark: Data, layout: LaunchLayout) throws {
        var stale = false
        let resolved: URL
        do {
            resolved = try URL(resolvingBookmarkData: bookmark, options: [.withSecurityScope, .withoutUI], relativeTo: nil, bookmarkDataIsStale: &stale)
        } catch {
            resolved = try URL(resolvingBookmarkData: bookmark, options: [.withoutUI], relativeTo: nil, bookmarkDataIsStale: &stale)
        }
        guard !stale, resolved.standardizedFileURL.path == layout.projectRoot.path,
              resolved.resolvingSymlinksInPath().path == layout.projectRoot.path else { throw LayoutError.invalidPath }
        self.url = resolved; self.bookmark = bookmark
        scoped = resolved.startAccessingSecurityScopedResource()
        try layout.validateStorage()
    }
    deinit { if scoped { url.stopAccessingSecurityScopedResource() } }
}

final class OwnedChild {
    let pid: pid_t
    private var reaped = false

    init(executable: String, arguments: [String], projectRoot: URL) throws {
        var actions: posix_spawn_file_actions_t?
        var attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0,
              posix_spawnattr_init(&attributes) == 0 else { throw LayoutError.invalidPath }
        defer { posix_spawn_file_actions_destroy(&actions); posix_spawnattr_destroy(&attributes) }
        for descriptor in 0...2 { posix_spawn_file_actions_addopen(&actions, Int32(descriptor), "/dev/null", O_RDWR, 0o600) }
        // SETPGROUP happens atomically before exec. No PID race or production process can join this new group.
        posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT))
        posix_spawnattr_setpgroup(&attributes, 0)
        let argv = ([executable] + arguments).map { strdup($0) } + [nil]
        var runtimeEnvironment = ["PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=en_US.UTF-8",
                                  "TMPDIR=\(projectRoot.appendingPathComponent("var/tmp").path)", "PYTHONNOUSERSITE=1"]
        // Pass only the agent socket reference; never inspect or inherit credential-bearing environments.
        if let agent = ProcessInfo.processInfo.environment["SSH_AUTH_SOCK"], agent.hasPrefix("/") {
            var metadata = stat()
            if lstat(agent, &metadata) == 0, metadata.st_uid == getuid(), metadata.st_mode & S_IFMT == S_IFSOCK {
                runtimeEnvironment.append("SSH_AUTH_SOCK=\(agent)")
            }
        }
        let envp = runtimeEnvironment.map { strdup($0) } + [nil]
        defer { argv.forEach { free($0) }; envp.forEach { free($0) } }
        var launched: pid_t = 0
        let result = argv.withUnsafeBufferPointer { args in envp.withUnsafeBufferPointer { environment in
            posix_spawn(&launched, executable, &actions, &attributes, UnsafeMutablePointer(mutating: args.baseAddress!), UnsafeMutablePointer(mutating: environment.baseAddress!))
        } }
        guard result == 0, launched > 0 else { throw LayoutError.invalidPath }
        pid = launched
    }

    func hasExited() -> Bool {
        if reaped { return true }
        var information = siginfo_t()
        if waitid(P_PID, id_t(pid), &information, WEXITED | WNOHANG | WNOWAIT) == 0 {
            return information.si_pid == pid
        }
        return errno == ECHILD
    }

    func stop() {
        let until = Date().addingTimeInterval(5)
        while !hasExited() && Date() < until { Thread.sleep(forTimeInterval: 0.05) }
        cleanGroup()
    }

    func cleanGroup() {
        guard pid > 0 else { return }
        // waitid(WNOWAIT) proves this is still our unreaped child and reserves its PID.
        // macOS getpgid can return ESRCH for a zombie while its SSH descendants remain alive.
        var information = siginfo_t()
        if !reaped && waitid(P_PID, id_t(pid), &information, WEXITED | WNOHANG | WNOWAIT) == 0 {
            _ = kill(-pid, SIGTERM)
            Thread.sleep(forTimeInterval: 0.1)
            _ = kill(-pid, SIGKILL)
        }
        if !reaped { var status: Int32 = 0; if waitpid(pid, &status, 0) == pid { reaped = true } }
    }
}

final class ServiceHost {
    let layout: LaunchLayout
    private var backend: OwnedChild?
    private var hostLock: Int32 = -1
    private var shouldKeepRunning = true
    private var restartCount = 0
    private var restartWindow = Date()
    private var hostSocket: URL { layout.runtimeDir.appendingPathComponent("host.sock") }
    private var backendSocket: URL { layout.runtimeDir.appendingPathComponent("control.sock") }
    private var lockFile: URL { layout.runtimeDir.appendingPathComponent("host.lock") }

    init(layout: LaunchLayout) { self.layout = layout }

    func run() throws {
        try layout.validateStorage()
        try makePrivateDirectory(layout.runtimeDir)
        try makePrivateDirectory(layout.dataDir)
        try acquireLock()
        removeSocketIfSafe(hostSocket)
        let listener = try UnixListener(path: hostSocket.path)
        guard chmod(hostSocket.path, 0o600) == 0 else { throw LayoutError.invalidPath }
        defer { listener.close(); removeSocketIfSafe(hostSocket); releaseLock() }
        try startBackend()
        while shouldKeepRunning {
            if let request = listener.accept(timeout: 1) {
                let response = handle(request)
                request.reply(response)
                request.close()
            }
            if let process = backend, process.hasExited(), shouldKeepRunning {
                process.cleanGroup()
                if Date().timeIntervalSince(restartWindow) > 300 { restartWindow = Date(); restartCount = 0 }
                if restartCount < 5 {
                    let delay = min(30.0, pow(2.0, Double(restartCount)))
                    restartCount += 1
                    Thread.sleep(forTimeInterval: delay)
                    do { try startBackend(recover: true) } catch { shouldKeepRunning = false }
                } else {
                    shouldKeepRunning = false
                }
            }
        }
        stopBackend()
    }

    private func acquireLock() throws {
        hostLock = open(lockFile.path, O_CREAT | O_RDWR | O_NOFOLLOW, 0o600)
        guard hostLock >= 0 else { throw LayoutError.invalidPath }
        if flock(hostLock, LOCK_EX | LOCK_NB) != 0 { Darwin.close(hostLock); hostLock = -1; throw LayoutError.invalidPath }
    }

    private func startBackend(recover: Bool = false) throws {
        try layout.validateStorage()
        guard FileManager.default.isExecutableFile(atPath: layout.backend.path) else { throw LayoutError.invalidPath }
        var arguments = ["--data-dir", layout.dataDir.path, "--runtime-dir", layout.runtimeDir.path,
                         "--web-dir", layout.web.path, "--port", "0", "--tinyproxy-executable", layout.tinyproxy.path,
                         "--watch-parent", "--expected-parent", String(getpid())]
        if recover { arguments.append("--recover-owned-state") }
        backend = try OwnedChild(executable: layout.backend.path, arguments: arguments, projectRoot: layout.projectRoot)
        recordEvent("backend_started")
    }

    private func stopBackend() {
        guard let child = backend else { return }
        shouldKeepRunning = false
        _ = readJSONSocket(backendSocket.path, line: "{\"command\":\"shutdown\"}\n")
        child.stop()
        backend = nil
        recordEvent("backend_stopped")
    }

    private func recordEvent(_ event: String) {
        guard (try? layout.validateStorage()) != nil else { return }
        let path = layout.runtimeDir.appendingPathComponent("servicehost.log")
        guard !isSymlink(path.path) else { return }
        if let attributes = try? FileManager.default.attributesOfItem(atPath: path.path),
           let size = attributes[.size] as? Int, size > 524288 { try? FileManager.default.removeItem(at: path) }
        let fd = open(path.path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { return }
        defer { Darwin.close(fd) }
        let line = "\(ISO8601DateFormatter().string(from: Date())) \(event)\n"
        _ = line.utf8.withContiguousStorageIfAvailable { Darwin.write(fd, $0.baseAddress, $0.count) }
    }

    private func handle(_ request: UnixRequest) -> [String: Any] {
        guard request.uid == getuid() else { return ["error": "FORBIDDEN"] }
        switch request.command {
        case "ticket":
            guard let reply = readJSONSocket(backendSocket.path, line: "{\"command\":\"ticket\"}\n") else {
                return ["error": "BACKEND_UNAVAILABLE"]
            }
            return reply
        case "status":
            return ["alive": true, "backend_alive": !(backend?.hasExited() ?? true), "pid": getpid()]
        case "shutdown":
            shouldKeepRunning = false
            return ["stopping": true]
        default:
            return ["error": "UNKNOWN_COMMAND"]
        }
    }

    private func releaseLock() {
        if hostLock >= 0 { flock(hostLock, LOCK_UN); Darwin.close(hostLock); hostLock = -1 }
    }
}

final class TunnelManagerApplication: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem!
    private var serviceProcess: Process?
    private var layout: LaunchLayout!
    private var storageAccess: StorageAccess?
    private var hostSocket: URL { layout.runtimeDir.appendingPathComponent("host.sock") }

    func applicationDidFinishLaunching(_ notification: Notification) {
        do {
            layout = try LaunchLayout()
            try requestStorageAccess()
            try makePrivateDirectory(layout.runtimeDir)
            try startHostIfNeeded()
            buildMenu()
            DispatchQueue.global().async { [weak self] in self?.openConsoleWhenReady() }
        } catch {
            showError("无法启动 Tunnel Manager。请确认项目所在外接磁盘已挂载，且项目路径没有变化。")
            NSApp.terminate(nil)
        }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        openConsole()
        return true
    }

    private func startHostIfNeeded() throws {
        if readJSONSocket(hostSocket.path, line: "{\"command\":\"status\"}\n") != nil { return }
        let p = Process()
        p.executableURL = Bundle.main.executableURL
        let accessPipe = Pipe()
        p.arguments = ["--service-host", "--storage-access-stdin"]
        p.standardInput = accessPipe
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try p.run()
        guard let bookmark = storageAccess?.bookmark, bookmark.count <= 65536 else { p.terminate(); throw LayoutError.invalidPath }
        accessPipe.fileHandleForWriting.write(bookmark)
        try accessPipe.fileHandleForWriting.close()
        serviceProcess = p
    }

    private func requestStorageAccess() throws {
        let bookmarkFile = layout.runtimeDir.appendingPathComponent("storage-access.bookmark")
        if let saved = readPrivateBookmark(bookmarkFile),
           let access = try? StorageAccess(bookmark: saved, layout: layout) {
            storageAccess = access
            return
        }
        let panel = NSOpenPanel()
        panel.title = "授权访问 Tunnel Manager 项目目录"
        panel.message = "项目位于桌面和外接磁盘。请选择当前项目目录，让应用保存本项目配置并运行后台服务。应用不会访问或修改其他项目。"
        panel.prompt = "授权此项目目录"
        panel.directoryURL = layout.projectRoot
        panel.canChooseDirectories = true; panel.canChooseFiles = false
        panel.allowsMultipleSelection = false; panel.canCreateDirectories = false
        guard panel.runModal() == .OK, let selected = panel.url,
              selected.standardizedFileURL.path == layout.projectRoot.path,
              selected.resolvingSymlinksInPath().path == layout.projectRoot.path else { throw LayoutError.invalidPath }
        let bookmark: Data
        do {
            bookmark = try selected.bookmarkData(options: [.withSecurityScope], includingResourceValuesForKeys: nil, relativeTo: nil)
        } catch {
            bookmark = try selected.bookmarkData(options: [.minimalBookmark], includingResourceValuesForKeys: nil, relativeTo: nil)
        }
        storageAccess = try StorageAccess(bookmark: bookmark, layout: layout)
        try makePrivateDirectory(layout.runtimeDir)
        let staging = layout.runtimeDir.appendingPathComponent("storage-access-\(UUID().uuidString).pending")
        let fd = open(staging.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw LayoutError.invalidPath }
        defer { Darwin.close(fd); unlink(staging.path) }
        var metadata = stat()
        guard fstat(fd, &metadata) == 0, metadata.st_uid == getuid(), metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_nlink == 1, fchmod(fd, 0o600) == 0 else { throw LayoutError.invalidPath }
        guard bookmark.withUnsafeBytes({ Darwin.write(fd, $0.baseAddress, bookmark.count) }) == bookmark.count else { throw LayoutError.invalidPath }
        guard fsync(fd) == 0, rename(staging.path, bookmarkFile.path) == 0 else { throw LayoutError.invalidPath }
    }

    private func openConsoleWhenReady() {
        for _ in 0..<60 {
            if let reply = readJSONSocket(hostSocket.path, line: "{\"command\":\"ticket\"}\n"),
               let ticket = reply["ticket"] as? String, let port = reply["port"] as? Int {
                let url = URL(string: "http://127.0.0.1:\(port)/#ticket=\(ticket.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? ticket)")!
                DispatchQueue.main.async { NSWorkspace.shared.open(url) }
                return
            }
            Thread.sleep(forTimeInterval: 0.25)
        }
        DispatchQueue.main.async {
            // This Process handle belongs only to the host created by this launcher.
            // A host blocked by OS storage authorization must not become an unknown orphan.
            if let started = self.serviceProcess, started.isRunning,
               readJSONSocket(self.hostSocket.path, line: "{\"command\":\"status\"}\n") == nil {
                started.terminate()
                self.serviceProcess = nil
            }
            self.showError("本地后台服务未能及时启动。若 macOS 请求桌面或外接磁盘访问，请允许本应用访问项目目录；否则请检查诊断日志后重试。")
        }
    }

    private func buildMenu() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.title = "Tunnel Manager"
        let menu = NSMenu()
        menu.addItem(withTitle: "打开控制台", action: #selector(openConsole), keyEquivalent: "o")
        menu.addItem(.separator())
        menu.addItem(withTitle: "启用登录自动启动", action: #selector(registerLoginItem), keyEquivalent: "")
        menu.addItem(withTitle: "关闭登录自动启动", action: #selector(unregisterLoginItem), keyEquivalent: "")
        menu.addItem(.separator())
        menu.addItem(withTitle: "安装或更新项目内应用", action: #selector(installProjectCopy), keyEquivalent: "")
        menu.addItem(withTitle: "卸载项目内应用", action: #selector(uninstallProjectCopy), keyEquivalent: "")
        menu.addItem(.separator())
        menu.addItem(withTitle: "停止后台服务", action: #selector(stopService), keyEquivalent: "")
        menu.addItem(withTitle: "退出菜单栏（保留后台）", action: #selector(quit), keyEquivalent: "q")
        menu.items.forEach { $0.target = self }
        statusItem.menu = menu
    }

    @objc private func openConsole() {
        do {
            try layout.validateStorage()
            if storageAccess == nil { try requestStorageAccess() }
            try startHostIfNeeded()
            DispatchQueue.global().async { [weak self] in self?.openConsoleWhenReady() }
        } catch { showError("无法打开控制台。请确认项目磁盘已挂载，再重试启动本地后台服务。") }
    }
    @objc private func registerLoginItem() {
        do { try SMAppService.agent(plistName: "com.tunnelmanager.service.plist").register() }
        catch { showError("未能启用登录自动启动。请在系统设置的“登录项”中检查 Tunnel Manager 的授权。") }
    }
    @objc private func unregisterLoginItem() {
        do { try SMAppService.agent(plistName: "com.tunnelmanager.service.plist").unregister() }
        catch { showError("未能关闭登录自动启动。请在系统设置的“登录项”中检查 Tunnel Manager。") }
    }
    @objc private func stopService() {
        do {
            let service = SMAppService.agent(plistName: "com.tunnelmanager.service.plist")
            if service.status == .enabled || service.status == .requiresApproval { try service.unregister() }
            _ = readJSONSocket(hostSocket.path, line: "{\"command\":\"shutdown\"}\n")
        } catch { showError("未能停止后台服务：本应用的登录项尚未成功关闭。请检查系统设置后重试。") }
    }
    @objc private func installProjectCopy() { packagingAction("--package-install", message: "安装或更新项目目录中的应用副本？请先停止后台服务并关闭本应用的登录自动启动。用户数据和现有代理服务将保留。") }
    @objc private func uninstallProjectCopy() { packagingAction("--package-uninstall", message: "卸载项目目录中的已安装副本并停止其后台服务？用户数据、回滚副本和现有代理服务将保留。请先关闭本应用的登录自动启动。") }
    private func packagingAction(_ action: String, message: String) {
        let alert = NSAlert(); alert.messageText = message
        alert.addButton(withTitle: "继续"); alert.addButton(withTitle: "取消")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        DispatchQueue.global().async {
            let process = Process(); let output = Pipe()
            process.executableURL = self.layout.backend; process.arguments = [action]
            process.standardOutput = output; process.standardError = output
            do {
                try process.run()
                let data = output.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                let result = String(data: data, encoding: .utf8) ?? ""
                DispatchQueue.main.async { self.showError(process.terminationStatus == 0 ? "项目内应用操作已完成。用户数据已保留。" : result) }
            } catch { DispatchQueue.main.async { self.showError("项目内应用操作未完成。请检查磁盘访问和诊断日志。") } }
        }
    }
    @objc private func quit() { NSApp.terminate(nil) }

    private func showError(_ message: String) { let alert = NSAlert(); alert.messageText = message; alert.addButton(withTitle: "确定"); alert.runModal() }
}

struct UnixRequest {
    let fd: Int32
    let uid: uid_t
    let command: String
    func reply(_ object: [String: Any]) { if var data = try? JSONSerialization.data(withJSONObject: object) { data.append(10); _ = data.withUnsafeBytes { Darwin.send(fd, $0.baseAddress, data.count, 0) } } }
    func close() { Darwin.close(fd) }
}

final class UnixListener {
    private let fd: Int32
    init(path: String) throws {
        fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw LayoutError.invalidPath }
        var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8) + [0]
        guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else { Darwin.close(fd); throw LayoutError.invalidPath }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
        let size = socklen_t(MemoryLayout<sockaddr_un>.offset(of: \sockaddr_un.sun_path)! + bytes.count)
        if bind(fd, withUnsafePointer(to: &address) { UnsafeRawPointer($0).assumingMemoryBound(to: sockaddr.self) }, size) != 0 || Darwin.listen(fd, 8) != 0 { Darwin.close(fd); throw LayoutError.invalidPath }
    }
    func accept(timeout: TimeInterval) -> UnixRequest? {
        var pollfd = Darwin.pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        guard Darwin.poll(&pollfd, 1, Int32(timeout * 1000)) > 0 else { return nil }
        let child = Darwin.accept(fd, nil, nil); guard child >= 0 else { return nil }
        configureSocket(child)
        var uid: uid_t = 0; var gid: gid_t = 0
        guard getpeereid(child, &uid, &gid) == 0 else { Darwin.close(child); return nil }
        var data = Data(); var buffer = [UInt8](repeating: 0, count: 2048)
        while data.count < 2048 { let count = Darwin.read(child, &buffer, buffer.count); if count <= 0 { break }; data.append(buffer, count: count); if buffer[..<count].contains(10) { break } }
        let line = String(data: data, encoding: .utf8) ?? "{}"
        let object = (try? JSONSerialization.jsonObject(with: Data(line.utf8))) as? [String: Any]
        return UnixRequest(fd: child, uid: uid, command: object?["command"] as? String ?? "")
    }
    func close() { Darwin.close(fd) }
}

func readJSONSocket(_ path: String, line: String) -> [String: Any]? {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0); guard fd >= 0 else { return nil }
    defer { Darwin.close(fd) }
    configureSocket(fd)
    var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX)
    let bytes = Array(path.utf8) + [0]; guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else { return nil }
    withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
    let size = socklen_t(MemoryLayout<sockaddr_un>.offset(of: \sockaddr_un.sun_path)! + bytes.count)
    guard connect(fd, withUnsafePointer(to: &address) { UnsafeRawPointer($0).assumingMemoryBound(to: sockaddr.self) }, size) == 0 else { return nil }
    var uid: uid_t = 0; var gid: gid_t = 0
    guard getpeereid(fd, &uid, &gid) == 0, uid == getuid() else { return nil }
    _ = line.utf8.withContiguousStorageIfAvailable { Darwin.write(fd, $0.baseAddress, $0.count) }
    var data = Data(); var buffer = [UInt8](repeating: 0, count: 4096)
    while data.count < 4096 { let count = Darwin.read(fd, &buffer, buffer.count); if count <= 0 { break }; data.append(buffer, count: count); if buffer[..<count].contains(10) { break } }
    return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
}

func configureSocket(_ fd: Int32) {
    var timeout = timeval(tv_sec: 2, tv_usec: 0)
    var enabled: Int32 = 1
    _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size))
}
func isSymlink(_ path: String) -> Bool { var metadata = stat(); return lstat(path, &metadata) == 0 && metadata.st_mode & S_IFMT == S_IFLNK }
func readPrivateBookmark(_ url: URL) -> Data? {
    let fd = open(url.path, O_RDONLY | O_NOFOLLOW)
    guard fd >= 0 else { return nil }
    defer { Darwin.close(fd) }
    var metadata = stat()
    guard fstat(fd, &metadata) == 0, metadata.st_uid == getuid(), metadata.st_mode & S_IFMT == S_IFREG,
          metadata.st_nlink == 1, metadata.st_mode & 0o777 == 0o600, metadata.st_size > 0, metadata.st_size <= 65536 else { return nil }
    var buffer = [UInt8](repeating: 0, count: Int(metadata.st_size))
    let count = Darwin.read(fd, &buffer, buffer.count)
    guard count == buffer.count else { return nil }
    return Data(buffer)
}
func rejectSymlinkAncestors(_ url: URL) throws {
    var current = url
    while current.path != "/" { if isSymlink(current.path) { throw LayoutError.invalidPath }; current.deleteLastPathComponent() }
}
func makePrivateDirectory(_ url: URL) throws {
    try rejectSymlinkAncestors(url)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    var metadata = stat(); guard lstat(url.path, &metadata) == 0, metadata.st_uid == getuid(), metadata.st_mode & S_IFMT == S_IFDIR else { throw LayoutError.invalidPath }
    if metadata.st_mode & 0o777 != 0o700 {
        guard chmod(url.path, 0o700) == 0 else { throw LayoutError.invalidPath }
    }
}
func removeSocketIfSafe(_ url: URL) { var statbuf = stat(); guard lstat(url.path, &statbuf) == 0 else { return }; if statbuf.st_uid == getuid(), (statbuf.st_mode & S_IFMT) == S_IFSOCK { unlink(url.path) } }

func argument(_ flag: String) -> String? {
    let args = CommandLine.arguments
    guard let index = args.firstIndex(of: flag), index + 1 < args.count else { return nil }
    return args[index + 1]
}

if CommandLine.arguments.contains("--service-host") {
    do {
        let layout = try LaunchLayout(dataOverride: argument("--data-dir"), runtimeOverride: argument("--runtime-dir"))
        var access: StorageAccess?
        if CommandLine.arguments.contains("--storage-access-stdin") {
            guard let bookmark = try FileHandle.standardInput.read(upToCount: 65537), !bookmark.isEmpty, bookmark.count <= 65536 else { throw LayoutError.invalidPath }
            access = try StorageAccess(bookmark: bookmark, layout: layout)
        } else if argument("--runtime-dir") == nil,
                  let saved = readPrivateBookmark(layout.runtimeDir.appendingPathComponent("storage-access.bookmark")) {
            access = try StorageAccess(bookmark: saved, layout: layout)
        }
        try withExtendedLifetime(access) { try ServiceHost(layout: layout).run() }
    } catch { exit(78) }
} else if CommandLine.arguments.contains("--service-status") || CommandLine.arguments.contains("--stop-service") {
    do {
        let layout = try LaunchLayout(dataOverride: argument("--data-dir"), runtimeOverride: argument("--runtime-dir"))
        let command = CommandLine.arguments.contains("--stop-service") ? "shutdown" : "status"
        guard let result = readJSONSocket(layout.runtimeDir.appendingPathComponent("host.sock").path, line: "{\"command\":\"\(command)\"}\n"),
              let data = try? JSONSerialization.data(withJSONObject: result) else { exit(1) }
        print(String(data: data, encoding: .utf8) ?? "{}"); exit(0)
    } catch { exit(78) }
} else if CommandLine.arguments.contains("--login-status") {
    let service = SMAppService.agent(plistName: "com.tunnelmanager.service.plist")
    let statuses: [SMAppService.Status: String] = [.notRegistered: "not_registered", .enabled: "enabled", .requiresApproval: "requires_approval", .notFound: "not_found"]
    let result = ["status": statuses[service.status] ?? "unknown"]
    if let data = try? JSONSerialization.data(withJSONObject: result) { print(String(data: data, encoding: .utf8)!) }
} else if CommandLine.arguments.contains("--unregister-login") {
    do { try SMAppService.agent(plistName: "com.tunnelmanager.service.plist").unregister() } catch { exit(1) }
} else {
    let app = NSApplication.shared; let delegate = TunnelManagerApplication(); app.delegate = delegate; app.setActivationPolicy(.accessory); app.run()
}
