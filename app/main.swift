// Zeke — native macOS app for the local Zeke dashboard (see ../docs/SPEC.md).
// Window: the dashboard at http://127.0.0.1:47800 in a WKWebView.
// Dock badge + menu bar item: number of updates available, refreshed every minute.
// Build: ./build.sh
import Cocoa
import ServiceManagement
import WebKit

let baseURL = URL(string: "http://127.0.0.1:47800/")!
let stateURL = URL(string: "http://127.0.0.1:47800/api/state")!
let healthURL = URL(string: "http://127.0.0.1:47800/api/health")!
let planURL = URL(string: "http://127.0.0.1:47800/api/plan")!
// ZekeHome can be overridden with: defaults write io.github.edamuza.zeke ZekeHome /path
let zekeHome = UserDefaults.standard.string(forKey: "ZekeHome")
    ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".zeke").path
let tokenPath = (zekeHome as NSString).appendingPathComponent("data/token")
let serverLabel = "io.github.edamuza.zeke.server"

func readToken() -> String? {
    (try? String(contentsOfFile: tokenPath, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines)
}

func authed(_ url: URL, timeout: TimeInterval = 10) -> URLRequest {
    var r = URLRequest(url: url, timeoutInterval: timeout)
    if let t = readToken() { r.setValue(t, forHTTPHeaderField: "X-Token") }
    return r
}

struct Snapshot {
    var outdated = 0
    var unknown = 0
    var urgent = 0
    var review = 0
    var unknownChecks = 0
    var scanned: Date?
    var running: String?  // kind of the current run, if any
    var reachable = false
}

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate, WKNavigationDelegate, WKUIDelegate {
    var window: NSWindow!
    var web: WKWebView!
    var statusItem: NSStatusItem!
    var snap = Snapshot()
    var timer: Timer?
    var inFlight = false
    var fastPolling = false

    // MARK: launch
    func applicationDidFinishLaunching(_ note: Notification) {
        buildMainMenu()
        buildWindow()
        buildStatusItem()
        ensureServer { [weak self] ok in
            guard let self else { return }
            if ok { self.web.load(URLRequest(url: baseURL)) } else { self.showOffline() }
            self.refresh()
        }
        schedulePolling(fast: false)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ app: NSApplication) -> Bool { false }

    func applicationShouldHandleReopen(_ app: NSApplication, hasVisibleWindows: Bool) -> Bool {
        showWindow()
        return true
    }

    // MARK: window
    func buildWindow() {
        let cfg = WKWebViewConfiguration()
        if UserDefaults.standard.bool(forKey: "WebInspector") {
            cfg.preferences.setValue(true, forKey: "developerExtrasEnabled")
        }
        // The page carries no secret; the app hands it the API token directly (SPEC §6).
        if let t = readToken(),
           let json = try? JSONSerialization.data(withJSONObject: [t]),
           let arr = String(data: json, encoding: .utf8) {
            let js = "window.UC_TOKEN = \(arr)[0];"
            cfg.userContentController.addUserScript(
                WKUserScript(source: js, injectionTime: .atDocumentStart, forMainFrameOnly: true))
        }
        web = WKWebView(frame: .zero, configuration: cfg)
        web.navigationDelegate = self
        web.uiDelegate = self
        web.setValue(false, forKey: "drawsBackground")  // no white flash in dark mode
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1280, height: 860),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable],
                          backing: .buffered, defer: false)
        window.title = "Zeke"
        window.minSize = NSSize(width: 720, height: 480)
        window.isReleasedWhenClosed = false
        window.contentView = web
        window.center()
        window.setFrameAutosaveName("ZekeMain")
        window.makeKeyAndOrderFront(nil)
    }

    @objc func showWindow() {
        if web.url == nil || snap.reachable == false { reload() }
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc func reload() {
        ensureServer { [weak self] ok in
            guard let self else { return }
            if ok { self.web.load(URLRequest(url: baseURL)) } else { self.showOffline() }
        }
    }

    func showOffline() {
        let html = """
        <html><body style="font:14px -apple-system;display:grid;place-items:center;height:90vh;color:#888;background:transparent">
        <div style="text-align:center"><h2 style="color:#999">Zeke server isn't running</h2>
        <p>It normally starts at login (launchd job <code>\(serverLabel)</code>).</p>
        <p>Press <b>⌘R</b> to try again.</p></div></body></html>
        """
        web.loadHTMLString(html, baseURL: nil)
    }

    // Keep the window on the dashboard; open anything else in the default browser.
    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        if let url = action.request.url, url.scheme == "http" || url.scheme == "https",
           !(url.host == "127.0.0.1" && url.port == 47800) {
            if url.scheme == "https" { NSWorkspace.shared.open(url) }
            decisionHandler(.cancel)
            return
        }
        decisionHandler(.allow)
    }

    // target="_blank" links (advisories) open in the default browser, https only.
    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                 for action: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        if let url = action.request.url, url.scheme == "https" { NSWorkspace.shared.open(url) }
        return nil
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation nav: WKNavigation!, withError error: Error) {
        showOffline()
    }

    // MARK: server
    /// Ping the server; if it's down, ask launchd to start it and retry for ~10 s.
    func ensureServer(_ done: @escaping (Bool) -> Void) {
        ping { ok in
            if ok { return done(true) }
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
            p.arguments = ["kickstart", "gui/\(getuid())/\(serverLabel)"]
            try? p.run()
            self.retry(10, done)
        }
    }

    func retry(_ n: Int, _ done: @escaping (Bool) -> Void) {
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
            self.ping { ok in
                if ok || n <= 1 { done(ok) } else { self.retry(n - 1, done) }
            }
        }
    }

    func ping(_ done: @escaping (Bool) -> Void) {
        URLSession.shared.dataTask(with: URLRequest(url: healthURL, timeoutInterval: 2)) { data, _, _ in
            var ok = false
            if let data, let o = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                ok = (o["app"] as? String) == "zeke"
            }
            DispatchQueue.main.async { done(ok) }
        }.resume()
    }

    func post(_ path: String) {
        guard let token = readToken() else { return alert("Can't read the Zeke token.") }
        var req = URLRequest(url: URL(string: path, relativeTo: baseURL)!)
        req.httpMethod = "POST"
        req.setValue(token, forHTTPHeaderField: "X-Token")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = Data("{}".utf8)
        URLSession.shared.dataTask(with: req) { data, resp, _ in
            DispatchQueue.main.async {
                let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
                if code == 409 { self.alert("Another scan or update is already running.") }
                else if code >= 400 || code == 0 {
                    let msg = data.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }?["error"] as? String
                    self.alert(msg ?? "The Zeke server didn't respond.")
                }
                self.web.evaluateJavaScript("typeof load==='function'&&load()", completionHandler: nil)
                DispatchQueue.main.asyncAfter(deadline: .now() + 1) { self.inFlight = false; self.refresh() }
            }
        }.resume()
    }

    func alert(_ text: String) {
        let a = NSAlert()
        a.messageText = "Zeke"
        a.informativeText = text
        a.runModal()
    }

    // MARK: state → Dock badge + menu bar
    func schedulePolling(fast: Bool) {
        fastPolling = fast
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: fast ? 3 : 60, repeats: true) { [weak self] _ in self?.refresh() }
    }

    func refresh() {
        if inFlight { return }
        inFlight = true
        URLSession.shared.dataTask(with: authed(stateURL)) { data, _, _ in
            var s = Snapshot()
            if let data, let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                s.reachable = true
                let inv = obj["inventory"] as? [String: Any] ?? [:]
                let counts = inv["counts"] as? [String: Any] ?? [:]
                s.outdated = counts["outdated"] as? Int ?? 0
                s.unknown = counts["unknown"] as? Int ?? 0
                if let str = inv["scanned"] as? String { s.scanned = ISO8601DateFormatter().date(from: str) }
                s.running = (obj["current"] as? [String: Any])?["kind"] as? String
                let sec = (obj["security"] as? [String: Any])?["summary"] as? [String: Any] ?? [:]
                s.urgent = sec["urgent"] as? Int ?? 0
                s.review = sec["review"] as? Int ?? 0
                s.unknownChecks = sec["unknown_checks"] as? Int ?? 0
            }
            DispatchQueue.main.async {
                self.inFlight = false
                self.snap = s
                self.applySnapshot()
                let fast = s.running != nil
                if fast != self.fastPolling { self.schedulePolling(fast: fast) }
            }
        }.resume()
    }

    func applySnapshot() {
        // Dock badge: number of updates; a leading "!" when something urgent needs attention.
        let n = snap.outdated > 0 ? "\(snap.outdated)" : ""
        NSApp.dockTile.badgeLabel = snap.urgent > 0 ? "!" + n : (n.isEmpty ? nil : n)
        guard let button = statusItem.button else { return }
        var symbol: String
        var title = ""
        var red = false
        if !snap.reachable { symbol = "exclamationmark.circle" }
        else if snap.running != nil { symbol = "arrow.triangle.2.circlepath.circle.fill" }
        else if snap.urgent > 0 { symbol = "exclamationmark.shield.fill"; title = " \(snap.urgent)"; red = true }
        else if snap.outdated > 0 { symbol = "arrow.down.circle"; title = " \(snap.outdated)" }
        else if snap.unknownChecks > 0 { symbol = "questionmark.circle" }
        else { symbol = "checkmark.circle" }
        let img = NSImage(systemSymbolName: symbol, accessibilityDescription: "Zeke")
        if red, let img {
            let cfg = NSImage.SymbolConfiguration(paletteColors: [.systemRed])
            button.image = img.withSymbolConfiguration(cfg)
            button.image?.isTemplate = false
        } else {
            button.image = img
            button.image?.isTemplate = true
        }
        button.title = title
        button.imagePosition = .imageLeading
        button.toolTip = summary()
    }

    func summary() -> String {
        if !snap.reachable { return "Zeke server isn't running" }
        if let r = snap.running { return r == "scan" ? "Scanning…" : "Updating…" }
        var s = snap.outdated == 0 ? "Everything is up to date" : "\(snap.outdated) updates available"
        if snap.unknown > 0 { s += " · \(snap.unknown) can't tell" }
        return s
    }

    func securityLine() -> String {
        if snap.urgent > 0 { return "Security: \(snap.urgent) urgent, \(snap.review) to review" }
        if snap.review > 0 { return "Security: \(snap.review) to review" }
        return snap.unknownChecks > 0 ? "Security: nothing found · \(snap.unknownChecks) check(s) can't tell"
            : "Security: nothing needs attention"
    }

    // MARK: menus
    func buildStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        let menu = NSMenu()
        menu.delegate = self
        statusItem.menu = menu
        applySnapshot()
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        guard menu === statusItem.menu else { return }
        menu.removeAllItems()
        let head = NSMenuItem(title: summary(), action: nil, keyEquivalent: "")
        head.isEnabled = false
        menu.addItem(head)
        if let d = snap.scanned {
            let f = RelativeDateTimeFormatter()
            let sub = NSMenuItem(title: "Last scan " + f.localizedString(for: d, relativeTo: Date()), action: nil, keyEquivalent: "")
            sub.isEnabled = false
            menu.addItem(sub)
        }
        if snap.reachable { menu.addItem(item(securityLine(), #selector(showSecurity), "")) }
        menu.addItem(.separator())
        menu.addItem(item("Open Zeke", #selector(showWindow), "o"))
        let busy = snap.running != nil || !snap.reachable
        let scan = item("Scan Now", #selector(scanNow), "")
        let all = item("Update Everything", #selector(updateAll), "")
        scan.isEnabled = !busy
        all.isEnabled = !busy
        menu.addItem(scan)
        menu.addItem(all)
        menu.addItem(.separator())
        let login = item("Open at Login", #selector(toggleLogin), "")
        login.state = SMAppService.mainApp.status == .enabled ? .on : .off
        menu.addItem(login)
        menu.addItem(item("Quit Zeke", #selector(NSApplication.terminate(_:)), "q"))
    }

    func item(_ title: String, _ sel: Selector, _ key: String) -> NSMenuItem {
        let i = NSMenuItem(title: title, action: sel, keyEquivalent: key)
        i.target = sel == #selector(NSApplication.terminate(_:)) ? NSApp : self
        return i
    }

    @objc func scanNow() { post("api/scan") }

    @objc func showSecurity() {
        showWindow()
        web.evaluateJavaScript("typeof selectTab==='function'&&selectTab('sec')", completionHandler: nil)
    }

    /// Confirm text comes from the engine's plan, so it says exactly what will run.
    @objc func updateAll() {
        URLSession.shared.dataTask(with: authed(planURL)) { data, _, _ in
            var text = "Updates Homebrew, npm (both), Ruby gems, uv tools, Claude Code and opencode."
            if let data, let p = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                let sf = (p["security_first"] as? [String])?.count ?? 0
                let ot = (p["others"] as? [String])?.count ?? 0
                let held = (p["held"] as? [String])?.count ?? 0
                let skip = (p["skipped"] as? [String])?.count ?? 0
                let maj = (p["majors"] as? [String])?.count ?? 0
                text = "\(sf + ot) updates" + (sf > 0 ? " — \(sf) security fixes first" : "") +
                    (maj > 0 ? ", \(maj) major versions" : "") + ".\nLeft alone: \(held) on hold, \(skip) skipped, " +
                    "apps outside Homebrew, macOS and Python packages.\nProgress shows in Activity & logs."
            }
            DispatchQueue.main.async {
                let a = NSAlert()
                a.messageText = "Update everything?"
                a.informativeText = text
                a.addButton(withTitle: "Update")
                a.addButton(withTitle: "Cancel")
                if a.runModal() == .alertFirstButtonReturn { self.post("api/update-all") }
            }
        }.resume()
    }

    @objc func toggleLogin() {
        do {
            if SMAppService.mainApp.status == .enabled { try SMAppService.mainApp.unregister() }
            else { try SMAppService.mainApp.register() }
        } catch {
            alert("Couldn't change Open at Login: \(error.localizedDescription)\nYou can add it in System Settings → General → Login Items.")
        }
    }

    func buildMainMenu() {
        let main = NSMenu()
        func sub(_ title: String, _ items: [NSMenuItem]) {
            let top = NSMenuItem()
            let m = NSMenu(title: title)
            items.forEach(m.addItem)
            top.submenu = m
            main.addItem(top)
        }
        let quit = NSMenuItem(title: "Quit Zeke", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        let hide = NSMenuItem(title: "Hide Zeke", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        sub("Zeke", [hide, .separator(), quit])
        sub("Edit", [
            NSMenuItem(title: "Undo", action: Selector(("undo:")), keyEquivalent: "z"),
            NSMenuItem(title: "Redo", action: Selector(("redo:")), keyEquivalent: "Z"),
            .separator(),
            NSMenuItem(title: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x"),
            NSMenuItem(title: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c"),
            NSMenuItem(title: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v"),
            NSMenuItem(title: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a"),
        ])
        let reload = NSMenuItem(title: "Reload", action: #selector(reload), keyEquivalent: "r")
        reload.target = self
        let scan = NSMenuItem(title: "Scan Now", action: #selector(scanNow), keyEquivalent: "s")
        scan.keyEquivalentModifierMask = [.command, .shift]
        scan.target = self
        sub("View", [reload, scan])
        sub("Window", [
            NSMenuItem(title: "Minimize", action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m"),
            NSMenuItem(title: "Close", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w"),
        ])
        NSApp.mainMenu = main
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
