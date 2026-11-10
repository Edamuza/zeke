// zeke-apps — tiny helper the engine uses to see and politely quit apps (no Apple-events permission needed).
//   zeke-apps running <bundle-id>          exit 0 + pids if running, 1 if not
//   zeke-apps quit <bundle-id> [seconds]   ask the app to quit normally (it may show "save changes?");
//                                         exit 0 when gone, 2 if still running after the timeout
//   zeke-apps open <app-path>              open in the background without stealing focus
import AppKit

let args = CommandLine.arguments
func apps(_ bid: String) -> [NSRunningApplication] {
    NSRunningApplication.runningApplications(withBundleIdentifier: bid).filter { !$0.isTerminated }
}
guard args.count >= 3 else {
    FileHandle.standardError.write("usage: zeke-apps running|quit|open <arg>\n".data(using: .utf8)!)
    exit(64)
}
switch args[1] {
case "running":
    let a = apps(args[2])
    print(a.map { String($0.processIdentifier) }.joined(separator: " "))
    exit(a.isEmpty ? 1 : 0)
case "quit":
    let timeout = args.count > 3 ? Double(args[3]) ?? 60 : 60
    for a in apps(args[2]) { _ = a.terminate() }
    let end = Date().addingTimeInterval(timeout)
    while Date() < end {
        if apps(args[2]).isEmpty { exit(0) }
        RunLoop.current.run(until: Date().addingTimeInterval(0.5))
    }
    exit(apps(args[2]).isEmpty ? 0 : 2)
case "open":
    let cfg = NSWorkspace.OpenConfiguration()
    cfg.activates = false
    cfg.addsToRecentItems = false
    let sem = DispatchSemaphore(value: 0)
    var ok = false
    NSWorkspace.shared.openApplication(at: URL(fileURLWithPath: args[2]), configuration: cfg) { app, err in
        ok = (app != nil && err == nil)
        if let err { FileHandle.standardError.write("\(err.localizedDescription)\n".data(using: .utf8)!) }
        sem.signal()
    }
    while sem.wait(timeout: .now() + 0.1) == .timedOut { RunLoop.current.run(until: Date().addingTimeInterval(0.1)) }
    exit(ok ? 0 : 1)
default:
    exit(64)
}
