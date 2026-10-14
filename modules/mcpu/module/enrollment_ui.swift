import AppKit
import Darwin
import Foundation

struct PromptIdentity: Decodable {
    let pid: UInt32
    let pid_version: UInt32
    let start_seconds: UInt64
    let start_microseconds: UInt64
    let executable: String
    let user_id: UInt32
    let fingerprint: String
    let code_directory_hash: String
}

struct Prompt: Decodable {
    let request_id: String
    let identity: PromptIdentity
    let name: String
    let cpu_percent: Double
    let memory_bytes: UInt64
    let reason: String
    let observed_at: String
    let default_timer_minutes: UInt64
}

struct Reply: Encodable, Equatable {
    let request_id: String
    let canonical_path: String
    let fingerprint: String
    let decision: String
    let timer_minutes: UInt64?
}

struct Acknowledgement: Decodable, Equatable {
    let request_id: String
    let canonical_path: String
    let fingerprint: String
    let decision: String?
    let timer_minutes: UInt64?
    let accepted: Bool
    let message: String?
}

enum ReplyPollResult: Equatable {
    case idle
    case waiting
    case accepted
    case rejected(String)
}

struct ReplyTracker {
    private(set) var pending: Reply?

    mutating func submit(_ reply: Reply) {
        guard pending == nil else { return }
        pending = reply
    }

    mutating func poll(_ acknowledgement: Acknowledgement?) -> ReplyPollResult {
        guard let pending else { return .idle }
        guard let acknowledgement,
              acknowledgement.request_id == pending.request_id,
              acknowledgement.canonical_path == pending.canonical_path,
              acknowledgement.fingerprint == pending.fingerprint else {
            return .waiting
        }

        if acknowledgement.accepted {
            guard acknowledgement.decision == pending.decision,
                  acknowledgement.timer_minutes == pending.timer_minutes else {
                return .waiting
            }
            self.pending = nil
            return .accepted
        }

        self.pending = nil
        return .rejected(
            acknowledgement.message ?? "The choice was not saved. Choose Add or Exclude again."
        )
    }
}

struct Heartbeat: Encodable {
    let request_id: String
    let pid: UInt32
    let unix_millis: Int64
}

final class PersistentEnrollmentWindow: NSWindow, NSWindowDelegate {
    override func cancelOperation(_ sender: Any?) {}

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        false
    }
}

final class EnrollmentApplicationDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        .terminateCancel
    }

    func applicationDidHide(_ notification: Notification) {
        let app = NSApplication.shared
        app.unhide(nil)
        app.activate(ignoringOtherApps: true)
        app.windows
            .first(where: { $0 is PersistentEnrollmentWindow })?
            .makeKeyAndOrderFront(nil)
    }
}

final class EnrollmentController: NSObject {
    private let prompt: Prompt
    private let responsePath: String
    private let acknowledgementPath: String
    private let heartbeatPath: String
    private let window: PersistentEnrollmentWindow
    private let timerField: NSTextField
    private let message = NSTextField(labelWithString: "")
    private var addButton: NSButton?
    private var excludeButton: NSButton?
    private var replyTracker = ReplyTracker()
    private var heartbeatTicks = 0

    init(prompt: Prompt, responsePath: String, acknowledgementPath: String, heartbeatPath: String) {
        self.prompt = prompt
        self.responsePath = responsePath
        self.acknowledgementPath = acknowledgementPath
        self.heartbeatPath = heartbeatPath
        self.timerField = NSTextField(string: String(prompt.default_timer_minutes))
        self.window = PersistentEnrollmentWindow(
            contentRect: NSRect(x: 0, y: 0, width: 720, height: 520),
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        super.init()
        buildWindow()
    }

    func present() {
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApplication.shared.activate(ignoringOtherApps: true)
        writeHeartbeat()
        let heartbeatTimer = Timer(timeInterval: 1, repeats: true) { [weak self] _ in
            self?.pulse()
        }
        // The modal loop and window dragging use separate AppKit run-loop modes.
        RunLoop.main.add(heartbeatTimer, forMode: .modalPanel)
        RunLoop.main.add(heartbeatTimer, forMode: .eventTracking)
        let _ = NSApplication.shared.runModal(for: window)
        heartbeatTimer.invalidate()
        window.orderOut(nil)
    }

    private func pulse() {
        heartbeatTicks += 1
        if heartbeatTicks >= 5 {
            heartbeatTicks = 0
            writeHeartbeat()
        }
        guard replyTracker.pending != nil else {
            return
        }
        let acknowledgement = (try? Data(contentsOf: URL(fileURLWithPath: acknowledgementPath)))
            .flatMap { try? JSONDecoder().decode(Acknowledgement.self, from: $0) }
        switch replyTracker.poll(acknowledgement) {
        case .accepted:
            try? FileManager.default.removeItem(atPath: acknowledgementPath)
            NSApplication.shared.stopModal(withCode: .OK)
        case .rejected(let rejection):
            try? FileManager.default.removeItem(atPath: acknowledgementPath)
            addButton?.isEnabled = true
            excludeButton?.isEnabled = true
            timerField.isEnabled = true
            message.textColor = .systemRed
            message.stringValue = rejection
        case .idle, .waiting:
            break
        }
    }

    private func writeHeartbeat() {
        let heartbeat = Heartbeat(
            request_id: prompt.request_id,
            pid: UInt32(getpid()),
            unix_millis: Int64(Date().timeIntervalSince1970 * 1000)
        )
        do {
            try writeAtomically(heartbeat, to: heartbeatPath)
        } catch {
            fputs("mcpu enrollment heartbeat failed: \(error)\n", stderr)
        }
    }

    private func buildWindow() {
        window.title = "CPU Tool Enrollment"
        window.isReleasedWhenClosed = false
        window.delegate = window
        window.isMovableByWindowBackground = true
        window.canHide = false
        for button in [NSWindow.ButtonType.closeButton, .miniaturizeButton, .zoomButton] {
            window.standardWindowButton(button)?.isHidden = true
        }

        guard let content = window.contentView else { return }
        let title = NSTextField(labelWithString: "Choose how scriptd should handle this high-CPU tool")
        title.font = .boldSystemFont(ofSize: 17)
        title.frame = NSRect(x: 24, y: 470, width: 672, height: 28)
        content.addSubview(title)

        let details = NSTextView(frame: NSRect(x: 8, y: 8, width: 656, height: 208))
        details.isEditable = false
        details.isSelectable = true
        details.drawsBackground = false
        details.font = .systemFont(ofSize: 13)
        details.string = """
        Tool: \(prompt.name)
        Executable: \(prompt.identity.executable)
        Observed CPU: \(String(format: "%.1f", prompt.cpu_percent))%
        Resident memory: \(ByteCountFormatter.string(fromByteCount: Int64(clamping: prompt.memory_bytes), countStyle: .memory))
        Observed at: \(prompt.observed_at)
        Observed ownership: \(prompt.reason)
        """
        let scroll = NSScrollView(frame: NSRect(x: 24, y: 224, width: 672, height: 226))
        scroll.borderType = .bezelBorder
        scroll.hasVerticalScroller = true
        scroll.documentView = details
        content.addSubview(scroll)

        let timerLabel = NSTextField(labelWithString: "Cleanup timer (minutes)")
        timerLabel.frame = NSRect(x: 24, y: 170, width: 210, height: 24)
        content.addSubview(timerLabel)

        timerField.frame = NSRect(x: 230, y: 166, width: 130, height: 30)
        timerField.alignment = .right
        timerField.placeholderString = String(prompt.default_timer_minutes)
        timerField.setAccessibilityLabel("Cleanup timer in minutes")
        content.addSubview(timerField)

        let help = NSTextField(labelWithString: "Add starts a fresh CPU monitoring period after you approve.")
        help.textColor = .secondaryLabelColor
        help.frame = NSRect(x: 24, y: 132, width: 672, height: 24)
        content.addSubview(help)

        message.textColor = .systemRed
        message.frame = NSRect(x: 24, y: 96, width: 672, height: 24)
        content.addSubview(message)

        let exclude = NSButton(title: "Exclude", target: self, action: #selector(excludeTool))
        exclude.bezelStyle = .rounded
        exclude.frame = NSRect(x: 568, y: 28, width: 128, height: 34)
        exclude.keyEquivalent = ""
        exclude.setAccessibilityLabel("Exclude this executable from CPU cleanup")
        content.addSubview(exclude)
        excludeButton = exclude

        let add = NSButton(title: "Add", target: self, action: #selector(addTool))
        add.bezelStyle = .rounded
        add.frame = NSRect(x: 424, y: 28, width: 128, height: 34)
        add.keyEquivalent = ""
        add.setAccessibilityLabel("Add this executable with the entered cleanup timer")
        content.addSubview(add)
        addButton = add
    }

    @objc private func addTool() {
        let raw = timerField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !raw.isEmpty, raw.allSatisfy(\.isNumber),
              let minutes = UInt64(raw), (UInt64(1)...UInt64(525_600)).contains(minutes) else {
            message.stringValue = "Enter a whole number from 1 to 525600 minutes."
            return
        }
        submit(decision: "add", minutes: minutes)
    }

    @objc private func excludeTool() {
        submit(decision: "exclude", minutes: nil)
    }

    private func submit(decision: String, minutes: UInt64?) {
        guard replyTracker.pending == nil else { return }
        let reply = Reply(
            request_id: prompt.request_id,
            canonical_path: prompt.identity.executable,
            fingerprint: prompt.identity.fingerprint,
            decision: decision,
            timer_minutes: minutes
        )
        do {
            try writeAtomically(reply, to: responsePath)
            replyTracker.submit(reply)
            addButton?.isEnabled = false
            excludeButton?.isEnabled = false
            timerField.isEnabled = false
            message.textColor = .secondaryLabelColor
            message.stringValue = "Saving your choice. This dialog will close after scriptd confirms it."
        } catch {
            message.stringValue = "Could not save your choice. The request is still pending; try again."
        }
    }
}

func acquireSingletonLock(_ path: String) -> Int32 {
    let descriptor = Darwin.open(
        path,
        O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW,
        S_IRUSR | S_IWUSR
    )
    guard descriptor >= 0 else { return -1 }
    guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
        Darwin.close(descriptor)
        return -1
    }
    return descriptor
}

func writeAtomically<T: Encodable>(_ value: T, to path: String) throws {
    let destination = URL(fileURLWithPath: path)
    let temporary = destination.appendingPathExtension("tmp.\(UUID().uuidString)")
    let bytes = try JSONEncoder().encode(value)
    let descriptor = Darwin.open(
        temporary.path,
        O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW,
        S_IRUSR | S_IWUSR
    )
    guard descriptor >= 0 else {
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }
    var succeeded = false
    defer {
        Darwin.close(descriptor)
        if !succeeded {
            try? FileManager.default.removeItem(at: temporary)
        }
    }

    try bytes.withUnsafeBytes { rawBuffer in
        guard let base = rawBuffer.baseAddress else { return }
        var written = 0
        while written < rawBuffer.count {
            let amount = Darwin.write(
                descriptor,
                base.advanced(by: written),
                rawBuffer.count - written
            )
            guard amount > 0 else {
                throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
            }
            written += amount
        }
    }
    guard fsync(descriptor) == 0 else {
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }
    guard rename(temporary.path, destination.path) == 0 else {
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }
    let directory = Darwin.open(
        destination.deletingLastPathComponent().path,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC
    )
    guard directory >= 0 else {
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }
    defer { Darwin.close(directory) }
    guard fsync(directory) == 0 else {
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }
    succeeded = true
}

#if MCPU_ENROLLMENT_TEST
@main
struct EnrollmentUITests {
    static func main() throws {
        let reply = Reply(
            request_id: String(repeating: "a", count: 64),
            canonical_path: "/opt/tools/trunk",
            fingerprint: String(repeating: "b", count: 64),
            decision: "add",
            timer_minutes: 30
        )
        var tracker = ReplyTracker()
        tracker.submit(reply)

        for acceptanceField in ["", ",\"accepted\":null", ",\"accepted\":\"true\""] {
            let malformedData = Data("""
            {"request_id":"\(reply.request_id)","canonical_path":"\(reply.canonical_path)","fingerprint":"\(reply.fingerprint)","decision":"add","timer_minutes":30\(acceptanceField)}
            """.utf8)
            let malformed = try? JSONDecoder().decode(Acknowledgement.self, from: malformedData)
            precondition(tracker.poll(malformed) == .waiting)
        }

        let accepted = Acknowledgement(
            request_id: reply.request_id,
            canonical_path: reply.canonical_path,
            fingerprint: reply.fingerprint,
            decision: reply.decision,
            timer_minutes: reply.timer_minutes,
            accepted: true,
            message: nil
        )
        precondition(tracker.poll(accepted) == .accepted)
        print("native enrollment acknowledgement tests passed")
    }
}
#else
@main
struct EnrollmentUI {
    static func main() {
        guard CommandLine.arguments.count == 6 else {
            exit(2)
        }
        let requestPath = CommandLine.arguments[1]
        let responsePath = CommandLine.arguments[2]
        let lockPath = CommandLine.arguments[3]
        let acknowledgementPath = CommandLine.arguments[4]
        let heartbeatPath = CommandLine.arguments[5]
        let lockDescriptor = acquireSingletonLock(lockPath)
        guard lockDescriptor >= 0 else {
            exit(0)
        }
        defer { Darwin.close(lockDescriptor) }

        do {
            let requestData = try Data(contentsOf: URL(fileURLWithPath: requestPath))
            let prompt = try JSONDecoder().decode(Prompt.self, from: requestData)
            let delegate = EnrollmentApplicationDelegate()
            let app = NSApplication.shared
            app.setActivationPolicy(.accessory)
            app.delegate = delegate
            app.finishLaunching()
            let controller = EnrollmentController(
                prompt: prompt,
                responsePath: responsePath,
                acknowledgementPath: acknowledgementPath,
                heartbeatPath: heartbeatPath
            )
            controller.present()
        } catch {
            fputs("mcpu enrollment UI failed: \(error)\n", stderr)
            exit(1)
        }
    }
}
#endif
