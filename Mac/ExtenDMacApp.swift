import SwiftUI
import Combine
import ServiceManagement

/// Menu-bar only app (no Dock icon, LSUIElement): a status item whose popover holds the whole UI.
@main
struct ExtenDMacApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        Settings { EmptyView() }   // no windows; everything lives in the status item
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    private let model = AppModel()
    private var statusItem: NSStatusItem!
    private let popover = NSPopover()
    private var observers: Set<AnyCancellable> = []

    func applicationDidFinishLaunching(_ notification: Notification) {
        LoginItem.registerOnFirstLaunch()

        popover.behavior = .transient
        popover.contentViewController = NSHostingController(rootView: ContentView(model: model))

        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        statusItem.button?.target = self
        statusItem.button?.action = #selector(togglePopover)
        updateIcon()

        // The icon is the active-input indicator: dimmed = idle, ▶ badge = an iPad is connected and
        // may send input, ! badge = a pairing needs your answer.
        model.$isActive.combineLatest(model.$pairingRequest)
            .receive(on: RunLoop.main)
            .sink { [weak self] _, request in
                self?.updateIcon()
                // Show the prompt without activating the app, so it never takes keyboard focus.
                if request != nil, self?.popover.isShown == false { self?.showPopover() }
            }
            .store(in: &observers)
    }

    @objc private func togglePopover() {
        popover.isShown ? popover.performClose(nil) : showPopover()
    }

    private func showPopover() {
        guard let button = statusItem.button else { return }
        model.refreshPermissions()
        popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
    }

    private func updateIcon() {
        let (symbol, label, dimmed): (String, String, Bool) =
            model.pairingRequest != nil ? ("ipad.landscape.badge.exclamationmark", "ExtenD: pairing request", false)
            : model.isActive ? ("ipad.landscape.badge.play", "ExtenD: iPad connected", false)
            : ("ipad.landscape", "ExtenD: not connected", true)
        let image = NSImage(systemSymbolName: symbol, accessibilityDescription: label)
        image?.isTemplate = true
        statusItem.button?.image = image
        statusItem.button?.appearsDisabled = dimmed
        statusItem.button?.toolTip = label
    }
}

/// Launch at login via SMAppService (macOS 13+). Turned on once at first launch, as planned;
/// the user can switch it off in the menu or in System Settings → General → Login Items.
enum LoginItem {
    private static let offeredKey = "LoginItemRegisteredOnce"

    static var isEnabled: Bool { SMAppService.mainApp.status == .enabled }

    static func set(_ on: Bool) {
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
        } catch {
            NSLog("Login item change failed: \(error)")
        }
    }

    static func registerOnFirstLaunch() {
        guard !UserDefaults.standard.bool(forKey: offeredKey) else { return }
        UserDefaults.standard.set(true, forKey: offeredKey)
        set(true)
    }
}

struct ContentView: View {
    @ObservedObject var model: AppModel
    @State private var loginToggle = false

    static func describe(_ state: AppModel.AttachedDevice.State) -> String {
        switch state {
        case .waiting: return "Open ExtenD on the iPad"
        case .connecting: return "Connecting securely…"
        case .pairing: return "Waiting for pairing approval"
        case .connected: return "Paired · connected"
        case .notPaired: return "Not paired"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("ExtenD (USB)").font(.headline)
            Text(model.status).fixedSize(horizontal: false, vertical: true)

            if let request = model.pairingRequest {
                PairingPrompt(request: request) { model.decidePairing(request, accepted: $0) }
                    .id(request.id)   // fresh view (and fresh Accept delay) for every prompt
            }

            Divider()
            Label("Screen Recording", systemImage: model.hasScreenRecording ? "checkmark.circle.fill" : "xmark.circle")
            Label("Accessibility (input)", systemImage: model.hasAccessibility ? "checkmark.circle.fill" : "xmark.circle")
            HStack {
                Button("Open Privacy Settings") {
                    NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy")!)
                }
                Button("Recheck") { model.refreshPermissions() }
            }

            Divider()
            Text("Connected").font(.subheadline.weight(.semibold))
            if model.attached.isEmpty && model.wifiConnectedName == nil {
                Text("No iPad connected.").foregroundStyle(.secondary)
            }
            if let name = model.wifiConnectedName {
                HStack {
                    Image(systemName: "wifi").foregroundStyle(.secondary)
                    VStack(alignment: .leading) {
                        Text(name)
                        Text("Paired · connected over Wi-Fi").font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                }
            }
            ForEach(model.attached) { device in
                HStack {
                    Image(systemName: "cable.connector").foregroundStyle(.secondary)
                    VStack(alignment: .leading) {
                        Text(device.name)
                        Text(Self.describe(device.state)).font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if device.state == .notPaired {
                        Button("Pair…") { model.pair(device) }
                    }
                }
            }

            if model.wifiEnabled && !model.wifiAvailable.isEmpty {
                Divider()
                Text("Available on Wi-Fi").font(.subheadline.weight(.semibold))
                ForEach(model.wifiAvailable) { peer in
                    HStack {
                        Image(systemName: "wifi").foregroundStyle(.secondary)
                        VStack(alignment: .leading) {
                            Text(peer.name)
                            Text("Not paired").font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Pair…") { model.pair(peer) }
                    }
                }
            }

            Divider()
            Toggle("Connect over Wi-Fi (same network only)", isOn: Binding(get: { model.wifiEnabled },
                                                                          set: { model.setWiFi($0) }))
            Picker("Size on iPad", selection: Binding(get: { model.displayScale },
                                                      set: { model.setDisplayScale($0) })) {
                ForEach(AppModel.DisplayScale.allCases) { Text($0.label).tag($0) }
            }
            .pickerStyle(.segmented)
            .help("Larger makes buttons and text bigger and easier to touch. The image gets slightly softer.")

            Divider()
            Text("Paired iPads").font(.subheadline.weight(.semibold))
            if model.pairedDevices.isEmpty {
                Text("None yet. Connect an iPad to pair it.").foregroundStyle(.secondary)
            }
            ForEach(model.pairedDevices) { device in
                HStack {
                    VStack(alignment: .leading) {
                        Text(device.name)
                        Text(device.fingerprint).font(.caption.monospaced()).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Forget") { model.forget(device) }
                }
            }

            Divider()
            HStack {
                Toggle("Open at Login", isOn: Binding(get: { LoginItem.isEnabled },
                                                      set: { LoginItem.set($0); loginToggle.toggle() }))
                    .id(loginToggle)   // re-read SMAppService status after a change
                Spacer()
                Button("Quit ExtenD") { NSApp.terminate(nil) }
            }
        }
        .padding(16)
        .frame(width: 360)
    }
}

private struct PairingPrompt: View {
    let request: AppModel.PairingRequest
    let decide: (Bool) -> Void
    /// Accept is briefly disabled so a keystroke or click aimed elsewhere can't approve a pairing.
    @State private var armed = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Pair with “\(request.peerName)”?").font(.headline)
            Text("Only accept if the iPad shows the same code.").foregroundStyle(.secondary)
            Text(request.code)
                .font(.system(size: 34, weight: .semibold, design: .monospaced))
                .frame(maxWidth: .infinity)
                .accessibilityLabel("Pairing code \(request.code)")
            HStack {
                Button("Reject", role: .cancel) { decide(false) }
                Spacer()
                Button("Accept") { decide(true) }.disabled(!armed)   // deliberately no Return shortcut
            }
        }
        .padding(12)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
        .task {
            try? await Task.sleep(for: .milliseconds(1500))
            armed = true
        }
    }
}
