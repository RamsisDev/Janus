import LocalAuthentication
import SwiftUI

@main
struct JanusApp: App {
    @StateObject private var model: AppModel
    @StateObject private var lock = AppLock()

    init() {
        let model = AppModel()
        _model = StateObject(wrappedValue: model)
        #if os(iOS)
        Background.register(model)
        #endif
    }

    var body: some Scene {
        WindowGroup {
            RootView(lock: lock)
                .environmentObject(model)
        }
    }
}

/// The contacts, under a cover whenever the app is locked, leaves the screen (so the app
/// switcher's snapshot shows nothing) or the screen is being recorded or mirrored.
struct RootView: View {
    @ObservedObject var lock: AppLock
    @EnvironmentObject private var model: AppModel
    @Environment(\.scenePhase) private var scenePhase
    @State private var captured = false

    var body: some View {
        ContactsView()
            .overlay {
                if lock.locked || scenePhase != .active || captured {
                    CoverView(lock: lock)
                }
            }
            .task { await model.run() }
            // onChange skips the phase the app launches in.
            .onAppear { lock.ask() }
            .onChange(of: scenePhase) { _, phase in
                switch phase {
                case .active:
                    lock.ask()
                case .background:
                    lock.lock()
                    #if os(iOS)
                    Background.schedule()
                    #endif
                default:
                    break
                }
            }
            #if os(iOS)
            .onReceive(NotificationCenter.default.publisher(
                for: UIScreen.capturedDidChangeNotification)) { _ in
                captured = UIScreen.main.isCaptured
            }
            #endif
    }
}

struct CoverView: View {
    @ObservedObject var lock: AppLock

    var body: some View {
        ZStack {
            Rectangle().fill(.background)
            VStack(spacing: 24) {
                Image(systemName: "lock.fill").font(.largeTitle)
                if lock.locked {
                    Button("Unlock") { lock.unlock() }
                        .buttonStyle(.borderedProminent)
                }
            }
        }
        .ignoresSafeArea()
    }
}

/// Locks on every trip to the background and unlocks with the device's own authentication
/// (Face ID, Touch ID or the passcode).
@MainActor
final class AppLock: ObservableObject {
    @Published private(set) var locked = true
    /// Ask on the next return to the foreground; a cancelled prompt waits for the button.
    private var pending = true
    private var asking = false

    func lock() {
        locked = true
        pending = true
    }

    func ask() {
        if locked && pending {
            pending = false
            unlock()
        }
    }

    func unlock() {
        guard locked, !asking else { return }
        let context = LAContext()
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) else {
            // shortcut: a device without a passcode has nothing to unlock with, so the app opens;
            // upgrade to an app passphrase if the threat model needs one there.
            locked = false
            return
        }
        asking = true
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Unlock Janus") {
            ok, _ in
            Task { @MainActor in
                self.asking = false
                if ok {
                    self.locked = false
                }
            }
        }
    }
}
