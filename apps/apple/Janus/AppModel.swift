import Foundation

/// The app's one `Client` and what the screens show. Every client call runs on one serial
/// queue, off the main thread, since any of them can wait on the network.
@MainActor
final class AppModel: ObservableObject {
    /// A's side of an invitation.
    enum Invitation: Equatable {
        /// Showing the 6 words until B answers.
        case waiting(words: String, network: String)
        /// B answered: the user types the 3 safety words B reads out.
        case answered
    }

    /// B's side of an invitation.
    enum Answer: Equatable {
        case looking
        /// Showing the safety words until A says they match.
        case joined(contact: String, safetyWords: String)
    }

    @Published private(set) var contacts: [Contact] = []
    @Published private(set) var networks: [NetworkInfo] = []
    @Published private(set) var histories: [String: [HistoryEntry]] = [:]
    @Published private(set) var unread: Set<String> = []
    @Published var invitation: Invitation?
    @Published var answer: Answer?
    /// Why the client could not open, or why the last tick failed.
    @Published private(set) var trouble: String?
    @Published private(set) var hardwareBacked = true
    /// The chat on screen, which reloads when a message arrives.
    var openChat: String?

    private var client: Client?
    private var opening: Task<Void, Never>?
    private let queue = DispatchQueue(label: "org.janusknot.janus.client")

    func open() async {
        if opening == nil {
            opening = Task { await start() }
        }
        await opening?.value
    }

    /// Ticks once a second for as long as the calling task runs.
    func run() async {
        await open()
        while !Task.isCancelled {
            await tick()
            try? await Task.sleep(nanoseconds: 1_000_000_000)
        }
    }

    /// A background wake-up, which iOS ends after about 30 seconds.
    func wake() async {
        await open()
        for _ in 0..<25 where !Task.isCancelled {
            await tick()
            try? await Task.sleep(nanoseconds: 1_000_000_000)
        }
    }

    func invite(network: String, hours: UInt8) async throws {
        let words = try await call { try $0.invite(network: network, intervalHours: hours) }
        let name = networks.first { $0.id == network }?.name ?? ""
        invitation = .waiting(words: words, network: name)
    }

    func verify(typed: String, name: String) async throws {
        _ = try await call { try $0.verify(typed: typed, name: name) }
        invitation = nil
        await refresh()
    }

    func join(network: String, words: String) async throws {
        try await call { try $0.join(network: network, words: words) }
        answer = .looking
    }

    func confirm(contact: String, name: String) async throws {
        try await call { try $0.confirm(contact: contact, name: name) }
        answer = nil
        await refresh()
    }

    func send(_ text: String, to contact: String) async throws {
        try await call { try $0.send(contact: contact, data: Data(text.utf8)) }
        await load(contact)
    }

    func close(_ contact: String) async throws {
        try await call { try $0.close(contact: contact) }
        if case .joined(contact, _) = answer {
            answer = nil
        }
        histories[contact] = nil
        await refresh()
    }

    func safetyWords(_ contact: String) async -> String? {
        try? await call { $0.safetyWords(contact: contact) }
    }

    func install(profile: Data) async throws {
        _ = try await call { try $0.installNetwork(profile: profile) }
        await refresh()
    }

    func load(_ contact: String) async {
        unread.remove(contact)
        histories[contact] = try? await call { try $0.history(contact: contact) }
    }

    private func start() async {
        do {
            let platform = try ApplePlatform()
            hardwareBacked = platform.hardwareBacked
            let dev = Self.devMailbox()
            client = try await onQueue { try Client(platform: platform, devMailbox: dev) }
            await refresh()
        } catch {
            trouble = describe(error)
        }
    }

    private func tick() async {
        guard client != nil else { return }
        let events: [Event]
        do {
            events = try await call { try $0.tick() }
            trouble = nil
        } catch {
            trouble = describe(error)
            return
        }
        for event in events {
            switch event {
            case .answered:
                if case .waiting = invitation {
                    invitation = .answered
                }
            case let .joined(contact, safetyWords):
                answer = .joined(contact: contact, safetyWords: safetyWords)
            case let .message(contact, _):
                if contact == openChat {
                    await load(contact)
                } else {
                    unread.insert(contact)
                    histories[contact] = nil
                }
            case let .closed(contact):
                histories[contact] = nil
            case .dormant, .awake:
                break
            }
        }
        if !events.isEmpty {
            await refresh()
        }
    }

    private func refresh() async {
        contacts = (try? await call { $0.contacts() }) ?? contacts
        networks = (try? await call { $0.networks() }) ?? networks
    }

    private func call<T: Sendable>(_ work: @escaping @Sendable (Client) throws -> T) async throws
        -> T
    {
        guard let client else { throw JanusError.Storage(reason: "the client is not open") }
        return try await onQueue { try work(client) }
    }

    private func onQueue<T: Sendable>(_ work: @escaping @Sendable () throws -> T) async throws
        -> T
    {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { continuation.resume(with: Result(catching: work)) }
        }
    }

    /// The development mailbox of Debug builds, if `make apple` found its certificate.
    private static func devMailbox() -> DevMailbox? {
        #if DEBUG
        guard let address = Bundle.main.object(forInfoDictionaryKey: "JanusDevMailbox") as? String,
              !address.isEmpty,
              let url = Bundle.main.url(forResource: "mailbox", withExtension: "der"),
              let cert = try? Data(contentsOf: url)
        else { return nil }
        return DevMailbox(address: address, cert: cert)
        #else
        return nil
        #endif
    }
}

func describe(_ error: Error) -> String {
    switch error as? JanusError {
    case .BadWords: "Exactly 6 words from the list are needed."
    case .Expired: "The invitation expired. Start a new one."
    case .Rejected: "The words do not match."
    case .NotConfirmed: "The safety words are not confirmed yet."
    case .TooLarge: "The message is over 16 MB."
    case .UnknownNetwork: "That network is not installed."
    case .BadProfile: "This is not a network profile."
    case .UnknownContact: "That contact no longer exists."
    case .BadInterval: "Pick one of the offered intervals."
    case .BadKey: "The storage key is damaged."
    case let .Storage(reason): "Storage failed: \(reason)"
    case nil: error.localizedDescription
    }
}
