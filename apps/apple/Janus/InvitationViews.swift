import SwiftUI

/// A: picks the network and rotation, reads the 6 words out, then types B's safety words.
struct InviteView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var network = ""
    @State private var hours: UInt8 = 10
    @State private var typed = ""
    @State private var name = ""
    @State private var failure: String?

    var body: some View {
        Form {
            switch model.invitation {
            case nil:
                Section {
                    NetworkPicker(selection: $network)
                    Picker("Key rotation", selection: $hours) {
                        ForEach([1, 5, 10, 120] as [UInt8], id: \.self) { h in
                            Text(rotation(h)).tag(h)
                        }
                    }
                } footer: {
                    Text("The other person answers on the same network. Keys are replaced at "
                        + "least this often, even if nobody writes.")
                }
                Button("Create the invitation") {
                    act { try await model.invite(network: network, hours: hours) }
                }
                .disabled(network.isEmpty)
            case let .waiting(words, network):
                Section {
                    Text(words).font(.title2.monospaced()).textSelection(.enabled)
                } header: {
                    Text("Read these 6 words to the other person")
                } footer: {
                    Text("In person or on a call, and tell them the network: \(network). They "
                        + "have 10 minutes to answer.")
                }
                HStack(spacing: 12) {
                    ProgressView()
                    Text("Waiting for the answer…")
                }
            case .answered:
                Section {
                    TextField("3 safety words", text: $typed)
                        .autocorrectionDisabled()
                        #if os(iOS)
                        .textInputAutocapitalization(.never)
                        #endif
                } header: {
                    Text("They answered")
                } footer: {
                    Text("Ask them to read you the 3 words their phone shows, and type them.")
                }
                Section {
                    TextField("Name for this contact", text: $name)
                }
                Button("Check the words") {
                    act {
                        do {
                            try await model.verify(typed: words(typed), name: name)
                            dismiss()
                        } catch JanusError.Rejected {
                            throw Mismatch()
                        }
                    }
                }
                .disabled(name.isEmpty)
            }
            if let failure {
                Text(failure).foregroundStyle(.red)
            }
        }
        .navigationTitle("Invitation")
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") {
                    model.invitation = nil
                    dismiss()
                }
            }
        }
    }

    private func act(_ work: @escaping () async throws -> Void) {
        Task {
            failure = nil
            do {
                try await work()
            } catch let mismatch as Mismatch {
                failure = mismatch.text
            } catch {
                failure = describe(error)
            }
        }
    }

    private func rotation(_ hours: UInt8) -> String {
        switch hours {
        case 1: "Every hour"
        case 120: "Every 5 days"
        default: "Every \(hours) hours"
        }
    }
}

private struct Mismatch: Error {
    let text = "The words do not match. Check them and type them again. If they really "
        + "differ, someone may be in the middle: cancel, and invite again in person."
}

/// B: types the 6 words on the network the invitation names, then reads out the safety words.
struct AnswerView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var network = ""
    @State private var typed = ""
    @State private var failure: String?

    var body: some View {
        Form {
            switch model.answer {
            case nil:
                Section {
                    NetworkPicker(selection: $network)
                } footer: {
                    Text("The network the other person named; if they named none, the default.")
                }
                Section {
                    TextField("6 words", text: $typed, axis: .vertical)
                        .autocorrectionDisabled()
                        #if os(iOS)
                        .textInputAutocapitalization(.never)
                        #endif
                }
                Button("Answer") {
                    Task {
                        failure = nil
                        do {
                            try await model.join(network: network, words: words(typed))
                        } catch {
                            failure = describe(error)
                        }
                    }
                }
                .disabled(network.isEmpty)
            case .looking:
                Section {
                    HStack(spacing: 12) {
                        ProgressView()
                        Text("Looking for the invitation…")
                    }
                } footer: {
                    Text("An invitation lives 10 minutes.")
                }
            case let .joined(contact, safetyWords):
                ConfirmSections(contact: contact, safetyWords: safetyWords) { dismiss() }
            }
            if let failure {
                Text(failure).foregroundStyle(.red)
            }
        }
        .navigationTitle("Answer")
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") {
                    if model.answer == .looking {
                        model.answer = nil
                    }
                    dismiss()
                }
            }
        }
    }
}

/// B, for a contact still waiting for the safety words, e.g. after a restart.
struct ConfirmView: View {
    let contact: String
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var safetyWords: String?

    var body: some View {
        Form {
            if let safetyWords {
                ConfirmSections(contact: contact, safetyWords: safetyWords) { dismiss() }
            } else {
                ProgressView()
            }
        }
        .navigationTitle("Safety words")
        .task { safetyWords = await model.safetyWords(contact) }
    }
}

struct ConfirmSections: View {
    let contact: String
    let safetyWords: String
    let done: () -> Void
    @EnvironmentObject private var model: AppModel
    @State private var name = ""
    @State private var failure: String?

    var body: some View {
        Section {
            Text(safetyWords).font(.title2.monospaced())
        } header: {
            Text("Read these 3 words to the other person")
        } footer: {
            Text("They type them and tell you whether they match. Nothing is sent before.")
        }
        Section {
            TextField("Name for this contact", text: $name)
        }
        Section {
            Button("They say the words match") {
                run { try await model.confirm(contact: contact, name: name) }
            }
            .disabled(name.isEmpty)
            Button("They do not match", role: .destructive) {
                run { try await model.close(contact) }
            }
        } footer: {
            Text("Words that do not match mean someone may be in the middle. Close this "
                + "contact and invite again in person.")
        }
        if let failure {
            Text(failure).foregroundStyle(.red)
        }
    }

    private func run(_ work: @escaping () async throws -> Void) {
        Task {
            do {
                try await work()
                done()
            } catch {
                failure = describe(error)
            }
        }
    }
}

/// The installed networks, the first (the default) preselected.
struct NetworkPicker: View {
    @Binding var selection: String
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Picker("Network", selection: $selection) {
            ForEach(model.networks, id: \.id) { network in
                Text(network.name).tag(network.id)
            }
        }
        .onAppear {
            if selection.isEmpty {
                selection = model.networks.first?.id ?? ""
            }
        }
    }
}

/// Words as the core expects them: lowercase, single spaces.
private func words(_ typed: String) -> String {
    typed.lowercased().split(whereSeparator: \.isWhitespace).joined(separator: " ")
}
