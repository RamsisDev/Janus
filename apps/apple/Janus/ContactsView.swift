import SwiftUI

struct ContactsView: View {
    enum Sheet: String, Identifiable {
        case invite, answer, networks
        var id: String { rawValue }
    }

    @EnvironmentObject private var model: AppModel
    @State private var sheet: Sheet?
    @State private var closing: Contact?

    var body: some View {
        let waiting = model.contacts.filter { !$0.confirmed }
        let active = model.contacts.filter { $0.confirmed && !$0.dormant }
        let dormant = model.contacts.filter { $0.confirmed && $0.dormant }
        NavigationStack {
            List {
                if let trouble = model.trouble {
                    Label(trouble, systemImage: "exclamationmark.triangle")
                }
                if !model.hardwareBacked {
                    Text("This device has no secure hardware for the storage key: the Keychain "
                        + "alone protects your conversations.")
                        .font(.footnote)
                }
                if model.networks.isEmpty {
                    Button("Install a network to start") { sheet = .networks }
                }
                if model.invitation == .answered {
                    Button("Your invitation was answered: type the safety words") {
                        sheet = .invite
                    }
                }
                if !waiting.isEmpty {
                    Section("Waiting for the safety words") {
                        ForEach(waiting, id: \.id) { contact in
                            NavigationLink("New contact") { ConfirmView(contact: contact.id) }
                                .swipeActions { closeButton(contact) }
                        }
                    }
                }
                Section("Contacts") {
                    if active.isEmpty {
                        Text("No contacts yet. Create an invitation, or answer one.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(active, id: \.id) { contact in
                        NavigationLink { ChatView(contact: contact.id) } label: {
                            HStack {
                                Text(contact.name)
                                if model.unread.contains(contact.id) {
                                    Spacer()
                                    Image(systemName: "circle.fill").font(.caption2)
                                        .foregroundStyle(.tint)
                                        .accessibilityLabel("New messages")
                                }
                            }
                        }
                        .swipeActions { closeButton(contact) }
                    }
                }
                if !dormant.isEmpty {
                    Section {
                        ForEach(dormant, id: \.id) { contact in
                            NavigationLink(contact.name) { ChatView(contact: contact.id) }
                                .swipeActions { closeButton(contact) }
                        }
                    } header: {
                        Text("Dormant")
                    } footer: {
                        Text("Nothing heard from these contacts for a year. Silence can be "
                            + "forged, so they stay until you close them.")
                    }
                }
            }
            .navigationTitle("Janus")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Menu {
                        Button("Create an invitation") { sheet = .invite }
                        Button("Answer an invitation") { sheet = .answer }
                        Button("Networks") { sheet = .networks }
                    } label: {
                        Image(systemName: "plus").accessibilityLabel("New")
                    }
                }
            }
            .sheet(item: $sheet) { sheet in
                NavigationStack {
                    switch sheet {
                    case .invite: InviteView()
                    case .answer: AnswerView()
                    case .networks: NetworksView()
                    }
                }
                .environmentObject(model)
            }
            .confirmationDialog(
                "Close this conversation?",
                isPresented: Binding(get: { closing != nil }, set: { if !$0 { closing = nil } }),
                presenting: closing
            ) { contact in
                Button("Close and delete", role: .destructive) {
                    Task { try? await model.close(contact.id) }
                }
            } message: { _ in
                Text("Ends the session on both phones and deletes its history from this one.")
            }
        }
    }

    private func closeButton(_ contact: Contact) -> some View {
        Button("Close", role: .destructive) { closing = contact }
    }
}
