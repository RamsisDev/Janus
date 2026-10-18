import SwiftUI

struct ChatView: View {
    let contact: String
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var draft = ""
    @State private var failure: String?
    @State private var closing = false

    var body: some View {
        let entries = model.histories[contact] ?? []
        let info = model.contacts.first { $0.id == contact }
        ScrollViewReader { proxy in
            List {
                if info?.dormant == true {
                    Text("Nothing heard from this contact for a year.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                ForEach(entries.indices, id: \.self) { i in
                    bubble(entries[i]).id(i).listRowSeparator(.hidden)
                }
            }
            .listStyle(.plain)
            .onChange(of: entries.count) { _, count in
                proxy.scrollTo(count - 1, anchor: .bottom)
            }
        }
        .safeAreaInset(edge: .bottom) {
            VStack {
                if let failure {
                    Text(failure).font(.footnote).foregroundStyle(.red)
                }
                HStack {
                    TextField("Message", text: $draft, axis: .vertical)
                        .textFieldStyle(.roundedBorder)
                    Button("Send", action: send)
                        .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
            .padding()
            .background(.bar)
        }
        .navigationTitle(info?.name ?? "")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button("Close", role: .destructive) { closing = true }
            }
        }
        .confirmationDialog("Close this conversation?", isPresented: $closing) {
            Button("Close and delete", role: .destructive) {
                Task {
                    try? await model.close(contact)
                    dismiss()
                }
            }
        } message: {
            Text("Ends the session on both phones and deletes its history from this one.")
        }
        .onAppear {
            model.openChat = contact
            Task { await model.load(contact) }
        }
        .onDisappear {
            if model.openChat == contact {
                model.openChat = nil
            }
        }
    }

    private func bubble(_ entry: HistoryEntry) -> some View {
        let text = String(data: entry.data, encoding: .utf8) ?? "[\(entry.data.count) bytes]"
        return HStack {
            if entry.mine { Spacer(minLength: 48) }
            Text(text)
                .padding(10)
                .background(entry.mine ? Color.accentColor.opacity(0.2) : Color.secondary.opacity(0.15),
                            in: RoundedRectangle(cornerRadius: 12))
                .textSelection(.enabled)
            if !entry.mine { Spacer(minLength: 48) }
        }
    }

    private func send() {
        let text = draft
        draft = ""
        Task {
            failure = nil
            do {
                try await model.send(text, to: contact)
            } catch {
                draft = text
                failure = describe(error)
            }
        }
    }
}
