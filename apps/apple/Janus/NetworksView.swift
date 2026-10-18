import SwiftUI
import UniformTypeIdentifiers

/// The installed networks, and installing one from a QR code or a file. The profile is shown
/// before it is installed, since a substituted one would route the user through someone
/// else's servers.
struct NetworksView: View {
    private struct Found: Identifiable {
        let profile: Data
        let network: NetworkInfo
        var id: String { network.id }
    }

    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var scanning = false
    @State private var importing = false
    @State private var found: Found?
    @State private var failure: String?

    var body: some View {
        Form {
            Section("Installed") {
                if model.networks.isEmpty {
                    Text("None yet").foregroundStyle(.secondary)
                }
                ForEach(model.networks, id: \.id) { network in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(network.name)
                        Text(fingerprint(network.id))
                            .font(.caption.monospaced()).foregroundStyle(.secondary)
                    }
                }
            }
            Section {
                #if os(iOS)
                Button("Scan a QR code") { scanning = true }
                #endif
                Button("Choose a file") { importing = true }
            } header: {
                Text("Install a network")
            } footer: {
                Text("Only from a source you verified: a QR code shown to you in person, or a "
                    + "file from someone you trust.")
            }
            if let failure {
                Text(failure).foregroundStyle(.red)
            }
        }
        .navigationTitle("Networks")
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Done") { dismiss() }
            }
        }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.data]) { result in
            do {
                let url = try result.get()
                let scoped = url.startAccessingSecurityScopedResource()
                defer {
                    if scoped { url.stopAccessingSecurityScopedResource() }
                }
                offer(try Data(contentsOf: url))
            } catch {
                failure = describe(error)
            }
        }
        #if os(iOS)
        .sheet(isPresented: $scanning) {
            QRScanner { text in
                scanning = false
                // shortcut: one QR code holds base64 text of up to ~2 KB of profile (one or two
                // authorities); move to binary or multi-part codes when profiles outgrow it.
                if let profile = Data(base64Encoded: text) {
                    offer(profile)
                } else {
                    failure = describe(JanusError.BadProfile)
                }
            }
            .ignoresSafeArea()
        }
        #endif
        .alert("Install \(found?.network.name ?? "")?",
               isPresented: Binding(get: { found != nil }, set: { if !$0 { found = nil } }),
               presenting: found) { found in
            Button("Install") {
                Task {
                    do {
                        try await model.install(profile: found.profile)
                    } catch {
                        failure = describe(error)
                    }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: { found in
            Text("Check that this id matches your source:\n\(fingerprint(found.network.id))")
        }
    }

    private func offer(_ profile: Data) {
        failure = nil
        do {
            found = Found(profile: profile, network: try readNetwork(profile: profile))
        } catch {
            failure = describe(error)
        }
    }
}

/// The network id in groups of 4 hex digits, for people to compare.
func fingerprint(_ id: String) -> String {
    stride(from: 0, to: id.count, by: 4).map { start in
        let from = id.index(id.startIndex, offsetBy: start)
        return String(id[from..<(id.index(from, offsetBy: 4, limitedBy: id.endIndex) ?? id.endIndex)])
    }.joined(separator: " ")
}
