import SwiftUI
import UniformTypeIdentifiers

/// One-off import: merges entries from an unrelated KDBX file into the
/// currently open vault, using the same KDBX4 database merge `pass merge`
/// uses on the CLI. For keeping copies of *this same* vault in sync across
/// your own devices, that happens automatically via pass-syncd (see the
/// top-level README's "Cross-device sync" section) — this view is for
/// something else, like a database someone else sent you.
struct MergeView: View {
    @EnvironmentObject private var state: AppState
    @Environment(\.dismiss) private var dismiss

    @State private var otherPath = ""
    @State private var showFileImporter = false

    private var kdbxType: UTType {
        UTType(filenameExtension: "kdbx") ?? .data
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("Import entries from an unrelated .kdbx file into this vault. For syncing this same vault across your own devices, set up pass-syncd instead — see the main README.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                Section {
                    HStack {
                        TextField("Path to other .kdbx file", text: $otherPath)
                            #if os(iOS)
                            .autocapitalization(.none)
                            .disableAutocorrection(true)
                            #endif
                        Button("Browse…") { showFileImporter = true }
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Merge From File")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Merge") {
                        state.merge(otherPath: otherPath)
                        dismiss()
                    }
                    .disabled(otherPath.isEmpty)
                }
            }
            .fileImporter(isPresented: $showFileImporter, allowedContentTypes: [kdbxType, .data]) { result in
                if case .success(let url) = result {
                    otherPath = url.path
                }
            }
        }
    }
}
