import SwiftUI
import UniformTypeIdentifiers

/// Pulls another copy of the vault (e.g. one synced into an iCloud Drive
/// or Files.app-visible folder) into the currently open one, using the
/// same KDBX4 database merge `pass merge`/`pass watch` use on the CLI.
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
                    Text("Point this at another copy of this vault — e.g. one synced via iCloud Drive/Nextcloud — to pull in changes made on another device.")
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
