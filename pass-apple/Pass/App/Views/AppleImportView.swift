import SwiftUI
import UniformTypeIdentifiers
#if os(macOS)
import AppKit
#endif

/// Imports the passwords saved in Apple Passwords (iCloud Keychain). Apple
/// doesn't let apps read iCloud Keychain directly, so — like iCloudBridge —
/// this goes through the CSV the Passwords app exports, the same import
/// `pass import-apple` does on the CLI. Logins the vault already has are
/// skipped, so importing a fresh export again only adds what's new.
struct AppleImportView: View {
    @EnvironmentObject private var state: AppState
    @Environment(\.dismiss) private var dismiss

    @State private var csvURL: URL?
    @State private var deleteAfterImport = true
    @State private var showFileImporter = false
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    #if os(macOS)
                    Text("1. In Passwords, choose File → Export All Passwords to File… and save the CSV.")
                    Text("2. Choose that file below.")
                    Button("Open Passwords") { openPasswordsApp() }
                    #else
                    Text("On your Mac, open Passwords, choose File → Export All Passwords to File… and save the CSV to iCloud Drive. Then choose that file below.")
                    #endif
                } footer: {
                    Text("Apple doesn't let apps read iCloud Keychain directly, so the import goes through the Passwords export. Logins already in this vault are skipped.")
                }

                Section {
                    HStack {
                        Text(csvURL?.lastPathComponent ?? "No file chosen")
                            .foregroundStyle(csvURL == nil ? .secondary : .primary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Spacer()
                        Button("Choose File…") { showFileImporter = true }
                    }
                    Toggle("Delete the file after importing", isOn: $deleteAfterImport)
                } footer: {
                    Text("The export holds every password in plain text.")
                }

                if let errorMessage {
                    Section {
                        Text(errorMessage)
                            .font(.footnote)
                            .foregroundStyle(.red)
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Import from Apple Passwords")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Import") { importSelectedFile() }
                        .disabled(csvURL == nil)
                }
            }
            .fileImporter(isPresented: $showFileImporter, allowedContentTypes: [.commaSeparatedText]) { result in
                switch result {
                case .success(let url):
                    csvURL = url
                    errorMessage = nil
                case .failure(let error):
                    errorMessage = error.localizedDescription
                }
            }
        }
    }

    private func importSelectedFile() {
        guard let csvURL else { return }
        do {
            try state.importApplePasswords(from: csvURL, deleteAfterImport: deleteAfterImport)
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    #if os(macOS)
    /// Opens the Passwords app (macOS 15+), or Safari before that, which is
    /// where the export lived (File → Export → Passwords…).
    private func openPasswordsApp() {
        let workspace = NSWorkspace.shared
        for bundleID in ["com.apple.Passwords", "com.apple.Safari"] {
            if let appURL = workspace.urlForApplication(withBundleIdentifier: bundleID) {
                workspace.openApplication(at: appURL, configuration: NSWorkspace.OpenConfiguration(), completionHandler: nil)
                return
            }
        }
    }
    #endif
}
