import SwiftUI
import UniformTypeIdentifiers

struct UnlockView: View {
    @EnvironmentObject private var state: AppState

    @State private var password = ""
    @State private var showFileImporter = false

    private var kdbxType: UTType {
        UTType(filenameExtension: "kdbx") ?? .data
    }

    var body: some View {
        VStack(spacing: 16) {
            Text("🔐 Pass")
                .font(.largeTitle.bold())
                .padding(.top, 32)

            VStack(alignment: .leading, spacing: 6) {
                Text("Vault file")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                HStack {
                    TextField("Path to .kdbx file", text: $state.vaultPath)
                        .textFieldStyle(.roundedBorder)
                        #if os(iOS)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                        #endif
                    Button("Browse…") { showFileImporter = true }
                }
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("Master password")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                SecureField("Master password", text: $password)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit(unlock)
            }

            HStack {
                Button("Unlock", action: unlock)
                    .keyboardShortcut(.defaultAction)
                    .disabled(state.vaultPath.isEmpty || password.isEmpty)

                Button("Create New Vault") {
                    state.createVault(password: password)
                    password = ""
                }
                .disabled(state.vaultPath.isEmpty || password.isEmpty)
            }

            if let error = state.errorMessage {
                Text(error)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
            }

            Spacer()
        }
        .padding(24)
        .frame(maxWidth: 420)
        .fileImporter(isPresented: $showFileImporter, allowedContentTypes: [kdbxType, .data]) { result in
            if case .success(let url) = result {
                state.importVaultFile(from: url)
            }
        }
    }

    private func unlock() {
        state.unlock(password: password)
        password = ""
    }
}
