import PassKit
import SwiftUI

/// Lets the user enable/disable biometric unlock for the currently open
/// vault at any time, independent of the one-shot post-unlock prompt in
/// `RootView` — useful if that prompt was dismissed, or the device only
/// gained biometric enrollment later.
struct SettingsView: View {
    @EnvironmentObject private var state: AppState
    @Environment(\.dismiss) private var dismiss

    @State private var biometricEnabled = false
    @State private var showPasswordPrompt = false
    @State private var confirmPassword = ""
    @State private var errorMessage: String?

    private var biometryLabel: String { BiometricUnlock.biometryLabel() }
    private var biometryAvailable: Bool { BiometricUnlock.isAvailable() }
    private var vaultName: String { URL(fileURLWithPath: state.vaultPath).lastPathComponent }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    if biometryAvailable {
                        Toggle("Unlock with \(biometryLabel)", isOn: $biometricEnabled)
                            .onChange(of: biometricEnabled) { _, enabled in
                                if enabled {
                                    showPasswordPrompt = true
                                } else {
                                    BiometricUnlock.forget(vaultPath: state.vaultPath)
                                    errorMessage = nil
                                }
                            }
                    } else {
                        Text("\(biometryLabel) is not available on this device.")
                            .foregroundStyle(.secondary)
                    }
                } footer: {
                    Text("Applies to the currently open vault (\(vaultName)).")
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
            .navigationTitle("Settings")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
        .onAppear {
            biometricEnabled = BiometricUnlock.hasStoredPassword(forVaultPath: state.vaultPath)
        }
        .alert("Confirm Master Password", isPresented: $showPasswordPrompt) {
            SecureField("Master password", text: $confirmPassword)
            Button("Enable", action: confirmAndEnable)
            Button("Cancel", role: .cancel) {
                confirmPassword = ""
                biometricEnabled = false
            }
        } message: {
            Text("Enter your master password once to enable \(biometryLabel) unlock for this vault.")
        }
    }

    /// The currently open vault handle doesn't expose its own master
    /// password (by design), so enabling biometrics from here needs it
    /// re-typed once — verified by actually opening the vault file with it,
    /// the same check `pass`/the unlock screen would do, before storing it
    /// behind Face ID/Touch ID.
    private func confirmAndEnable() {
        let typed = confirmPassword
        confirmPassword = ""

        do {
            _ = try Vault.unlock(atPath: state.vaultPath, masterPassword: typed)
        } catch {
            biometricEnabled = false
            errorMessage = "Incorrect password — \(biometryLabel) was not enabled."
            return
        }

        do {
            try BiometricUnlock.store(password: typed, forVaultPath: state.vaultPath)
            errorMessage = nil
        } catch {
            // Password was correct — this is a genuine Keychain failure,
            // not a wrong-password case, so surface the real reason.
            NSLog("[Pass] BiometricUnlock.store failed: \(error)")
            biometricEnabled = false
            errorMessage = error.localizedDescription
        }
    }
}
