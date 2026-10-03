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
    @State private var showMoveConfirmation = false

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

                Section {
                    if state.isVaultInSharedContainer {
                        Label("AutoFill can read this vault.", systemImage: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                    } else if state.hasSharedContainer {
                        Text("AutoFill can't reach this vault where it is now. Moving it into Pass's shared container fixes that\(sharedClientsNote).")
                        Button("Move Vault to Shared Container…") { showMoveConfirmation = true }
                    } else {
                        Text("This build has no App Group, so AutoFill can't reach the vault. Select a team under Signing & Capabilities in Xcode and rebuild.")
                            .foregroundStyle(.secondary)
                    }
                } header: {
                    Text("AutoFill")
                } footer: {
                    Text(autoFillSettingsHint)
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
        .confirmationDialog(
            "Move the vault into the shared container?",
            isPresented: $showMoveConfirmation,
            titleVisibility: .visible
        ) {
            Button("Move and Lock") { moveVault() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The vault will be locked; unlock it again with your master password. \(biometryLabel) unlock is set up again afterwards, since it's tied to the file's location.")
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

    private var sharedClientsNote: String {
        #if os(macOS)
        return ", and the CLI and Chrome extension bundled with Pass follow it automatically"
        #else
        return ""
        #endif
    }

    private var autoFillSettingsHint: String {
        #if os(macOS)
        return "Turn Pass on in System Settings → General → AutoFill & Passwords to fill passwords and verification codes in Safari and apps."
        #else
        return "Turn Pass on in Settings → General → AutoFill & Passwords to fill passwords and verification codes in Safari and apps."
        #endif
    }

    private func moveVault() {
        do {
            try state.moveVaultToSharedContainer()
        } catch {
            // The vault may already be locked by now (the move locks it
            // first), in which case this sheet is gone and the unlock
            // screen shows `state.errorMessage` instead.
            errorMessage = error.localizedDescription
            state.errorMessage = error.localizedDescription
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
