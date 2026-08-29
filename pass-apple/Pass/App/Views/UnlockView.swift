import SwiftUI
import UniformTypeIdentifiers

struct UnlockView: View {
    @EnvironmentObject private var state: AppState
    @Environment(\.scenePhase) private var scenePhase

    @State private var password = ""
    @State private var showFileImporter = false
    @State private var isChoosingVault = false
    @State private var hasBiometricCredential = false
    @State private var isAuthenticatingBiometrics = false
    @State private var hasAttemptedAutoBiometricUnlock = false

    private var kdbxType: UTType {
        UTType(filenameExtension: "kdbx") ?? .data
    }

    private var biometryLabel: String { BiometricUnlock.biometryLabel() }

    private var vaultDisplayName: String {
        URL(fileURLWithPath: state.vaultPath).lastPathComponent
    }

    var body: some View {
        VStack(spacing: 16) {
            Text("🔐 Pass")
                .font(.largeTitle.bold())
                .padding(.top, 32)

            if isChoosingVault {
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
                    Button("Done") { isChoosingVault = false }
                        .font(.caption)
                }
            } else {
                VStack(spacing: 2) {
                    Text(vaultDisplayName)
                        .font(.subheadline.weight(.medium))
                    Text(state.vaultPath)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Button("Choose a different vault…") { isChoosingVault = true }
                        .font(.caption)
                        .buttonStyle(.plain)
                        .foregroundStyle(.blue)
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

            if hasBiometricCredential {
                Button {
                    Task { await unlockWithBiometrics() }
                } label: {
                    Label("Unlock with \(biometryLabel)", systemImage: BiometricUnlock.biometryIcon())
                }
                .disabled(isAuthenticatingBiometrics)

                Button("Don't use \(biometryLabel) for this vault", role: .destructive) {
                    BiometricUnlock.forget(vaultPath: state.vaultPath)
                    refreshBiometricState()
                }
                .font(.caption)
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
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
                isChoosingVault = false
            }
        }
        .onAppear {
            refreshBiometricState()
            attemptAutoBiometricUnlockOnce()
        }
        .onChange(of: state.vaultPath) {
            refreshBiometricState()
        }
        .onChange(of: scenePhase) { _, newPhase in
            // A Touch ID/Face ID prompt triggered too early — before the
            // window is actually key/active — can be silently dropped by
            // macOS. `.onAppear` alone fires before that's guaranteed, so
            // also retry once the scene genuinely becomes active; the
            // `hasAttemptedAutoBiometricUnlock` guard keeps this to a
            // single attempt even though both call sites can fire.
            if newPhase == .active {
                attemptAutoBiometricUnlockOnce()
            }
        }
    }

    private func unlock() {
        state.unlock(password: password)
        password = ""
    }

    private func refreshBiometricState() {
        hasBiometricCredential = BiometricUnlock.isAvailable()
            && BiometricUnlock.hasStoredPassword(forVaultPath: state.vaultPath)
    }

    private func unlockWithBiometrics() async {
        isAuthenticatingBiometrics = true
        defer { isAuthenticatingBiometrics = false }
        do {
            let storedPassword = try await BiometricUnlock.retrievePassword(forVaultPath: state.vaultPath)
            state.unlock(password: storedPassword)
        } catch {
            NSLog("[Pass] BiometricUnlock.retrievePassword failed: \(error)")
            state.errorMessage = error.localizedDescription
        }
    }

    /// Offers Face ID/Touch ID automatically once per time this screen is
    /// shown (guarded by `hasAttemptedAutoBiometricUnlock`), so returning
    /// to an already-enrolled vault needs no tap — only a genuinely new
    /// vault path (or a declined/forgotten one) falls back to showing the
    /// manual password field first.
    private func attemptAutoBiometricUnlockOnce() {
        guard !hasAttemptedAutoBiometricUnlock else { return }
        hasAttemptedAutoBiometricUnlock = true
        Task { await unlockWithBiometricsIfConvenient() }
    }

    private func unlockWithBiometricsIfConvenient() async {
        guard hasBiometricCredential, !isAuthenticatingBiometrics else { return }
        await unlockWithBiometrics()
    }
}
