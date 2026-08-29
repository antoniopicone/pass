import SwiftUI

/// Switches between the locked (unlock/create) screen and the unlocked
/// entry list, mirroring the CLI/GNOME/extension clients' session model:
/// no vault stays open across app launches, and locking clears it from
/// memory immediately.
struct RootView: View {
    @EnvironmentObject private var state: AppState

    var body: some View {
        Group {
            if state.isUnlocked {
                EntryListView()
            } else {
                UnlockView()
            }
        }
        #if os(macOS)
        .frame(minWidth: 420, minHeight: 480)
        #endif
        .alert(
            "Enable \(BiometricUnlock.biometryLabel())?",
            isPresented: Binding(
                get: { state.biometricEnrollmentOffer != nil },
                set: { if !$0 { state.biometricEnrollmentOffer = nil } }
            ),
            presenting: state.biometricEnrollmentOffer
        ) { offer in
            Button("Enable") {
                do {
                    try BiometricUnlock.store(password: offer.password, forVaultPath: offer.vaultPath)
                } catch {
                    NSLog("[Pass] BiometricUnlock.store failed: \(error)")
                    state.statusMessage = "Couldn't enable \(BiometricUnlock.biometryLabel()): \(error.localizedDescription)"
                }
                state.biometricEnrollmentOffer = nil
            }
            Button("Not Now", role: .cancel) {
                state.biometricEnrollmentOffer = nil
            }
        } message: { _ in
            Text("Unlock this vault with \(BiometricUnlock.biometryLabel()) next time instead of typing your master password.")
        }
    }
}
