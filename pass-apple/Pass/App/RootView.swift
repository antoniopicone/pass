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
    }
}
