#if os(macOS)
import AppKit
import SwiftUI

/// Menu shown from the macOS status bar icon (see `PassApp`).
struct MenuBarContent: View {
    @EnvironmentObject private var state: AppState
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Button("Open Pass") { openMainWindow() }
            .keyboardShortcut("o")

        if state.isUnlocked {
            Button("Lock") { state.lock() }
                .keyboardShortcut("l")
        }

        Divider()

        Button("Quit Pass") { NSApp.terminate(nil) }
            .keyboardShortcut("q")
    }

    /// Brings the existing main window to the front, or opens a new one if
    /// the user closed it. Reusing the existing window avoids piling up
    /// duplicate `WindowGroup` windows every time the menu item is used.
    private func openMainWindow() {
        NSApp.activate(ignoringOtherApps: true)
        let existing = NSApp.windows.first { window in
            window.canBecomeMain && window.identifier?.rawValue.hasPrefix(PassApp.mainWindowID) == true
        }
        if let existing {
            if existing.isMiniaturized { existing.deminiaturize(nil) }
            existing.makeKeyAndOrderFront(nil)
        } else {
            openWindow(id: PassApp.mainWindowID)
        }
    }
}
#endif
