import SwiftUI

/// Shared `@main` entry point for both the macOS and iOS targets
/// (`Pass-macOS` and `Pass-iOS` in `project.yml`).
@main
struct PassApp: App {
    @StateObject private var state = AppState()

    var body: some Scene {
        WindowGroup(id: PassApp.mainWindowID) {
            RootView()
                .environmentObject(state)
        }

        #if os(macOS)
        MenuBarExtra("Pass", systemImage: "key.fill") {
            MenuBarContent()
                .environmentObject(state)
        }
        #endif
    }

    static let mainWindowID = "main"
}
