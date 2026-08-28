import SwiftUI

/// Shared `@main` entry point for both the macOS and iOS targets — add
/// this whole `App/` directory to both, using Xcode's "Multiplatform App"
/// template as the starting project (see the setup README next to this
/// file's parent directory).
@main
struct PassApp: App {
    @StateObject private var state = AppState()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(state)
        }
    }
}
