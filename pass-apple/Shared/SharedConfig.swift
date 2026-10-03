import Foundation

/// Where the app and its AutoFill extension find the vault. Both are part
/// of the same App Group, whose name (and the keychain group's) comes from
/// the target's Info.plist — filled in at build time from `DEVELOPMENT_TEAM`
/// by `Config/Shared.xcconfig`, so no Team ID is hard-coded here.
enum SharedConfig {
    /// `TEAMID.it.antoniopicone.Pass` on macOS, `group.it.antoniopicone.Pass`
    /// on iOS; `nil` when the build didn't set it (no team selected yet).
    static let appGroupID: String? = infoString("PassAppGroupIdentifier")

    /// `TEAMID.it.antoniopicone.Pass`; `nil` when the build didn't set it.
    static let keychainAccessGroup: String? = infoString("PassKeychainAccessGroup")

    /// The App Group container — readable by the sandboxed AutoFill
    /// extension, unlike the rest of the user's home folder.
    static var containerURL: URL? {
        appGroupID.flatMap { FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: $0) }
    }

    /// Preferences both processes read: the app records the vault it has
    /// open here, the extension opens that one.
    static var defaults: UserDefaults {
        appGroupID.flatMap { UserDefaults(suiteName: $0) } ?? .standard
    }

    /// Same file name passlib's `default_vault_path()` uses, so the CLI and
    /// the Chromium native host land on this file too.
    static let defaultVaultFileName = "personal.kdbx"

    /// `personal.kdbx` in the App Group container, or in Documents when the
    /// App Group isn't available (build without a team).
    static var defaultVaultPath: String {
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
        let directory = containerURL ?? documents ?? URL(fileURLWithPath: NSTemporaryDirectory())
        return directory.appendingPathComponent(defaultVaultFileName).path
    }

    private static let vaultPathKey = "PassVaultPath"

    /// The vault the app last opened or created.
    static var vaultPath: String? {
        get { defaults.string(forKey: vaultPathKey) }
        set { defaults.set(newValue, forKey: vaultPathKey) }
    }

    /// Whether `path` is inside the App Group container, i.e. reachable by
    /// the AutoFill extension.
    static func isInSharedContainer(_ path: String) -> Bool {
        guard let container = containerURL?.standardizedFileURL.path else { return false }
        return URL(fileURLWithPath: path).standardizedFileURL.path.hasPrefix(container + "/")
    }

    private static func infoString(_ key: String) -> String? {
        guard let value = Bundle.main.object(forInfoDictionaryKey: key) as? String else { return nil }
        // An unset DEVELOPMENT_TEAM leaves ".it.antoniopicone.Pass", and a
        // plist used without the xcconfig leaves "$(...)" unexpanded.
        guard !value.isEmpty, !value.hasPrefix("."), !value.contains("$(") else { return nil }
        return value
    }
}
