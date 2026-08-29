import Combine
import Foundation
import PassKit

/// Shared app state: the currently open vault (if any), its entries, and
/// the actions the views drive. Everything here runs on the main actor —
/// `Vault`'s calls are synchronous and hit disk, which is fine for a
/// personal vault with a modest number of entries, but is a candidate to
/// move to a background actor if that ever becomes noticeable.
@MainActor
final class AppState: ObservableObject {
    /// Persisted across launches (in `UserDefaults`, just a file path — not
    /// sensitive) so the app remembers the vault the user picked or created
    /// last time instead of asking again on every launch.
    @Published var vaultPath: String = AppState.loadVaultPath() {
        didSet { UserDefaults.standard.set(vaultPath, forKey: Self.vaultPathDefaultsKey) }
    }
    @Published private(set) var entries: [PasswordEntry] = []
    @Published var errorMessage: String?
    @Published var statusMessage: String?

    /// Set right after a successful unlock/create when biometrics are
    /// available but not yet enabled for this vault, so `RootView` (which,
    /// unlike `UnlockView`/`EntryListView`, stays mounted across the
    /// locked/unlocked transition) can offer to enable them. Cleared once
    /// the user answers.
    @Published var biometricEnrollmentOffer: BiometricEnrollmentOffer?

    struct BiometricEnrollmentOffer: Identifiable {
        let id = UUID()
        let vaultPath: String
        let password: String
    }

    private var vault: Vault?

    var isUnlocked: Bool { vault != nil }

    static func defaultVaultPath() -> String {
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
        return documents?.appendingPathComponent("passwords.kdbx").path ?? "passwords.kdbx"
    }

    private static let vaultPathDefaultsKey = "PassVaultPath"

    private static func loadVaultPath() -> String {
        UserDefaults.standard.string(forKey: vaultPathDefaultsKey) ?? defaultVaultPath()
    }

    // MARK: - Unlock / create / lock

    func unlock(password: String) {
        do {
            let opened = try Vault.unlock(atPath: vaultPath, masterPassword: password)
            vault = opened
            errorMessage = nil
            try reload()
            offerBiometricEnrollmentIfNeeded(password: password)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func createVault(password: String) {
        guard password.count >= 8 else {
            errorMessage = "Master password must be at least 8 characters."
            return
        }
        do {
            let created = try Vault.create(atPath: vaultPath, masterPassword: password)
            vault = created
            errorMessage = nil
            try reload()
            offerBiometricEnrollmentIfNeeded(password: password)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func offerBiometricEnrollmentIfNeeded(password: String) {
        guard BiometricUnlock.isAvailable(), !BiometricUnlock.hasStoredPassword(forVaultPath: vaultPath) else { return }
        biometricEnrollmentOffer = BiometricEnrollmentOffer(vaultPath: vaultPath, password: password)
    }

    func lock() {
        vault = nil
        entries = []
        statusMessage = nil
    }

    // MARK: - Entries

    private func reload() throws {
        guard let vault else { return }
        entries = try vault.listEntries()
            .sorted { $0.website.localizedCaseInsensitiveCompare($1.website) == .orderedAscending }
    }

    func refresh() {
        do {
            try reload()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func entry(id: String) -> PasswordEntry? {
        entries.first { $0.id == id }
    }

    /// Re-fetches a single entry directly from the vault (bypassing the
    /// cached `entries` list), for callers that need an up-to-the-second
    /// TOTP code/countdown without reloading everything.
    func fetchEntry(id: String) -> PasswordEntry? {
        guard let vault else { return nil }
        return try? vault.getEntry(id: id)
    }

    func addEntry(website: String, url: String, username: String, password: String) {
        guard let vault else { return }
        do {
            try vault.addEntry(website: website, url: url, username: username, password: password)
            try reload()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func updateEntry(id: String, website: String, url: String, username: String, password: String?) {
        guard let vault else { return }
        do {
            try vault.updateEntry(id: id, website: website, url: url, username: username, password: password)
            try reload()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func deleteEntry(id: String) {
        guard let vault else { return }
        do {
            try vault.deleteEntry(id: id)
            try reload()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func setTOTP(entryId: String, otpauthURI: String) {
        guard let vault else { return }
        do {
            try vault.setTOTP(entryId: entryId, otpauthURI: otpauthURI)
            try reload()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func clearTOTP(entryId: String) {
        guard let vault else { return }
        do {
            try vault.clearTOTP(entryId: entryId)
            try reload()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func merge(otherPath: String) {
        guard let vault else { return }
        do {
            let summary = try vault.merge(fromFile: otherPath)
            try reload()
            statusMessage = "Merged — created \(summary.created), updated \(summary.updated), \(summary.deleted) deleted."
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    // MARK: - Picking a vault file

    /// Handles a vault file the user picked via `.fileImporter`. On iOS the
    /// picked URL is security-scoped and not guaranteed to stay valid
    /// across app launches or the many separate FFI calls a session makes,
    /// so it's copied into the app's own Documents directory first; on
    /// macOS (assumed not App-Sandboxed — see the setup README) the path
    /// is used directly.
    func importVaultFile(from url: URL) {
        #if os(iOS)
        let didAccess = url.startAccessingSecurityScopedResource()
        defer { if didAccess { url.stopAccessingSecurityScopedResource() } }

        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let destination = documents.appendingPathComponent(url.lastPathComponent)
        do {
            if FileManager.default.fileExists(atPath: destination.path) {
                try FileManager.default.removeItem(at: destination)
            }
            try FileManager.default.copyItem(at: url, to: destination)
            vaultPath = destination.path
        } catch {
            errorMessage = "Failed to import vault: \(error.localizedDescription)"
        }
        #else
        vaultPath = url.path
        #endif
    }
}
