import AuthenticationServices
import Foundation
import PassKit

/// State behind the AutoFill extension's UI: unlocking the vault, listing
/// the logins that fit the site being filled, and turning the one the user
/// picks into a `Result` for `CredentialProviderViewController`.
@MainActor
final class AutoFillModel: ObservableObject {
    enum Request {
        /// Show the list of logins, the ones for these sites first.
        case chooseLogin([ASCredentialServiceIdentifier])
        /// Show the logins with a verification code, for these sites first.
        case chooseOneTimeCode([ASCredentialServiceIdentifier])
        /// Fill this entry (a suggestion the user already picked).
        case provide(entryID: String?, oneTimeCode: Bool)
    }

    enum Result {
        case login(user: String, password: String)
        case oneTimeCode(String)
    }

    enum Phase {
        case locked
        case unlocking
        case unlocked
    }

    @Published private(set) var phase: Phase = .locked
    @Published private(set) var entries: [PasswordEntry] = []
    @Published var searchText = ""
    @Published var masterPassword = ""
    @Published var errorMessage: String?

    let vaultPath: String
    private(set) var request: Request = .chooseLogin([])
    private var vault: Vault?
    private let completeHandler: (Result) -> Void
    private let cancelHandler: () -> Void

    init(vaultPath: String, complete: @escaping (Result) -> Void, cancel: @escaping () -> Void) {
        self.vaultPath = vaultPath
        self.completeHandler = complete
        self.cancelHandler = cancel
    }

    // MARK: - Request

    func start(_ request: Request) {
        self.request = request
        errorMessage = nil
        if canUseBiometrics {
            Task { await unlockWithBiometrics() }
        }
    }

    var wantsOneTimeCode: Bool {
        switch request {
        case .chooseOneTimeCode: return true
        case let .provide(_, oneTimeCode): return oneTimeCode
        case .chooseLogin: return false
        }
    }

    var isProvidingSpecificEntry: Bool {
        if case .provide = request { return true }
        return false
    }

    /// The sites being filled, for the "Suggested" section header.
    var requestedHosts: [String] {
        switch request {
        case let .chooseLogin(ids), let .chooseOneTimeCode(ids):
            return SiteMatcher.requestedHosts(ids)
        case .provide:
            return []
        }
    }

    // MARK: - Unlocking

    /// Whether the vault file is where the extension can read it: inside the
    /// App Group container (the app's Settings offers to move it there).
    var isVaultReachable: Bool {
        FileManager.default.isReadableFile(atPath: vaultPath)
    }

    var canUseBiometrics: Bool {
        BiometricUnlock.isAvailable() && BiometricUnlock.hasStoredPassword(forVaultPath: vaultPath)
    }

    func unlockWithBiometrics() async {
        do {
            let password = try await BiometricUnlock.retrievePassword(forVaultPath: vaultPath)
            await open(with: password)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func unlockWithMasterPassword() {
        let password = masterPassword
        masterPassword = ""
        Task { await open(with: password) }
    }

    /// Opening the KDBX file runs Argon2, which takes a moment — done off
    /// the main actor so the UI keeps showing progress.
    private func open(with password: String) async {
        phase = .unlocking
        let path = vaultPath
        let opened = await Task.detached(priority: .userInitiated) {
            Swift.Result { try Vault.unlock(atPath: path, masterPassword: password) }
        }.value

        switch opened {
        case let .success(vault):
            self.vault = vault
            entries = ((try? vault.listEntries()) ?? [])
                .sorted { $0.website.localizedCaseInsensitiveCompare($1.website) == .orderedAscending }
            phase = .unlocked
            // The vault may have changed since the app last ran (CLI,
            // Chrome, other devices via pass-syncd): refresh the system's
            // suggestions while we have it open.
            CredentialIdentities.replace(with: entries)
            if case let .provide(entryID, _) = request {
                provide(entryID: entryID)
            }
        case let .failure(error):
            phase = .locked
            errorMessage = error.localizedDescription
        }
    }

    // MARK: - Choosing

    private var candidates: [PasswordEntry] {
        let base = wantsOneTimeCode ? entries.filter { $0.totp != nil } : entries
        let query = searchText.trimmingCharacters(in: .whitespaces).lowercased()
        guard !query.isEmpty else { return base }
        return base.filter {
            $0.website.lowercased().contains(query)
                || $0.username.lowercased().contains(query)
                || $0.url.lowercased().contains(query)
        }
    }

    var suggestedEntries: [PasswordEntry] {
        let hosts = requestedHosts
        guard !hosts.isEmpty else { return [] }
        return candidates.filter { SiteMatcher.matches($0, requestedHosts: hosts) }
    }

    var otherEntries: [PasswordEntry] {
        let suggestedIDs = Set(suggestedEntries.map(\.id))
        return candidates.filter { !suggestedIDs.contains($0.id) }
    }

    func select(_ entry: PasswordEntry) {
        if wantsOneTimeCode {
            // Re-read the entry: the code in `entries` was computed at
            // unlock time and may have rolled over since.
            guard let code = (try? vault?.getEntry(id: entry.id))?.totp?.code else {
                errorMessage = "This login has no verification code."
                return
            }
            completeHandler(.oneTimeCode(code))
        } else {
            completeHandler(.login(user: entry.username, password: entry.password))
        }
    }

    private func provide(entryID: String?) {
        guard let entryID, let entry = try? vault?.getEntry(id: entryID) else {
            errorMessage = "This login is no longer in your vault."
            return
        }
        select(entry)
    }

    func cancel() {
        cancelHandler()
    }
}
