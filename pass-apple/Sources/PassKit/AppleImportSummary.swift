/// Result of an Apple Passwords import, mirroring the `*_out` parameters of
/// `vault_import_apple_passwords_csv` in passlib_ffi.h.
public struct AppleImportSummary: Equatable, Sendable {
    /// Logins added to the vault.
    public let imported: Int
    /// Logins the vault already had (same username, password and site).
    public let alreadyPresent: Int
    /// CSV rows skipped because they had no password.
    public let skipped: Int
}
