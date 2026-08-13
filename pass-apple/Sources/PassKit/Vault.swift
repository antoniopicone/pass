import Foundation
import PassKitFFI

/// An open (decrypted) KDBX4 password vault, backed by `passlib_ffi`.
///
/// Every call here is synchronous and touches disk (each mutating call
/// re-saves the vault, matching the other `pass` clients) — callers on
/// iOS/macOS should invoke these off the main thread for anything beyond a
/// handful of entries. `deinit` frees the underlying Rust `CVault` exactly
/// once, so don't keep raw handles around outside this type.
///
/// `@unchecked Sendable` only asserts that *handing this instance across
/// actors* is fine, not that concurrent calls into it are — the
/// underlying Rust vault isn't synchronized, so all calls on one instance
/// still need to come from a single serialized context (this package's
/// intended use is one vault, driven from `@MainActor`, as `AppState` does).
public final class Vault: @unchecked Sendable {
    private let handle: OpaquePointer
    private let path: String

    private init(handle: OpaquePointer, path: String) {
        self.handle = handle
        self.path = path
    }

    deinit {
        vault_free(handle)
    }

    /// The path this vault was opened/created at.
    public var vaultPath: String { path }

    /// Create a new KDBX4 vault file. Fails with `PassError.vaultExists` if
    /// `path` already exists.
    public static func create(atPath path: String, masterPassword: String) throws -> Vault {
        var handle: OpaquePointer?
        let result = withCStrings([path, masterPassword]) { ptrs in
            vault_init(ptrs[0], ptrs[1], &handle)
        }
        try check(result)
        guard let handle else { throw PassError.unknown }
        return Vault(handle: handle, path: path)
    }

    /// Unlock an existing KDBX4 vault file with its master password.
    public static func unlock(atPath path: String, masterPassword: String) throws -> Vault {
        var handle: OpaquePointer?
        let result = withCStrings([path, masterPassword]) { ptrs in
            vault_unlock(ptrs[0], ptrs[1], &handle)
        }
        try check(result)
        guard let handle else { throw PassError.unknown }
        return Vault(handle: handle, path: path)
    }

    /// Add a new entry and persist the vault. Returns the new entry's ID.
    @discardableResult
    public func addEntry(website: String, url: String, username: String, password: String) throws -> String {
        var idPtr: UnsafeMutablePointer<CChar>?
        let result = withCStrings([website, url, username, password]) { ptrs in
            vault_add_entry(handle, ptrs[0], ptrs[1], ptrs[2], ptrs[3], &idPtr)
        }
        try check(result)
        guard let idPtr else { throw PassError.unknown }
        defer { string_free(idPtr) }
        return String(cString: idPtr)
    }

    /// All entries in the vault (excluding anything in the Recycle Bin),
    /// including their plaintext passwords — this mirrors `vault_list_entries`,
    /// which doesn't have a lighter password-free summary at the C boundary.
    public func listEntries() throws -> [PasswordEntry] {
        var listPtr: UnsafeMutablePointer<CPasswordEntryList>?
        let result = vault_list_entries(handle, &listPtr)
        try check(result)
        guard let listPtr else { return [] }
        defer { entry_list_free(listPtr) }

        let list = listPtr.pointee
        guard let entriesPtr = list.entries, list.count > 0 else { return [] }

        let buffer = UnsafeBufferPointer(start: entriesPtr, count: list.count)
        return buffer.map { PasswordEntry(cEntry: $0) }
    }

    /// A specific entry by ID.
    public func getEntry(id: String) throws -> PasswordEntry {
        var entryPtr: UnsafeMutablePointer<CPasswordEntry>?
        let result = withCStrings([id]) { ptrs in
            vault_get_entry(handle, ptrs[0], &entryPtr)
        }
        try check(result)
        guard let entryPtr else { throw PassError.unknown }
        defer { entry_free(entryPtr) }
        return PasswordEntry(cEntry: entryPtr.pointee)
    }

    /// Update an entry's fields and persist the vault. `website`/`url`/
    /// `username` are always re-supplied (the C API has no partial-update
    /// form for them); pass `password: nil` to leave the password unchanged.
    public func updateEntry(id: String, website: String, url: String, username: String, password: String?) throws {
        let result = withCStrings([id, website, url, username, password]) { ptrs in
            vault_update_entry(handle, ptrs[0], ptrs[1], ptrs[2], ptrs[3], ptrs[4])
        }
        try check(result)
    }

    /// Move an entry to the Recycle Bin and persist the vault.
    public func deleteEntry(id: String) throws {
        let result = withCStrings([id]) { ptrs in
            vault_delete_entry(handle, ptrs[0])
        }
        try check(result)
    }

    /// Attach (or replace) an entry's MFA/TOTP secret from an `otpauth://`
    /// URI and persist the vault.
    public func setTOTP(entryId: String, otpauthURI: String) throws {
        let result = withCStrings([entryId, otpauthURI]) { ptrs in
            vault_set_entry_totp_uri(handle, ptrs[0], ptrs[1])
        }
        try check(result)
    }

    /// Remove an entry's MFA/TOTP secret, if any, and persist the vault.
    public func clearTOTP(entryId: String) throws {
        let result = withCStrings([entryId]) { ptrs in
            vault_clear_entry_totp(handle, ptrs[0])
        }
        try check(result)
    }

    /// Merge another copy of this vault (e.g. one synced via Nextcloud)
    /// into this one and persist the result.
    public func merge(fromFile otherPath: String) throws -> MergeSummary {
        // `size_t` imports as `UInt` in Swift, not `Int`.
        var created: UInt = 0
        var updated: UInt = 0
        var unchanged: UInt = 0
        var deleted: UInt = 0

        let result = otherPath.withCString { pathPtr in
            withUnsafeMutablePointer(to: &created) { createdPtr in
                withUnsafeMutablePointer(to: &updated) { updatedPtr in
                    withUnsafeMutablePointer(to: &unchanged) { unchangedPtr in
                        withUnsafeMutablePointer(to: &deleted) { deletedPtr in
                            vault_merge_from_file(handle, pathPtr, createdPtr, updatedPtr, unchangedPtr, deletedPtr)
                        }
                    }
                }
            }
        }
        try check(result)

        return MergeSummary(
            created: Int(created),
            updated: Int(updated),
            unchanged: Int(unchanged),
            deleted: Int(deleted)
        )
    }
}
