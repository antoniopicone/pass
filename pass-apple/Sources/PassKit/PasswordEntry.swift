import Foundation
import PassKitFFI

/// The current TOTP/MFA code for an entry, as computed by passlib at the
/// moment the entry was fetched (not live-updating on its own — re-fetch
/// the entry, e.g. on a 1-second timer, to refresh it).
public struct TOTPStatus: Equatable, Sendable {
    public let code: String
    public let secondsRemaining: Int
}

/// A password entry, mirroring `CPasswordEntry` from passlib_ffi.h.
///
/// `passlib_ffi`'s list/get calls both return the full entry including the
/// plaintext password (there's no separate lighter "summary" type at the C
/// boundary), so this one struct covers both list rows and detail views.
public struct PasswordEntry: Identifiable, Equatable, Sendable {
    public let id: String
    public let website: String
    public let url: String
    public let username: String
    public let password: String
    public let notes: String
    public let additionalUrls: [String]
    public let createdAt: Date
    public let updatedAt: Date
    public let totp: TOTPStatus?

    /// Builds a Swift value from a `CPasswordEntry` *before* it's freed.
    /// Copies every string out immediately — nothing here keeps pointers
    /// from the C struct alive past this initializer.
    init(cEntry: CPasswordEntry) {
        self.id = String(cString: cEntry.id)
        self.website = String(cString: cEntry.website)
        self.url = String(cString: cEntry.url)
        self.username = String(cString: cEntry.username)
        self.password = String(cString: cEntry.password)
        self.notes = String(cString: cEntry.notes)
        self.additionalUrls = String(cString: cEntry.additional_urls)
            .split(separator: "\n")
            .map(String.init)
        self.createdAt = Date(timeIntervalSince1970: TimeInterval(cEntry.created_at))
        self.updatedAt = Date(timeIntervalSince1970: TimeInterval(cEntry.updated_at))

        if cEntry.has_totp, let codePtr = cEntry.totp_code {
            self.totp = TOTPStatus(
                code: String(cString: codePtr),
                secondsRemaining: Int(cEntry.totp_seconds_remaining)
            )
        } else {
            self.totp = nil
        }
    }
}

/// One previous password from an entry's KDBX4 history, newest first.
public struct PasswordHistoryEntry: Identifiable, Equatable, Sendable {
    public var id: Date { changedAt }
    public let password: String
    public let changedAt: Date

    init(cEntry: CPasswordHistoryEntry) {
        self.password = String(cString: cEntry.password)
        self.changedAt = Date(timeIntervalSince1970: TimeInterval(cEntry.changed_at))
    }
}
