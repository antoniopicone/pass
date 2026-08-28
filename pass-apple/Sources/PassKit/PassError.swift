import Foundation
import PassKitFFI

/// Swift-facing errors mirroring `PassResult` from passlib_ffi.h.
public enum PassError: Error, LocalizedError, Equatable {
    case invalidPassword
    case vaultNotFound
    case vaultExists
    case entryNotFound
    case invalidInput
    /// A failure that doesn't map to a specific `PassResult` code, carrying
    /// the underlying Rust error's message when available (from
    /// `passlib_last_error_message`) — e.g. why a vault file failed to
    /// parse as valid KDBX4, or why a save to disk failed.
    case unknown(detail: String?)

    public var errorDescription: String? {
        switch self {
        case .invalidPassword:
            return "Incorrect master password."
        case .vaultNotFound:
            return "Vault file not found."
        case .vaultExists:
            return "A vault already exists at that location."
        case .entryNotFound:
            return "Entry not found."
        case .invalidInput:
            return "Invalid input."
        case .unknown(let detail):
            if let detail {
                return detail
            }
            return "Something went wrong."
        }
    }

    init(rawResult: PassResult) {
        switch rawResult {
        case PassResultErrorInvalidPassword:
            self = .invalidPassword
        case PassResultErrorVaultNotFound:
            self = .vaultNotFound
        case PassResultErrorVaultExists:
            self = .vaultExists
        case PassResultErrorEntryNotFound:
            self = .entryNotFound
        case PassResultErrorInvalidInput:
            self = .invalidInput
        default:
            self = .unknown(detail: PassError.consumeLastErrorMessage())
        }
    }

    private static func consumeLastErrorMessage() -> String? {
        guard let ptr = passlib_last_error_message() else { return nil }
        defer { string_free(ptr) }
        return String(cString: ptr)
    }
}

/// Throws a `PassError` if `result` isn't `PassResultSuccess`.
func check(_ result: PassResult) throws {
    guard result == PassResultSuccess else {
        throw PassError(rawResult: result)
    }
}
