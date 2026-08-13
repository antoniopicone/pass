import Foundation
import PassKitFFI

/// Swift-facing errors mirroring `PassResult` from passlib_ffi.h.
public enum PassError: Error, LocalizedError, Equatable {
    case invalidPassword
    case vaultNotFound
    case vaultExists
    case entryNotFound
    case invalidInput
    case unknown

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
        case .unknown:
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
            self = .unknown
        }
    }
}

/// Throws a `PassError` if `result` isn't `PassResultSuccess`.
func check(_ result: PassResult) throws {
    guard result == PassResultSuccess else {
        throw PassError(rawResult: result)
    }
}
