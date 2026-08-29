import Foundation
import LocalAuthentication
import Security

/// Stores a vault's master password in the Keychain behind Face ID/Touch ID
/// (keyed by vault path), so `UnlockView` can offer a biometric unlock
/// button instead of retyping the password every launch.
///
/// This doesn't change how the vault itself is encrypted — passlib always
/// requires the real master password to open the KDBX4 file; this only
/// guards *locally retrieving* that password using the device's existing
/// biometric enrollment, the same pattern system apps like Mail/Notes use
/// for "Unlock with Face ID".
enum BiometricUnlock {
    private static let service = "it.antoniopicone.Pass.vault-password"

    static func isAvailable() -> Bool {
        LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }

    /// "Face ID", "Touch ID", "Optic ID", or a generic fallback — whichever
    /// this device actually has enrolled.
    static func biometryLabel() -> String {
        let context = LAContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        switch context.biometryType {
        case .faceID: return "Face ID"
        case .touchID: return "Touch ID"
        case .opticID: return "Optic ID"
        default: return "Biometrics"
        }
    }

    static func biometryIcon() -> String {
        let context = LAContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        switch context.biometryType {
        case .faceID: return "faceid"
        case .touchID: return "touchid"
        case .opticID: return "opticid"
        default: return "lock.shield"
        }
    }

    /// Whether a biometric-protected password is already stored for this
    /// vault path. Checked without triggering a Face ID/Touch ID prompt.
    static func hasStoredPassword(forVaultPath path: String) -> Bool {
        var query = baseQuery(forVaultPath: path)
        query[kSecReturnData as String] = false
        query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        // `errSecInteractionNotAllowed` means the item exists but would
        // need biometric auth to read — i.e. it's still present.
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    /// Removes the biometric-protected password for this vault path, if any.
    static func forget(vaultPath path: String) {
        SecItemDelete(baseQuery(forVaultPath: path) as CFDictionary)
    }

    /// Stores `password` in the Keychain, gated behind Face ID/Touch ID (or
    /// the device passcode as LocalAuthentication's own fallback), for the
    /// given vault path. Replaces any existing entry for that path.
    static func store(password: String, forVaultPath path: String) throws {
        forget(vaultPath: path)

        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.biometryCurrentSet],
            nil
        ) else {
            throw BiometricError.accessControlCreationFailed
        }

        var query = baseQuery(forVaultPath: path)
        query[kSecValueData as String] = Data(password.utf8)
        query[kSecAttrAccessControl as String] = access

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw BiometricError.keychain(status)
        }
    }

    /// Prompts Face ID/Touch ID and, on success, returns the stored
    /// password for this vault path.
    static func retrievePassword(forVaultPath path: String) async throws -> String {
        let context = LAContext()
        context.localizedReason = "Unlock your Pass vault"

        var query = baseQuery(forVaultPath: path)
        query[kSecReturnData as String] = true
        query[kSecUseAuthenticationContext as String] = context

        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                var result: AnyObject?
                let status = SecItemCopyMatching(query as CFDictionary, &result)
                guard status == errSecSuccess, let data = result as? Data,
                      let password = String(data: data, encoding: .utf8) else {
                    continuation.resume(throwing: BiometricError.keychain(status))
                    return
                }
                continuation.resume(returning: password)
            }
        }
    }

    private static func baseQuery(forVaultPath path: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: path,
            // On macOS, SecItem* targets the legacy file-based keychain by
            // default, which doesn't support biometric access control at
            // all — SecItemAdd fails outright for a `.biometryCurrentSet`
            // item without this. iOS only has the Data Protection Keychain,
            // so this is a no-op there.
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    enum BiometricError: Error, LocalizedError {
        case accessControlCreationFailed
        case keychain(OSStatus)

        var errorDescription: String? {
            switch self {
            case .accessControlCreationFailed:
                return "Could not set up biometric protection."
            case .keychain(let status):
                let message = (SecCopyErrorMessageString(status, nil) as String?) ?? "Unknown error"
                return "\(message) (Keychain status \(status))"
            }
        }
    }
}
