import AuthenticationServices
import Foundation
import PassKit

/// Keeps the system's AutoFill index (`ASCredentialIdentityStore`) in step
/// with the vault, so iOS/macOS can suggest "username — Pass" right above
/// the keyboard / under the field without unlocking anything first. Only
/// site, username and entry ID go in — never passwords or TOTP secrets;
/// those are read from the vault by the extension after Face ID/Touch ID.
enum CredentialIdentities {
    /// Replaces the whole index with `entries`. Does nothing unless the user
    /// has turned Pass on in AutoFill settings.
    static func replace(with entries: [PasswordEntry]) {
        let identities = makeIdentities(for: entries)
        let store = ASCredentialIdentityStore.shared
        store.getState { state in
            guard state.isEnabled else { return }
            store.replaceCredentialIdentities(identities) { _, error in
                if let error {
                    NSLog("[Pass] Updating AutoFill suggestions failed: \(error)")
                }
            }
        }
    }

    /// Empties the index, e.g. after switching to a different vault.
    static func removeAll() {
        ASCredentialIdentityStore.shared.removeAllCredentialIdentities { _, error in
            if let error {
                NSLog("[Pass] Clearing AutoFill suggestions failed: \(error)")
            }
        }
    }

    static func makeIdentities(for entries: [PasswordEntry]) -> [any ASCredentialIdentity] {
        var identities: [any ASCredentialIdentity] = []
        for entry in entries {
            for host in SiteMatcher.hosts(of: entry) {
                let service = ASCredentialServiceIdentifier(identifier: host, type: .domain)
                identities.append(
                    ASPasswordCredentialIdentity(serviceIdentifier: service, user: entry.username, recordIdentifier: entry.id)
                )
                if entry.totp != nil, #available(iOS 18.0, macOS 15.0, *) {
                    let label = entry.username.isEmpty ? entry.website : entry.username
                    identities.append(
                        ASOneTimeCodeCredentialIdentity(serviceIdentifier: service, label: label, recordIdentifier: entry.id)
                    )
                }
            }
        }
        return identities
    }
}
