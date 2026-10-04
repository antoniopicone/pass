import AuthenticationServices
import Foundation
import PassKit

/// Matches vault entries to the website AutoFill is asking about, by host:
/// `github.com` matches requests for `github.com` and `gist.github.com`,
/// ignoring a leading `www.` — the same normalization passlib uses to spot
/// duplicates when importing from Apple Passwords.
enum SiteMatcher {
    /// Lowercased host of `urlString` without `www.`, tolerating a missing
    /// scheme ("github.com/login").
    static func host(of urlString: String) -> String? {
        let trimmed = urlString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let withScheme = trimmed.contains("://") ? trimmed : "https://" + trimmed
        guard var host = URLComponents(string: withScheme)?.host?.lowercased(), !host.isEmpty else { return nil }
        if host.hasPrefix("www.") {
            host.removeFirst(4)
        }
        return host
    }

    /// Every distinct host an entry belongs to (its URL and additional URLs).
    static func hosts(of entry: PasswordEntry) -> [String] {
        var result: [String] = []
        for url in [entry.url] + entry.additionalUrls {
            if let host = host(of: url), !result.contains(host) {
                result.append(host)
            }
        }
        return result
    }

    /// The hosts AutoFill is asking for.
    static func requestedHosts(_ identifiers: [ASCredentialServiceIdentifier]) -> [String] {
        identifiers.compactMap { identifier in
            switch identifier.type {
            case .domain:
                return host(of: identifier.identifier)
            case .URL:
                return host(of: identifier.identifier)
            @unknown default:
                return nil
            }
        }
    }

    static func matches(_ entry: PasswordEntry, requestedHosts: [String]) -> Bool {
        let entryHosts = hosts(of: entry)
        return requestedHosts.contains { requested in
            entryHosts.contains { host in
                requested == host || requested.hasSuffix("." + host) || host.hasSuffix("." + requested)
            }
        }
    }
}
