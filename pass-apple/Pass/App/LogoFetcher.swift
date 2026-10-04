import Foundation
import SwiftUI

#if os(macOS)
import AppKit
private typealias PlatformColor = NSColor
private typealias PlatformFont = NSFont
private typealias PlatformBezierPath = NSBezierPath
#else
import UIKit
private typealias PlatformColor = UIColor
private typealias PlatformFont = UIFont
private typealias PlatformBezierPath = UIBezierPath
#endif

/// Generates website icons locally using site name and deterministic colors
@MainActor
final class LogoFetcher: ObservableObject {
    @Published private(set) var logos: [String: Image] = [:]

    /// Returns an Image for the given website, generating it locally
    func logo(forWebsite website: String) -> Image {
        if let cached = logos[website] {
            return cached
        }

        let icon = generateIcon(for: website)
        logos[website] = icon
        return icon
    }

    private func generateIcon(for website: String) -> Image {
        let initials = extractInitials(from: website)
        let backgroundColor = generateColor(from: website)

        let size: CGFloat = 64
        let rect = CGRect(x: 0, y: 0, width: size, height: size)

        let draw = {
            // Draw background circle
            let path = PlatformBezierPath(ovalIn: rect)
            backgroundColor.setFill()
            path.fill()

            // Draw initials
            let textColor = PlatformColor.white
            let attributes: [NSAttributedString.Key: Any] = [
                .font: PlatformFont.systemFont(ofSize: 24, weight: .bold),
                .foregroundColor: textColor
            ]

            let attributedString = NSAttributedString(string: initials, attributes: attributes)
            let textSize = attributedString.size()
            let textRect = CGRect(
                x: (rect.width - textSize.width) / 2,
                y: (rect.height - textSize.height) / 2,
                width: textSize.width,
                height: textSize.height
            )
            attributedString.draw(in: textRect)
        }

        #if os(macOS)
        let image = NSImage(size: rect.size)
        image.lockFocus()
        draw()
        image.unlockFocus()
        return Image(nsImage: image)
        #else
        let image = UIGraphicsImageRenderer(size: rect.size).image { _ in draw() }
        return Image(uiImage: image)
        #endif
    }

    private func extractInitials(from website: String) -> String {
        // Extract domain name for initials
        let domain = extractDomain(from: website) ?? website

        // Get the first part before the dot (e.g., "github" from "github.com")
        let mainName = domain.components(separatedBy: ".").first ?? domain

        // Take first 1-2 characters
        if mainName.count >= 2 {
            let index = mainName.index(mainName.startIndex, offsetBy: 2)
            return String(mainName[..<index]).uppercased()
        } else {
            return mainName.uppercased()
        }
    }

    private func generateColor(from website: String) -> PlatformColor {
        // Generate a deterministic color based on the website name
        let domain = extractDomain(from: website) ?? website
        let hash = domain.hashValue

        // Use the hash to generate RGB values
        let r = CGFloat((hash & 0xFF0000) >> 16) / 255.0
        let g = CGFloat((hash & 0x00FF00) >> 8) / 255.0
        let b = CGFloat(hash & 0x0000FF) / 255.0

        // Ensure colors are not too light or too dark
        let brightness = (r * 299 + g * 587 + b * 114) / 1000
        let factor: CGFloat = brightness > 0.7 ? 0.7 : (brightness < 0.3 ? 1.3 : 1.0)

        return PlatformColor(
            red: min(r * factor, 1.0),
            green: min(g * factor, 1.0),
            blue: min(b * factor, 1.0),
            alpha: 1.0
        )
    }

    private func extractDomain(from website: String) -> String? {
        // Try to extract domain from website field
        if let url = URL(string: website) {
            return url.host
        }

        // If website is not a valid URL, try adding https://
        if let url = URL(string: "https://\(website)") {
            return url.host
        }

        return nil
    }
}
