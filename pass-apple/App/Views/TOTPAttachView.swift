import PhotosUI
import SwiftUI
import Vision

#if os(iOS)
import UIKit
#elseif os(macOS)
import AppKit
#endif

/// Attach an MFA/TOTP secret to an entry: paste an `otpauth://` URI
/// directly, or pick a QR code photo and decode it with Vision (no
/// third-party QR library needed — `VNDetectBarcodesRequest` is built into
/// iOS/macOS).
struct TOTPAttachView: View {
    let entryId: String

    @EnvironmentObject private var state: AppState
    @Environment(\.dismiss) private var dismiss

    @State private var uri = ""
    @State private var photoItem: PhotosPickerItem?
    @State private var statusText: String?
    @State private var isDecoding = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("Paste the otpauth:// URI from the service's MFA setup page, or scan a QR code photo from your library.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                Section {
                    TextField("otpauth://totp/...", text: $uri)
                        #if os(iOS)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                        #endif
                }

                Section {
                    PhotosPicker("Choose QR Code Photo…", selection: $photoItem, matching: .images)
                    if isDecoding {
                        ProgressView("Scanning…")
                    }
                }

                if let statusText {
                    Section {
                        Text(statusText)
                            .font(.footnote)
                            .foregroundStyle(.red)
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Add MFA Code")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Attach") {
                        state.setTOTP(entryId: entryId, otpauthURI: uri)
                        dismiss()
                    }
                    .disabled(uri.isEmpty)
                }
            }
            .onChange(of: photoItem) { _, newItem in
                guard let newItem else { return }
                decodeQRCode(from: newItem)
            }
        }
    }

    private func decodeQRCode(from item: PhotosPickerItem) {
        isDecoding = true
        statusText = nil

        Task {
            defer { isDecoding = false }
            do {
                guard let data = try await item.loadTransferable(type: Data.self) else {
                    statusText = "Couldn't read that photo."
                    return
                }
                guard let decoded = try Self.decodeQRPayload(from: data) else {
                    statusText = "No QR code found in that photo."
                    return
                }
                uri = decoded
            } catch {
                statusText = "Failed to scan photo: \(error.localizedDescription)"
            }
        }
    }

    private static func decodeQRPayload(from data: Data) throws -> String? {
        guard let cgImage = cgImage(from: data) else { return nil }

        let request = VNDetectBarcodesRequest()
        request.symbologies = [.qr]

        let handler = VNImageRequestHandler(cgImage: cgImage, options: [:])
        try handler.perform([request])

        return request.results?.compactMap { $0.payloadStringValue }.first
    }

    private static func cgImage(from data: Data) -> CGImage? {
        #if os(iOS)
        return UIImage(data: data)?.cgImage
        #elseif os(macOS)
        guard let image = NSImage(data: data) else { return nil }
        var rect = CGRect(origin: .zero, size: image.size)
        return image.cgImage(forProposedRect: &rect, context: nil, hints: nil)
        #else
        return nil
        #endif
    }
}
