import PassKit
import SwiftUI

/// The AutoFill extension's UI: unlock, then pick a login (or a
/// verification code) — suggestions for the current site first.
struct AutoFillView: View {
    @ObservedObject var model: AutoFillModel

    var body: some View {
        NavigationStack {
            content
                .navigationTitle(model.wantsOneTimeCode ? "Verification Codes" : "Pass")
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { model.cancel() }
                    }
                }
        }
    }

    @ViewBuilder
    private var content: some View {
        if !model.isVaultReachable {
            ContentUnavailableView(
                "Vault Not Available",
                systemImage: "externaldrive.badge.xmark",
                description: Text("Open Pass and choose Settings → Move Vault to Shared Container, so AutoFill can read it.")
            )
        } else {
            switch model.phase {
            case .locked:
                UnlockForm(model: model)
            case .unlocking:
                ProgressView("Unlocking…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            case .unlocked:
                if model.isProvidingSpecificEntry {
                    statusOrProgress
                } else {
                    EntryPicker(model: model)
                }
            }
        }
    }

    @ViewBuilder
    private var statusOrProgress: some View {
        if let error = model.errorMessage {
            ContentUnavailableView("Can't Fill", systemImage: "exclamationmark.triangle", description: Text(error))
        } else {
            ProgressView()
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

private struct UnlockForm: View {
    @ObservedObject var model: AutoFillModel

    var body: some View {
        Form {
            if model.canUseBiometrics {
                Section {
                    Button {
                        Task { await model.unlockWithBiometrics() }
                    } label: {
                        Label("Unlock with \(BiometricUnlock.biometryLabel())", systemImage: BiometricUnlock.biometryIcon())
                    }
                }
            }
            Section {
                SecureField("Master password", text: $model.masterPassword)
                    .onSubmit { model.unlockWithMasterPassword() }
                Button("Unlock") { model.unlockWithMasterPassword() }
                    .disabled(model.masterPassword.isEmpty)
            } footer: {
                Text(URL(fileURLWithPath: model.vaultPath).lastPathComponent)
            }
            if let error = model.errorMessage {
                Section {
                    Text(error)
                        .font(.footnote)
                        .foregroundStyle(.red)
                }
            }
        }
        .formStyle(.grouped)
    }
}

private struct EntryPicker: View {
    @ObservedObject var model: AutoFillModel

    var body: some View {
        List {
            let suggested = model.suggestedEntries
            if !suggested.isEmpty {
                Section(suggestedHeader) {
                    ForEach(suggested) { entry in row(for: entry) }
                }
            }
            let others = model.otherEntries
            if !others.isEmpty {
                Section(suggested.isEmpty ? "Logins" : "Other Logins") {
                    ForEach(others) { entry in row(for: entry) }
                }
            }
            if suggested.isEmpty && others.isEmpty {
                Text(model.wantsOneTimeCode ? "No logins with a verification code." : "No matching logins.")
                    .foregroundStyle(.secondary)
            }
            if let error = model.errorMessage {
                Text(error)
                    .font(.footnote)
                    .foregroundStyle(.red)
            }
        }
        .searchable(text: $model.searchText, prompt: "Search logins")
    }

    private var suggestedHeader: String {
        guard let host = model.requestedHosts.first else { return "Suggested" }
        return "For \(host)"
    }

    private func row(for entry: PasswordEntry) -> some View {
        Button {
            model.select(entry)
        } label: {
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.website)
                    .font(.headline)
                Text(entry.username.isEmpty ? entry.url : entry.username)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}
