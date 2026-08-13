import SwiftUI

struct EntryDetailView: View {
    let entryId: String

    @EnvironmentObject private var state: AppState
    @State private var entry: PasswordEntry?
    @State private var passwordRevealed = false
    @State private var showEditSheet = false
    @State private var showDeleteConfirm = false
    @State private var showTOTPAttachSheet = false
    @State private var totpTimer: Timer?

    var body: some View {
        Group {
            if let entry {
                Form {
                    Section("Details") {
                        LabeledContent("Website", value: entry.website)
                        LabeledContent("URL", value: entry.url)
                        HStack {
                            LabeledContent("Username", value: entry.username)
                            Spacer()
                            CopyButton { Clipboard.copy(entry.username) }
                        }
                        HStack {
                            LabeledContent("Password", value: passwordRevealed ? entry.password : String(repeating: "•", count: 10))
                            Spacer()
                            Button {
                                passwordRevealed.toggle()
                            } label: {
                                Image(systemName: passwordRevealed ? "eye.slash" : "eye")
                            }
                            .buttonStyle(.borderless)
                            CopyButton { Clipboard.copy(entry.password) }
                        }
                    }

                    Section("MFA Code") {
                        if let totp = entry.totp {
                            HStack {
                                VStack(alignment: .leading) {
                                    Text(totp.code)
                                        .font(.title2.monospaced().bold())
                                    Text("Expires in \(totp.secondsRemaining)s")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                CopyButton { Clipboard.copy(totp.code) }
                            }
                            Button("Remove MFA Code", role: .destructive) {
                                state.clearTOTP(entryId: entryId)
                                reload()
                            }
                        } else {
                            Button("Add MFA Code…") {
                                showTOTPAttachSheet = true
                            }
                        }
                    }

                    Section {
                        LabeledContent("Created", value: entry.createdAt.formatted(date: .abbreviated, time: .shortened))
                        LabeledContent("Updated", value: entry.updatedAt.formatted(date: .abbreviated, time: .shortened))
                    }
                }
                .formStyle(.grouped)
                .navigationTitle(entry.website)
                .toolbar {
                    ToolbarItem(placement: .primaryAction) {
                        Menu {
                            Button("Edit") { showEditSheet = true }
                            Button("Delete", role: .destructive) { showDeleteConfirm = true }
                        } label: {
                            Label("Actions", systemImage: "ellipsis.circle")
                        }
                    }
                }
                .confirmationDialog(
                    "Delete \"\(entry.website)\"?",
                    isPresented: $showDeleteConfirm,
                    titleVisibility: .visible
                ) {
                    Button("Delete", role: .destructive) {
                        state.deleteEntry(id: entryId)
                    }
                    Button("Cancel", role: .cancel) {}
                } message: {
                    Text("It will be moved to the vault's Recycle Bin.")
                }
                .sheet(isPresented: $showEditSheet, onDismiss: reload) {
                    EntryFormView(mode: .edit(entry))
                }
                .sheet(isPresented: $showTOTPAttachSheet, onDismiss: reload) {
                    TOTPAttachView(entryId: entryId)
                }
            } else {
                ContentUnavailableView("Entry Not Found", systemImage: "questionmark.circle")
            }
        }
        .onAppear {
            reload()
            startLiveRefreshTimer()
        }
        .onDisappear {
            totpTimer?.invalidate()
            totpTimer = nil
        }
    }

    private func reload() {
        entry = state.fetchEntry(id: entryId) ?? state.entry(id: entryId)
    }

    /// Ticks once a second so the MFA code's countdown (and the code
    /// itself, once it rolls over) stay live while this view is visible.
    private func startLiveRefreshTimer() {
        totpTimer?.invalidate()
        totpTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in
            Task { @MainActor in
                guard let fresh = state.fetchEntry(id: entryId) else { return }
                entry = fresh
            }
        }
    }
}

private struct CopyButton: View {
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: "doc.on.doc")
        }
        .buttonStyle(.borderless)
    }
}
