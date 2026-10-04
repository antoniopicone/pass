import PassKit
import SwiftUI

struct EntryListView: View {
    @EnvironmentObject private var state: AppState
    @StateObject private var logoFetcher = LogoFetcher()

    @State private var searchText = ""
    @State private var showAddSheet = false
    @State private var showMergeSheet = false
    @State private var showAppleImportSheet = false
    @State private var showSettingsSheet = false
    @State private var selectedEntry: PasswordEntry?

    private var filteredEntries: [PasswordEntry] {
        guard !searchText.isEmpty else { return state.entries }
        let query = searchText.lowercased()
        return state.entries.filter {
            $0.website.lowercased().contains(query)
                || $0.username.lowercased().contains(query)
                || $0.url.lowercased().contains(query)
        }
    }

    var body: some View {
        NavigationSplitView {
            VStack(spacing: 8) {
                HStack {
                    Image(systemName: "magnifyingglass")
                        .foregroundStyle(.secondary)
                    TextField("Search entries", text: $searchText)
                        .textFieldStyle(.plain)
                }
                .padding(.horizontal)
                .padding(.vertical, 8)

                List(selection: $selectedEntry) {
                    if filteredEntries.isEmpty {
                        ContentUnavailableView(
                            state.entries.isEmpty ? "No Entries Yet" : "No Matches",
                            systemImage: "key.fill",
                            description: Text(state.entries.isEmpty ? "Add your first password entry." : "Try a different search.")
                        )
                    } else {
                        ForEach(filteredEntries) { entry in
                            NavigationLink(value: entry) {
                                EntryRow(entry: entry, logoFetcher: logoFetcher)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Pass")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        showAddSheet = true
                    } label: {
                        Label("Add Entry", systemImage: "plus")
                    }
                }
                ToolbarItem(placement: .secondaryAction) {
                    Menu {
                        Button {
                            showMergeSheet = true
                        } label: {
                            Label("Merge From File…", systemImage: "arrow.triangle.merge")
                        }
                        Button {
                            showAppleImportSheet = true
                        } label: {
                            Label("Import from Apple Passwords…", systemImage: "key.icloud")
                        }
                        Button {
                            showSettingsSheet = true
                        } label: {
                            Label("Settings…", systemImage: "gearshape")
                        }
                        Button(role: .destructive) {
                            state.lock()
                        } label: {
                            Label("Lock", systemImage: "lock.fill")
                        }
                    } label: {
                        Label("More", systemImage: "ellipsis.circle")
                    }
                }
            }
            .sheet(isPresented: $showAddSheet) {
                EntryFormView(mode: .add)
            }
            .sheet(isPresented: $showMergeSheet) {
                MergeView()
            }
            .sheet(isPresented: $showAppleImportSheet) {
                AppleImportView()
            }
            .sheet(isPresented: $showSettingsSheet) {
                SettingsView()
            }
            .overlay(alignment: .bottom) {
                if let status = state.statusMessage {
                    StatusBanner(text: status) { state.statusMessage = nil }
                }
            }
        } detail: {
            // Keeps the detail pane in sync when the selected entry is
            // deleted (or moved to the Recycle Bin) out from under it —
            // `state.entries` already excludes recycled entries.
            if let selectedEntry, state.entries.contains(where: { $0.id == selectedEntry.id }) {
                EntryDetailView(entryId: selectedEntry.id)
                    .id(selectedEntry.id)
            } else {
                ContentUnavailableView(
                    "No Entry Selected",
                    systemImage: "key.fill",
                    description: Text("Select an entry from the list to view its details.")
                )
            }
        }
    }
}

private struct EntryRow: View {
    let entry: PasswordEntry
    @ObservedObject var logoFetcher: LogoFetcher

    var body: some View {
        HStack(spacing: 12) {
            logoFetcher.logo(forWebsite: entry.website)
                .resizable()
                .aspectRatio(contentMode: .fit)
                .frame(width: 32, height: 32)
                .clipShape(RoundedRectangle(cornerRadius: 6))

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(entry.website)
                        .font(.headline)
                    if entry.totp != nil {
                        Image(systemName: "lock.shield.fill")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                }
                Text(entry.username)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .contentShape(Rectangle())
    }
}

private struct StatusBanner: View {
    let text: String
    let dismiss: () -> Void

    var body: some View {
        Text(text)
            .font(.footnote)
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 10))
            .padding()
            .onTapGesture(perform: dismiss)
            .task {
                try? await Task.sleep(for: .seconds(5))
                dismiss()
            }
    }
}
