import SwiftUI

struct EntryListView: View {
    @EnvironmentObject private var state: AppState

    @State private var searchText = ""
    @State private var showAddSheet = false
    @State private var showMergeSheet = false

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
        NavigationStack {
            List {
                if filteredEntries.isEmpty {
                    ContentUnavailableView(
                        state.entries.isEmpty ? "No Entries Yet" : "No Matches",
                        systemImage: "key.fill",
                        description: Text(state.entries.isEmpty ? "Add your first password entry." : "Try a different search.")
                    )
                } else {
                    ForEach(filteredEntries) { entry in
                        NavigationLink(value: entry.id) {
                            EntryRow(entry: entry)
                        }
                    }
                }
            }
            .navigationTitle("Pass")
            .navigationDestination(for: String.self) { entryId in
                EntryDetailView(entryId: entryId)
            }
            .searchable(text: $searchText, prompt: "Search entries")
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
            .overlay(alignment: .bottom) {
                if let status = state.statusMessage {
                    StatusBanner(text: status) { state.statusMessage = nil }
                }
            }
        }
    }
}

private struct EntryRow: View {
    let entry: PasswordEntry

    var body: some View {
        HStack {
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
