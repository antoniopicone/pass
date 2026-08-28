import PassKit
import SwiftUI

enum EntryFormMode {
    case add
    case edit(PasswordEntry)

    var title: String {
        switch self {
        case .add: return "Add Entry"
        case .edit: return "Edit Entry"
        }
    }
}

struct EntryFormView: View {
    let mode: EntryFormMode

    @EnvironmentObject private var state: AppState
    @Environment(\.dismiss) private var dismiss

    @State private var website = ""
    @State private var url = "https://"
    @State private var username = ""
    @State private var password = ""

    var body: some View {
        NavigationStack {
            Form {
                TextField("Website", text: $website)
                TextField("URL", text: $url)
                    #if os(iOS)
                    .keyboardType(.URL)
                    .autocapitalization(.none)
                    #endif
                TextField("Username / Email", text: $username)
                    #if os(iOS)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)
                    #endif
                SecureField("Password", text: $password)
            }
            .formStyle(.grouped)
            .navigationTitle(mode.title)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save", action: save)
                        .disabled(website.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
        }
        .onAppear(perform: populateIfEditing)
    }

    private func populateIfEditing() {
        guard case .edit(let entry) = mode else { return }
        website = entry.website
        url = entry.url
        username = entry.username
        password = entry.password
    }

    private func save() {
        switch mode {
        case .add:
            state.addEntry(website: website, url: url, username: username, password: password)
        case .edit(let entry):
            state.updateEntry(id: entry.id, website: website, url: url, username: username, password: password)
        }
        dismiss()
    }
}
