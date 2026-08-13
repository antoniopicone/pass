mod dialogs;
mod qr;
mod state;

use gtk4 as gtk;
use libadwaita as adw;

use adw::prelude::*;
use gtk::{gio, glib};
use passlib::Vault;
use state::{AppState, Unlocked};
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

const APP_ID: &str = "it.antoniopicone.Pass";

fn main() -> glib::ExitCode {
    let app = adw::Application::builder().application_id(APP_ID).build();
    app.connect_activate(build_ui);
    app.run()
}

/// Widgets that need to be reached from callbacks defined outside
/// `build_ui`'s own scope (list refresh, status updates, page switches).
#[derive(Clone)]
struct Ui {
    stack: gtk::Stack,
    toasts: adw::ToastOverlay,
    list_box: gtk::ListBox,
    search_entry: gtk::SearchEntry,
    locked_status: gtk::Label,
    vault_path_entry: gtk::Entry,
    password_entry: gtk::PasswordEntry,
}

fn build_ui(app: &adw::Application) {
    let state = Rc::new(RefCell::new(AppState::new()));

    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("Pass")
        .default_width(420)
        .default_height(600)
        .build();

    let stack = gtk::Stack::new();

    // ---- Locked page ----
    let locked_page = gtk::Box::new(gtk::Orientation::Vertical, 12);
    locked_page.set_margin_top(48);
    locked_page.set_margin_bottom(24);
    locked_page.set_margin_start(24);
    locked_page.set_margin_end(24);
    locked_page.set_valign(gtk::Align::Start);

    let title = gtk::Label::new(Some("🔐 Pass"));
    title.add_css_class("title-1");
    locked_page.append(&title);

    let path_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let vault_path_entry = gtk::Entry::builder()
        .placeholder_text("Path to vault file")
        .hexpand(true)
        .build();
    let browse_btn = gtk::Button::with_label("Browse…");
    path_row.append(&vault_path_entry);
    path_row.append(&browse_btn);
    locked_page.append(&path_row);

    let password_entry = gtk::PasswordEntry::builder()
        .placeholder_text("Master password")
        .show_peek_icon(true)
        .build();
    locked_page.append(&password_entry);

    let button_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let unlock_btn = gtk::Button::with_label("Unlock");
    unlock_btn.add_css_class("suggested-action");
    let create_btn = gtk::Button::with_label("Create new vault");
    button_row.append(&unlock_btn);
    button_row.append(&create_btn);
    locked_page.append(&button_row);

    let locked_status = gtk::Label::new(None);
    locked_status.add_css_class("error");
    locked_status.set_wrap(true);
    locked_page.append(&locked_status);

    stack.add_named(&locked_page, Some("locked"));

    // ---- Unlocked page ----
    let toasts = adw::ToastOverlay::new();
    let unlocked_content = gtk::Box::new(gtk::Orientation::Vertical, 0);

    let header = adw::HeaderBar::new();
    let header_title = adw::WindowTitle::new("Pass", "");
    header.set_title_widget(Some(&header_title));

    let add_btn = gtk::Button::from_icon_name("list-add-symbolic");
    add_btn.set_tooltip_text(Some("Add entry"));
    header.pack_start(&add_btn);

    let menu_btn = gtk::MenuButton::new();
    menu_btn.set_icon_name("open-menu-symbolic");
    let popover = gtk::Popover::new();
    let popover_box = gtk::Box::new(gtk::Orientation::Vertical, 4);
    let merge_btn = gtk::Button::with_label("Merge from file…");
    merge_btn.add_css_class("flat");
    let lock_btn = gtk::Button::with_label("Lock");
    lock_btn.add_css_class("flat");
    popover_box.append(&merge_btn);
    popover_box.append(&lock_btn);
    popover.set_child(Some(&popover_box));
    menu_btn.set_popover(Some(&popover));
    header.pack_end(&menu_btn);

    unlocked_content.append(&header);

    let search_entry = gtk::SearchEntry::builder()
        .placeholder_text("Search entries…")
        .margin_start(12)
        .margin_end(12)
        .margin_top(8)
        .margin_bottom(8)
        .build();
    unlocked_content.append(&search_entry);

    let list_box = gtk::ListBox::new();
    list_box.add_css_class("boxed-list");
    list_box.set_margin_start(12);
    list_box.set_margin_end(12);
    list_box.set_margin_bottom(12);
    list_box.set_selection_mode(gtk::SelectionMode::None);

    let scroller = gtk::ScrolledWindow::builder().vexpand(true).child(&list_box).build();
    unlocked_content.append(&scroller);

    toasts.set_child(Some(&unlocked_content));
    stack.add_named(&toasts, Some("unlocked"));

    window.set_content(Some(&stack));

    let ui = Ui {
        stack: stack.clone(),
        toasts: toasts.clone(),
        list_box: list_box.clone(),
        search_entry: search_entry.clone(),
        locked_status: locked_status.clone(),
        vault_path_entry: vault_path_entry.clone(),
        password_entry: password_entry.clone(),
    };
    let header_title_for_updates = header_title.clone();

    vault_path_entry.set_text(&state.borrow().vault_path.to_string_lossy());

    // Browse for a vault file.
    {
        let vault_path_entry = vault_path_entry.clone();
        let window = window.clone();
        browse_btn.connect_clicked(move |_| {
            let dialog = gtk::FileDialog::builder().title("Select Vault File").build();
            let vault_path_entry = vault_path_entry.clone();
            dialog.open(Some(&window), gio::Cancellable::NONE, move |result: Result<gio::File, glib::Error>| {
                if let Ok(file) = result {
                    if let Some(path) = file.path() {
                        vault_path_entry.set_text(&path.to_string_lossy());
                    }
                }
            });
        });
    }

    // Unlock.
    {
        let state = state.clone();
        let ui = ui.clone();
        let header_title = header_title_for_updates.clone();
        unlock_btn.connect_clicked(move |_| {
            let path = PathBuf::from(ui.vault_path_entry.text().to_string());
            let password = ui.password_entry.text().to_string();
            ui.locked_status.set_text("");

            match Vault::unlock(&path, &password) {
                Ok(vault) => {
                    ui.password_entry.set_text("");
                    header_title.set_subtitle(&path.to_string_lossy());
                    {
                        let mut s = state.borrow_mut();
                        s.vault_path = path;
                        s.unlocked = Some(Unlocked { vault, master_password: password });
                    }
                    refresh_list(&state, &ui);
                    ui.stack.set_visible_child_name("unlocked");
                }
                Err(e) => ui.locked_status.set_text(&format!("{e}")),
            }
        });
    }

    // Create a brand-new vault.
    {
        let state = state.clone();
        let ui = ui.clone();
        let header_title = header_title_for_updates.clone();
        create_btn.connect_clicked(move |_| {
            let path = PathBuf::from(ui.vault_path_entry.text().to_string());
            let password = ui.password_entry.text().to_string();
            ui.locked_status.set_text("");

            if password.len() < 8 {
                ui.locked_status.set_text("Master password must be at least 8 characters.");
                return;
            }

            match Vault::init(&path, &password) {
                Ok(vault) => {
                    ui.password_entry.set_text("");
                    header_title.set_subtitle(&path.to_string_lossy());
                    {
                        let mut s = state.borrow_mut();
                        s.vault_path = path;
                        s.unlocked = Some(Unlocked { vault, master_password: password });
                    }
                    refresh_list(&state, &ui);
                    ui.stack.set_visible_child_name("unlocked");
                }
                Err(e) => ui.locked_status.set_text(&format!("{e}")),
            }
        });
    }

    // Lock.
    {
        let state = state.clone();
        let ui = ui.clone();
        let popover = popover.clone();
        lock_btn.connect_clicked(move |_| {
            state.borrow_mut().unlocked = None;
            popover.popdown();
            ui.stack.set_visible_child_name("locked");
        });
    }

    // Merge from another vault file.
    {
        let state = state.clone();
        let ui = ui.clone();
        let window = window.clone();
        let popover = popover.clone();
        merge_btn.connect_clicked(move |_| {
            popover.popdown();
            let dialog = gtk::FileDialog::builder().title("Select Vault Copy to Merge").build();
            let state = state.clone();
            let ui = ui.clone();
            dialog.open(Some(&window), gio::Cancellable::NONE, move |result: Result<gio::File, glib::Error>| {
                let Ok(file) = result else { return };
                let Some(other_path) = file.path() else { return };

                let mut s = state.borrow_mut();
                let Some(unlocked) = s.unlocked.as_mut() else { return };

                match unlocked.vault.merge_from_file(&other_path, &unlocked.master_password) {
                    Ok(summary) => {
                        if let Err(e) = unlocked.vault.save(&unlocked.master_password) {
                            ui.toasts.add_toast(adw::Toast::new(&format!("Failed to save merged vault: {e}")));
                            return;
                        }
                        drop(s);
                        ui.toasts.add_toast(adw::Toast::new(&format!(
                            "Merged — created {}, updated {}, {} deleted",
                            summary.created, summary.updated, summary.deleted
                        )));
                        refresh_list(&state, &ui);
                    }
                    Err(e) => {
                        ui.toasts.add_toast(adw::Toast::new(&format!("Merge failed: {e}")));
                    }
                }
            });
        });
    }

    // Add entry.
    {
        let state = state.clone();
        let ui = ui.clone();
        let window = window.clone();
        add_btn.connect_clicked(move |_| {
            dialogs::show_edit_dialog(state.clone(), ui.clone(), window.clone().upcast(), None);
        });
    }

    // Search filtering.
    {
        let state = state.clone();
        let ui = ui.clone();
        search_entry.connect_search_changed(move |_| {
            refresh_list(&state, &ui);
        });
    }

    window.present();
}

/// Rebuild the entry list box from the vault, applying the current search
/// filter, sorted by website name with matches for anything containing the
/// query filtered in (website, username, or URL).
fn refresh_list(state: &Rc<RefCell<AppState>>, ui: &Ui) {
    while let Some(child) = ui.list_box.first_child() {
        ui.list_box.remove(&child);
    }

    let s = state.borrow();
    let Some(unlocked) = s.unlocked.as_ref() else { return };
    let Ok(mut entries) = unlocked.vault.list_entries() else { return };
    entries.sort_by(|a, b| a.website.to_lowercase().cmp(&b.website.to_lowercase()));

    let query = ui.search_entry.text().to_lowercase();
    drop(s);

    for entry in entries {
        if !query.is_empty()
            && !entry.website.to_lowercase().contains(&query)
            && !entry.username.to_lowercase().contains(&query)
            && !entry.url.to_lowercase().contains(&query)
        {
            continue;
        }

        let title = if entry.has_totp {
            format!("{} 🔐", entry.website)
        } else {
            entry.website.clone()
        };

        let row = adw::ActionRow::builder()
            .title(title)
            .subtitle(entry.username.clone())
            .activatable(true)
            .build();
        row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
        ui.list_box.append(&row);

        let state = state.clone();
        let ui_for_row = ui.clone();
        let id = entry.id.clone();
        row.connect_activated(move |row| {
            let window = row
                .root()
                .and_then(|r| r.downcast::<gtk::Window>().ok())
                .expect("row is attached to a window");
            dialogs::show_detail_dialog(state.clone(), ui_for_row.clone(), window, id.clone());
        });
    }
}
