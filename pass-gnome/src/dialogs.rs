use crate::qr;
use crate::state::AppState;
use crate::{refresh_list, Ui};
use adw::prelude::*;
use gtk4 as gtk;
use gtk::{gio, glib};
use libadwaita as adw;
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

fn copy_to_clipboard(widget: &impl IsA<gtk::Widget>, text: &str) {
    widget.display().clipboard().set_text(text);
}

fn new_dialog_window(parent: &gtk::Window, title: &str) -> adw::Window {
    let dialog = adw::Window::builder()
        .transient_for(parent)
        .modal(true)
        .destroy_with_parent(true)
        .default_width(380)
        .title(title)
        .build();
    dialog
}

/// Add (existing_id: None) or edit (existing_id: Some) an entry.
pub fn show_edit_dialog(
    state: Rc<RefCell<AppState>>,
    ui: Ui,
    parent: gtk::Window,
    existing_id: Option<String>,
) {
    let is_edit = existing_id.is_some();
    let dialog = new_dialog_window(&parent, if is_edit { "Edit Entry" } else { "Add Entry" });

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());

    let list = gtk::ListBox::new();
    list.add_css_class("boxed-list");
    list.set_margin_top(12);
    list.set_margin_bottom(12);
    list.set_margin_start(12);
    list.set_margin_end(12);
    list.set_selection_mode(gtk::SelectionMode::None);

    let website_row = adw::EntryRow::builder().title("Website").build();
    let url_row = adw::EntryRow::builder().title("URL").build();
    let username_row = adw::EntryRow::builder().title("Username / Email").build();
    let password_row = adw::PasswordEntryRow::builder().title("Password").build();

    if let Some(id) = &existing_id {
        let s = state.borrow();
        if let Some(unlocked) = s.unlocked.as_ref() {
            if let Ok(entry) = unlocked.vault.get_entry(id) {
                website_row.set_text(&entry.website);
                url_row.set_text(&entry.url);
                username_row.set_text(&entry.username);
                password_row.set_text(entry.password());
            }
        }
    } else {
        url_row.set_text("https://");
    }

    list.append(&website_row);
    list.append(&url_row);
    list.append(&username_row);
    list.append(&password_row);

    let status = gtk::Label::new(None);
    status.add_css_class("error");
    status.set_margin_start(12);
    status.set_margin_end(12);

    let save_btn = gtk::Button::with_label(if is_edit { "Save" } else { "Add" });
    save_btn.add_css_class("suggested-action");
    save_btn.set_margin_top(4);
    save_btn.set_margin_bottom(12);
    save_btn.set_margin_start(12);
    save_btn.set_margin_end(12);

    let content = gtk::Box::new(gtk::Orientation::Vertical, 6);
    content.append(&list);
    content.append(&status);
    content.append(&save_btn);
    toolbar.set_content(Some(&content));
    dialog.set_content(Some(&toolbar));

    {
        let state = state.clone();
        let ui = ui.clone();
        let dialog = dialog.clone();
        save_btn.connect_clicked(move |_| {
            let website = website_row.text().to_string();
            let url = url_row.text().to_string();
            let username = username_row.text().to_string();
            let password = password_row.text().to_string();

            if website.trim().is_empty() {
                status.set_text("Website is required.");
                return;
            }

            let mut s = state.borrow_mut();
            let Some(unlocked) = s.unlocked.as_mut() else { return };

            let result = match &existing_id {
                Some(id) => unlocked
                    .vault
                    .update_entry(id, Some(website), Some(url), Some(username), Some(password))
                    .map(|_| ()),
                None => {
                    let entry = passlib::PasswordEntry::new(website, url, username, password);
                    unlocked.vault.add_entry(entry).map(|_| ())
                }
            };

            match result.and_then(|_| unlocked.vault.save(&unlocked.master_password)) {
                Ok(_) => {
                    drop(s);
                    dialog.close();
                    refresh_list(&state, &ui);
                }
                Err(e) => status.set_text(&format!("{e}")),
            }
        });
    }

    dialog.present();
}

/// View an entry: password reveal, TOTP code with a live countdown, copy
/// buttons, and entry points into edit/delete/attach-MFA.
pub fn show_detail_dialog(state: Rc<RefCell<AppState>>, ui: Ui, parent: gtk::Window, entry_id: String) {
    let (website, url, username, password, has_totp) = {
        let s = state.borrow();
        let Some(unlocked) = s.unlocked.as_ref() else { return };
        let Ok(entry) = unlocked.vault.get_entry(&entry_id) else { return };
        (
            entry.website.clone(),
            entry.url.clone(),
            entry.username.clone(),
            entry.password().to_string(),
            entry.totp.is_some(),
        )
    };

    let dialog = new_dialog_window(&parent, &website);
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());

    let list = gtk::ListBox::new();
    list.add_css_class("boxed-list");
    list.set_margin_top(12);
    list.set_margin_start(12);
    list.set_margin_end(12);
    list.set_selection_mode(gtk::SelectionMode::None);

    let url_row = adw::ActionRow::builder().title("URL").subtitle(url).build();
    list.append(&url_row);

    let username_row = adw::ActionRow::builder().title("Username").subtitle(username.clone()).build();
    let copy_user_btn = gtk::Button::from_icon_name("edit-copy-symbolic");
    copy_user_btn.set_valign(gtk::Align::Center);
    username_row.add_suffix(&copy_user_btn);
    {
        let username = username.clone();
        let ui = ui.clone();
        copy_user_btn.connect_clicked(move |btn| {
            copy_to_clipboard(btn, &username);
            ui.toasts.add_toast(adw::Toast::new("Username copied"));
        });
    }
    list.append(&username_row);

    let password_row = adw::ActionRow::builder().title("Password").subtitle("••••••••").build();
    let reveal_btn = gtk::Button::from_icon_name("view-reveal-symbolic");
    reveal_btn.set_valign(gtk::Align::Center);
    let copy_pass_btn = gtk::Button::from_icon_name("edit-copy-symbolic");
    copy_pass_btn.set_valign(gtk::Align::Center);
    password_row.add_suffix(&reveal_btn);
    password_row.add_suffix(&copy_pass_btn);
    {
        let password_row = password_row.clone();
        let password = password.clone();
        let revealed = Rc::new(RefCell::new(false));
        reveal_btn.connect_clicked(move |_| {
            let mut r = revealed.borrow_mut();
            *r = !*r;
            password_row.set_subtitle(if *r { &password } else { "••••••••" });
        });
    }
    {
        let password = password.clone();
        let ui = ui.clone();
        copy_pass_btn.connect_clicked(move |btn| {
            copy_to_clipboard(btn, &password);
            ui.toasts.add_toast(adw::Toast::new("Password copied"));
        });
    }
    list.append(&password_row);

    // TOTP section: either the live code + countdown, or an "Add MFA
    // code" row, appended below the main list as a second boxed group.
    let totp_list = gtk::ListBox::new();
    totp_list.add_css_class("boxed-list");
    totp_list.set_margin_top(12);
    totp_list.set_margin_start(12);
    totp_list.set_margin_end(12);
    totp_list.set_selection_mode(gtk::SelectionMode::None);

    let outer = gtk::Box::new(gtk::Orientation::Vertical, 0);
    outer.append(&list);
    outer.append(&totp_list);

    let totp_source: Rc<RefCell<Option<glib::SourceId>>> = Rc::new(RefCell::new(None));

    if has_totp {
        let totp_row = adw::ActionRow::builder().title("MFA code").subtitle("……").build();
        let copy_totp_btn = gtk::Button::from_icon_name("edit-copy-symbolic");
        copy_totp_btn.set_valign(gtk::Align::Center);
        totp_row.add_suffix(&copy_totp_btn);
        totp_list.append(&totp_row);

        let remove_totp_row = adw::ActionRow::builder().title("Remove MFA code").activatable(true).build();
        remove_totp_row.add_css_class("error");
        totp_list.append(&remove_totp_row);

        let update_code = {
            let state = state.clone();
            let entry_id = entry_id.clone();
            let totp_row = totp_row.clone();
            move || -> Option<String> {
                let s = state.borrow();
                let unlocked = s.unlocked.as_ref()?;
                let entry = unlocked.vault.get_entry(&entry_id).ok()?;
                let totp = entry.totp.as_ref()?;
                let now = chrono::Utc::now();
                let code = passlib::totp::generate_code(totp, now).ok()?;
                let remaining = passlib::totp::seconds_remaining(totp, now);
                totp_row.set_subtitle(&format!("{code}  (expires in {remaining}s)"));
                Some(code)
            }
        };
        let current_code = Rc::new(RefCell::new(update_code().unwrap_or_default()));

        {
            let update_code = update_code.clone();
            let current_code = current_code.clone();
            let source = glib::timeout_add_local(Duration::from_secs(1), move || {
                if let Some(code) = update_code() {
                    *current_code.borrow_mut() = code;
                }
                glib::ControlFlow::Continue
            });
            *totp_source.borrow_mut() = Some(source);
        }

        {
            let ui = ui.clone();
            let current_code = current_code.clone();
            copy_totp_btn.connect_clicked(move |btn| {
                copy_to_clipboard(btn, &current_code.borrow());
                ui.toasts.add_toast(adw::Toast::new("MFA code copied"));
            });
        }

        {
            let state = state.clone();
            let ui = ui.clone();
            let dialog = dialog.clone();
            let entry_id = entry_id.clone();
            remove_totp_row.connect_activated(move |_| {
                let mut s = state.borrow_mut();
                let Some(unlocked) = s.unlocked.as_mut() else { return };
                let result = unlocked
                    .vault
                    .clear_entry_totp(&entry_id)
                    .and_then(|_| unlocked.vault.save(&unlocked.master_password));
                match result {
                    Ok(_) => {
                        drop(s);
                        dialog.close();
                        refresh_list(&state, &ui);
                    }
                    Err(e) => ui.toasts.add_toast(adw::Toast::new(&format!("Failed to remove MFA code: {e}"))),
                }
            });
        }
    } else {
        let add_totp_row = adw::ActionRow::builder().title("Add MFA code…").activatable(true).build();
        totp_list.append(&add_totp_row);

        let state2 = state.clone();
        let ui2 = ui.clone();
        let dialog2 = dialog.clone();
        let entry_id2 = entry_id.clone();
        add_totp_row.connect_activated(move |_| {
            show_totp_attach_dialog(state2.clone(), ui2.clone(), dialog2.clone().upcast(), entry_id2.clone());
        });
    }

    // Stop the countdown timer when the dialog closes, and clean up
    // whichever page's UI needs a refresh afterwards.
    {
        let totp_source = totp_source.clone();
        dialog.connect_close_request(move |_| {
            if let Some(source) = totp_source.borrow_mut().take() {
                source.remove();
            }
            glib::Propagation::Proceed
        });
    }

    let action_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    action_row.set_margin_top(12);
    action_row.set_margin_bottom(12);
    action_row.set_margin_start(12);
    action_row.set_margin_end(12);
    action_row.set_homogeneous(true);

    let edit_btn = gtk::Button::with_label("Edit");
    let delete_btn = gtk::Button::with_label("Delete");
    delete_btn.add_css_class("destructive-action");
    action_row.append(&edit_btn);
    action_row.append(&delete_btn);
    outer.append(&action_row);

    toolbar.set_content(Some(&outer));
    dialog.set_content(Some(&toolbar));

    {
        let state = state.clone();
        let ui = ui.clone();
        let dialog = dialog.clone();
        let entry_id = entry_id.clone();
        edit_btn.connect_clicked(move |_| {
            dialog.close();
            show_edit_dialog(state.clone(), ui.clone(), parent.clone(), Some(entry_id.clone()));
        });
    }

    {
        let state = state.clone();
        let ui = ui.clone();
        let dialog = dialog.clone();
        delete_btn.connect_clicked(move |_| {
            let confirm = gtk::AlertDialog::builder()
                .message("Delete this entry?")
                .detail(format!("\"{website}\" will be removed from the vault."))
                .buttons(["Cancel", "Delete"])
                .cancel_button(0)
                .default_button(0)
                .build();

            let state = state.clone();
            let ui = ui.clone();
            let dialog_for_choice = dialog.clone();
            let entry_id = entry_id.clone();
            confirm.choose(Some(&dialog), gio::Cancellable::NONE, move |result| {
                let dialog = dialog_for_choice;
                if result != Ok(1) {
                    return;
                }
                let mut s = state.borrow_mut();
                let Some(unlocked) = s.unlocked.as_mut() else { return };
                let result = unlocked
                    .vault
                    .delete_entry(&entry_id)
                    .and_then(|_| unlocked.vault.save(&unlocked.master_password));
                match result {
                    Ok(_) => {
                        drop(s);
                        dialog.close();
                        refresh_list(&state, &ui);
                    }
                    Err(e) => ui.toasts.add_toast(adw::Toast::new(&format!("Failed to delete: {e}"))),
                }
            });
        });
    }

    dialog.present();
}

/// Attach an MFA/TOTP secret to an entry: paste an `otpauth://` URI
/// directly, or pick a QR code image to decode into that URI.
fn show_totp_attach_dialog(state: Rc<RefCell<AppState>>, ui: Ui, parent: gtk::Window, entry_id: String) {
    let dialog = new_dialog_window(&parent, "Add MFA Code");
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());

    let content = gtk::Box::new(gtk::Orientation::Vertical, 8);
    content.set_margin_top(12);
    content.set_margin_bottom(12);
    content.set_margin_start(12);
    content.set_margin_end(12);

    let hint = gtk::Label::new(Some(
        "Paste the otpauth:// URI from the service's MFA setup page, or choose a QR code image you saved from it.",
    ));
    hint.set_wrap(true);
    hint.set_xalign(0.0);
    hint.add_css_class("dim-label");
    content.append(&hint);

    let uri_entry = gtk::Entry::builder().placeholder_text("otpauth://totp/...").build();
    content.append(&uri_entry);

    let choose_qr_btn = gtk::Button::with_label("Choose QR code image…");
    content.append(&choose_qr_btn);

    let status = gtk::Label::new(None);
    status.add_css_class("error");
    status.set_wrap(true);
    content.append(&status);

    let attach_btn = gtk::Button::with_label("Attach");
    attach_btn.add_css_class("suggested-action");
    content.append(&attach_btn);

    toolbar.set_content(Some(&content));
    dialog.set_content(Some(&toolbar));

    {
        let uri_entry = uri_entry.clone();
        let status = status.clone();
        let dialog = dialog.clone();
        choose_qr_btn.connect_clicked(move |_| {
            let file_dialog = gtk::FileDialog::builder().title("Select QR Code Image").build();
            let uri_entry = uri_entry.clone();
            let status = status.clone();
            file_dialog.open(Some(&dialog), gio::Cancellable::NONE, move |result: Result<gio::File, glib::Error>| {
                let Ok(file) = result else { return };
                let Some(path) = file.path() else { return };
                match qr::decode_qr_image(&path) {
                    Ok(content) => {
                        uri_entry.set_text(&content);
                        status.set_text("");
                    }
                    Err(e) => status.set_text(&e),
                }
            });
        });
    }

    {
        let dialog = dialog.clone();
        attach_btn.connect_clicked(move |_| {
            let uri = uri_entry.text().to_string();
            let totp = match passlib::totp::parse_otpauth_uri(&uri) {
                Ok(t) => t,
                Err(e) => {
                    status.set_text(&format!("{e}"));
                    return;
                }
            };

            let mut s = state.borrow_mut();
            let Some(unlocked) = s.unlocked.as_mut() else { return };
            let result = unlocked
                .vault
                .set_entry_totp(&entry_id, totp)
                .and_then(|_| unlocked.vault.save(&unlocked.master_password));

            match result {
                Ok(_) => {
                    drop(s);
                    dialog.close();
                    // The entry detail dialog underneath is stale now;
                    // closing it and letting the user reopen it is
                    // simpler and safer than trying to patch it live.
                    if let Some(parent_window) = dialog.transient_for() {
                        parent_window.close();
                    }
                    refresh_list(&state, &ui);
                }
                Err(e) => status.set_text(&format!("{e}")),
            }
        });
    }

    dialog.present();
}
