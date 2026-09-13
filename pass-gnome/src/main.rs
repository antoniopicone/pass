mod dialogs;
mod qr;
mod state;
mod tray;

use gtk4 as gtk;
use libadwaita as adw;

use adw::prelude::*;
use gtk::{gio, glib};
use passlib::{SyncHandle, Vault};
use state::{AppState, Unlocked};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

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
    howdy_btn: gtk::Button,
}

fn build_ui(app: &adw::Application) {
    // `connect_activate` fires on every activation, not just the first —
    // including a repeat launch of the binary or the tray icon's own
    // "Open Pass" action once the app is already registered as a running
    // GApplication instance (its activation is forwarded here over D-Bus
    // instead of starting a second process). Without this guard, either
    // one would build an entire second window/state from scratch.
    if let Some(window) = app.active_window() {
        window.present();
        return;
    }

    let state = Rc::new(RefCell::new(AppState::new()));

    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("Pass")
        .default_width(420)
        .default_height(600)
        .build();

    // Keep the app (and its tray icon — see below) running after the
    // window is closed, instead of `gio::Application`'s default of
    // quitting once its last window goes away: closing the window just
    // hides it, and the tray icon's "Open Pass"/left-click brings it back
    // (via `app.active_window()`, which still finds a hidden-but-not-
    // destroyed window). `app.hold()` is what suppresses the auto-quit;
    // the tray's "Quit" item calls `app.quit()`, which — unlike
    // `release()` — ends the application immediately regardless of any
    // outstanding hold, so it's still the right way out.
    // `hold()` returns an RAII guard — the hold is only in effect while it
    // lives, so it must outlive this function (which returns as soon as
    // the UI is built, well before the app would otherwise quit). Leaked
    // deliberately, same as the tray `Handle` below: both need to live for
    // the whole process, and the process exiting cleans up either way.
    std::mem::forget(app.hold());
    window.connect_close_request(|window| {
        window.set_visible(false);
        glib::Propagation::Stop
    });

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

    // "Unlock with your face" (howdy) — hidden by default, shown only when
    // it's actually available for whatever path is currently in
    // vault_path_entry (see the "changed" handler wired below, and
    // `refresh_howdy_button`'s call sites). A `gtk::Button` convenience
    // constructor only takes an icon *or* a label, not both, hence the
    // manual icon+label box as its child.
    let howdy_btn = gtk::Button::new();
    let howdy_btn_content = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    howdy_btn_content.set_halign(gtk::Align::Center);
    howdy_btn_content.append(&gtk::Image::from_icon_name("it.antoniopicone.Pass-fingerprint"));
    howdy_btn_content.append(&gtk::Label::new(Some("Unlock with your face")));
    howdy_btn.set_child(Some(&howdy_btn_content));
    howdy_btn.set_visible(false);
    locked_page.append(&howdy_btn);

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
        howdy_btn: howdy_btn.clone(),
    };
    let header_title_for_updates = header_title.clone();

    vault_path_entry.set_text(&state.borrow().vault_path.to_string_lossy());
    refresh_howdy_button(&ui);

    // Refresh the "Unlock with your face" button's visibility whenever the
    // vault path changes (typed or picked via Browse…) — availability is
    // per-vault (see pass_howdy::is_available_for).
    {
        let ui = ui.clone();
        vault_path_entry.connect_changed(move |_| refresh_howdy_button(&ui));
    }

    // Unlock with your face (howdy). Runs the actual PAM authentication +
    // camera scan on a background thread — unlike the local pass-syncd
    // loopback calls elsewhere in this file, this can take a real,
    // user-noticeable amount of time (a face to look for, a camera to
    // read), so blocking the UI thread here would freeze the whole app for
    // that whole duration.
    {
        let state = state.clone();
        let ui = ui.clone();
        let header_title = header_title_for_updates.clone();
        howdy_btn.connect_clicked(move |_| {
            let path = PathBuf::from(ui.vault_path_entry.text().to_string());
            ui.locked_status.set_text("");
            ui.howdy_btn.set_sensitive(false);

            let (tx, rx) = async_channel::bounded(1);
            std::thread::spawn(move || {
                let result = pass_howdy::unlock_with_face(&path)
                    .map_err(|e| e.to_string())
                    .and_then(|pw| Vault::unlock(&path, &pw).map(|v| (v, pw)).map_err(|e| e.to_string()));
                let _ = tx.send_blocking((path, result));
            });

            let state = state.clone();
            let ui = ui.clone();
            let header_title = header_title.clone();
            glib::spawn_future_local(async move {
                if let Ok((path, result)) = rx.recv().await {
                    ui.howdy_btn.set_sensitive(true);
                    match result {
                        Ok((vault, master_password)) => {
                            header_title.set_subtitle(&path.to_string_lossy());
                            passlib::remember_last_vault(&path);
                            {
                                let mut s = state.borrow_mut();
                                s.vault_path = path;
                                s.unlocked = Some(Unlocked { vault, master_password });
                            }
                            refresh_list(&state, &ui);
                            ui.stack.set_visible_child_name("unlocked");
                        }
                        Err(e) => ui.locked_status.set_text(&format!("Face unlock failed: {e}")),
                    }
                }
            });
        });
    }

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
        let window = window.clone();
        let header_title = header_title_for_updates.clone();
        unlock_btn.connect_clicked(move |_| {
            let path = PathBuf::from(ui.vault_path_entry.text().to_string());
            let password = ui.password_entry.text().to_string();
            ui.locked_status.set_text("");

            match Vault::unlock(&path, &password) {
                Ok(vault) => {
                    ui.password_entry.set_text("");
                    header_title.set_subtitle(&path.to_string_lossy());
                    offer_howdy_enrollment(&ui, &window, &path, &password);
                    passlib::remember_last_vault(&path);
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
        let window = window.clone();
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
                    offer_howdy_enrollment(&ui, &window, &path, &password);
                    passlib::remember_last_vault(&path);
                    {
                        let mut s = state.borrow_mut();
                        s.vault_path = path;
                        s.unlocked = Some(Unlocked { vault, master_password: password.clone() });
                    }
                    refresh_list(&state, &ui);
                    ui.stack.set_visible_child_name("unlocked");
                    offer_sync_import(&state, &ui, &window, password);
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
                        let salt = unlocked.vault.ensure_sync_salt();
                        if let Err(e) = unlocked.vault.save(&unlocked.master_password) {
                            ui.toasts.add_toast(adw::Toast::new(&format!("Failed to save merged vault: {e}")));
                            return;
                        }
                        // A merge can touch many entries at once with no
                        // single id to push (see pass-native-host's
                        // mergeFromFile handler for the same reasoning) —
                        // push every entry so other devices don't have to
                        // wait for each one's next individual edit.
                        if summary.changed() {
                            if let Ok(entries) = unlocked.vault.list_entries() {
                                let handle = SyncHandle::new(unlocked.vault.path(), salt, &unlocked.master_password);
                                for e in entries {
                                    if let Ok(entry) = unlocked.vault.get_entry(&e.id) {
                                        handle.push_upsert(&entry);
                                    }
                                }
                            }
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

    // Periodic real-time sync pull while the vault is unlocked, reusing the
    // same `glib::timeout_add_local` pattern as the TOTP countdown in
    // dialogs.rs. Registered once, unconditionally, rather than started/
    // stopped per unlock/lock cycle: it simply no-ops while locked, which
    // is simpler than tracking a cancellable `SourceId` across every
    // unlock/create/lock transition. Runs the pull (a loopback HTTP call,
    // bounded by passlib::sync's own short request timeout) directly on
    // the GTK main thread rather than a worker thread: `Vault`/`AppState`
    // aren't `Send`, so offloading it would require splitting
    // `SyncHandle::pull_and_apply`'s fetch-then-decrypt-then-apply into
    // separate network and vault-mutation steps — not worth it for a call
    // that resolves near-instantly on the common path (daemon reachable,
    // unchanged fingerprint).
    //
    // Also run once immediately whenever the window is (re-)mapped (see
    // `window.connect_map` below), not just on this timer: while the
    // window has no visible surface (hidden via the close-to-tray behavior
    // above), the desktop can freeze this process entirely to save power
    // (GNOME Shell/systemd's background-app throttling for windowless
    // apps) — pausing *this very timer* along with everything else until
    // the window is shown again. Relying on the timer alone left the list
    // showing stale data for the first few seconds after switching back to
    // the app from the tray, which looked broken even though it would
    // have caught up shortly on its own.
    {
        let state = state.clone();
        let ui = ui.clone();
        glib::timeout_add_local(Duration::from_secs(3), move || {
            sync_pull_now(&state, &ui);
            glib::ControlFlow::Continue
        });
    }
    {
        let state = state.clone();
        let ui = ui.clone();
        window.connect_map(move |_| sync_pull_now(&state, &ui));
    }

    // GNOME Shell top-bar indicator (see tray.rs) — best-effort: a system
    // without a StatusNotifierWatcher (stock GNOME without the
    // "AppIndicator and KStatusNotifierItem Support" extension) just means
    // no icon ever appears, not a startup failure.
    {
        let (tx, rx) = async_channel::unbounded();
        let app = app.clone();
        glib::spawn_future_local(async move {
            while let Ok(event) = rx.recv().await {
                match event {
                    tray::TrayEvent::Open => {
                        if let Some(window) = app.active_window() {
                            window.present();
                        }
                    }
                    tray::TrayEvent::Quit => app.quit(),
                }
            }
        });

        use ksni::blocking::TrayMethods;
        match (tray::AppTray { tx }).spawn() {
            // Leaked deliberately: the tray must stay alive for the whole
            // process lifetime, and there's no meaningful earlier point to
            // shut it down from (see ksni::blocking::Handle::shutdown if
            // that ever changes).
            Ok(handle) => std::mem::forget(handle),
            Err(e) => eprintln!("[tray] system tray icon not available: {e}"),
        }
    }

    window.present();
}

/// Right after creating a brand-new vault: if `pass-syncd` already knows
/// of an existing synced vault on this network (some other device set one
/// up first), offers to import its entries immediately instead of leaving
/// the new vault empty — see `passlib::sync::import_from_sync`. Silently
/// does nothing if there's nothing to offer (daemon unreachable, or
/// reachable but genuinely empty) rather than showing a pointless dialog.
/// Shows or hides the "Unlock with your face" button on the locked screen
/// for whatever path is currently in `ui.vault_path_entry` — availability
/// is per-vault (a master password must have already been stored for it,
/// see `pass-howdy::store_password`/`offer_howdy_enrollment`), so this is
/// re-checked every time the path changes, not just once at startup.
fn refresh_howdy_button(ui: &Ui) {
    let path = PathBuf::from(ui.vault_path_entry.text().to_string());
    ui.howdy_btn.set_visible(pass_howdy::is_available_for(&path));
}

/// Right after a successful manual unlock/create: if howdy is installed
/// and its PAM service is configured but this vault hasn't opted in to
/// face unlock yet, offers to enable it (see `pass-howdy::store_password`).
fn offer_howdy_enrollment(ui: &Ui, window: &adw::ApplicationWindow, vault_path: &Path, master_password: &str) {
    if !pass_howdy::can_enroll() || pass_howdy::has_stored_password(vault_path) {
        return;
    }

    let confirm = gtk::AlertDialog::builder()
        .message("Enable face unlock?")
        .detail("howdy is available on this system. Enable \"unlock with your face\" for this vault?")
        .buttons(["Not now", "Enable"])
        .cancel_button(0)
        .default_button(1)
        .build();

    let ui = ui.clone();
    let vault_path = vault_path.to_path_buf();
    let master_password = master_password.to_string();
    confirm.choose(Some(window), gio::Cancellable::NONE, move |result| {
        if result != Ok(1) {
            return;
        }
        match pass_howdy::store_password(&vault_path, &master_password) {
            Ok(()) => {
                refresh_howdy_button(&ui);
                ui.toasts.add_toast(adw::Toast::new("Face unlock enabled for this vault"));
            }
            Err(e) => ui.toasts.add_toast(adw::Toast::new(&format!("Could not enable face unlock: {e}"))),
        }
    });
}

fn offer_sync_import(state: &Rc<RefCell<AppState>>, ui: &Ui, window: &adw::ApplicationWindow, password: String) {
    if passlib::sync::discover_existing_salt().is_none() {
        return;
    }

    let confirm = gtk::AlertDialog::builder()
        .message("Import from synced device?")
        .detail("pass-syncd found an existing vault already synced on this network. Import its entries now?")
        .buttons(["Not now", "Import"])
        .cancel_button(0)
        .default_button(1)
        .build();

    let state = state.clone();
    let ui = ui.clone();
    confirm.choose(Some(window), gio::Cancellable::NONE, move |result| {
        if result != Ok(1) {
            return;
        }
        let mut s = state.borrow_mut();
        let Some(unlocked) = s.unlocked.as_mut() else { return };
        let imported = passlib::sync::import_from_sync(&mut unlocked.vault, &password);
        match imported {
            Some(n) => {
                if let Err(e) = unlocked.vault.save(&password) {
                    drop(s);
                    ui.toasts.add_toast(adw::Toast::new(&format!("Failed to save imported entries: {e}")));
                    return;
                }
                drop(s);
                refresh_list(&state, &ui);
                ui.toasts.add_toast(adw::Toast::new(&format!("Imported {n} entries from the synced vault")));
            }
            None => {
                drop(s);
                ui.toasts.add_toast(adw::Toast::new("No existing synced vault found"));
            }
        }
    });
}

/// Pulls and applies any pending sync changes right now — see the two call
/// sites (the periodic timer and `window.connect_map`) for why both exist.
/// No-ops while locked or when nothing changed, same as the timer always
/// did; refreshes the list and shows a toast only when something actually
/// came in.
fn sync_pull_now(state: &Rc<RefCell<AppState>>, ui: &Ui) {
    let mut s = state.borrow_mut();
    let Some(unlocked) = s.unlocked.as_mut() else { return };
    let Some(handle) = SyncHandle::for_vault(&unlocked.vault, &unlocked.master_password) else { return };
    let changed = handle.pull_and_apply(&mut unlocked.vault);
    if changed > 0 && unlocked.vault.save(&unlocked.master_password).is_ok() {
        drop(s);
        refresh_list(state, ui);
        ui.toasts.add_toast(adw::Toast::new(&format!("Synced {changed} change(s) from another device")));
    }
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
