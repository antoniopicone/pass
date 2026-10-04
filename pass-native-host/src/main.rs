//! Native messaging host bridging the Pass Chromium extension to `passlib`.
//!
//! Speaks Chrome's native messaging stdio protocol: each message is a
//! 4-byte length prefix (native byte order) followed by that many bytes of
//! UTF-8 JSON. Every request is handled statelessly — it opens the vault
//! file fresh with the supplied master password, performs the operation,
//! saves if needed, and replies. This avoids relying on the extension's
//! service worker (or this process) staying alive between calls; Chrome is
//! free to spawn a new host process per `chrome.runtime.sendNativeMessage`
//! call, which is exactly the model this host is built for. A `loop` is
//! used regardless so the host also works correctly if the extension opts
//! into a long-lived `chrome.runtime.connectNative` port instead.

use passlib::{PasswordEntry, SyncHandle, Vault};
use serde_json::{json, Value};
use std::io::{self, Read, Write};

fn main() {
    loop {
        let request = match read_message() {
            Ok(Some(req)) => req,
            Ok(None) => break, // clean EOF: the extension side disconnected
            Err(_) => break,   // malformed input, nothing sane left to do
        };

        let response = handle(&request);
        if write_message(&response).is_err() {
            break;
        }
    }
}

fn read_message() -> io::Result<Option<Value>> {
    let mut stdin = io::stdin().lock();

    let mut len_buf = [0u8; 4];
    if let Err(e) = stdin.read_exact(&mut len_buf) {
        return if e.kind() == io::ErrorKind::UnexpectedEof {
            Ok(None)
        } else {
            Err(e)
        };
    }
    let len = u32::from_ne_bytes(len_buf) as usize;

    let mut buf = vec![0u8; len];
    stdin.read_exact(&mut buf)?;

    let value = serde_json::from_slice(&buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some(value))
}

fn write_message(value: &Value) -> io::Result<()> {
    let bytes = serde_json::to_vec(value)?;
    let len = bytes.len() as u32;

    let mut stdout = io::stdout().lock();
    stdout.write_all(&len.to_ne_bytes())?;
    stdout.write_all(&bytes)?;
    stdout.flush()
}

/// Dispatch a request to the matching command handler and normalize the
/// response into `{"ok": true, ...}` or `{"ok": false, "error": "..."}`.
fn handle(request: &Value) -> Value {
    let cmd = request.get("cmd").and_then(Value::as_str).unwrap_or("");

    let result = match cmd {
        "ping" => Ok(json!({ "pong": true })),
        "vaultExists" => vault_exists(request),
        "getDefaultVaultPath" => default_vault_path(request),
        "checkSyncImportAvailable" => check_sync_import_available(request),
        "initVault" => init_vault(request),
        "unlockVault" => unlock_vault(request),
        "howdyStatus" => howdy_status(request),
        "howdyUnlock" => howdy_unlock(request),
        "howdyEnroll" => howdy_enroll(request),
        "getEntry" => get_entry(request),
        "getEntryHistory" => get_entry_history(request),
        "addEntry" => add_entry(request),
        "updateEntry" => update_entry(request),
        "deleteEntry" => delete_entry(request),
        "addTotpUri" => add_totp_uri(request),
        "removeTotp" => remove_totp(request),
        "mergeFromFile" => merge_from_file(request),
        other => Err(format!("Unknown command: {other}")),
    };

    match result {
        Ok(mut value) => {
            value["ok"] = json!(true);
            value
        }
        Err(error) => json!({ "ok": false, "error": error }),
    }
}

fn field<'a>(req: &'a Value, name: &str) -> Result<&'a str, String> {
    req.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Missing field: {name}"))
}

fn optional_field(req: &Value, name: &str) -> Option<String> {
    req.get(name).and_then(Value::as_str).map(str::to_string)
}

fn optional_string_array_field(req: &Value, name: &str) -> Option<Vec<String>> {
    req.get(name)
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(Value::as_str).map(str::to_string).collect())
}

/// Pulls and applies any changes `pass-syncd` has for this vault, saving if
/// anything actually changed. Called right after every unlock (this host
/// re-unlocks fresh per stateless message, so "right after unlock" already
/// means "before every response"): the Chromium extension picks up other
/// devices' changes on every popup open/action with no JS-side changes
/// needed. Best-effort/never fails the request — see [`SyncHandle`]'s own
/// doc comment.
fn sync_pull(vault: &mut Vault, master_password: &str) {
    if let Some(handle) = SyncHandle::for_vault(vault, master_password) {
        if handle.pull_and_apply(vault) > 0 {
            let _ = vault.save(master_password);
        }
    }
}

/// Pushes entry `id`'s current state to `pass-syncd`. `salt` must come from
/// [`Vault::ensure_sync_salt`] called *before* the mutation was saved, same
/// ordering contract as passcli's helper of the same name.
fn sync_push_upsert(vault: &Vault, master_password: &str, salt: [u8; 16], id: &str) {
    if let Ok(entry) = vault.get_entry(id) {
        SyncHandle::new(vault.path(), salt, master_password).push_upsert(&entry);
    }
}

/// Pushes entry `id`'s deletion to `pass-syncd`. See [`sync_push_upsert`].
fn sync_push_delete(vault: &Vault, master_password: &str, salt: [u8; 16], id: &str) {
    SyncHandle::new(vault.path(), salt, master_password).push_delete(id);
}

fn vault_exists(req: &Value) -> Result<Value, String> {
    let path = field(req, "vaultPath")?;
    Ok(json!({ "exists": std::path::Path::new(path).exists() }))
}

/// Checks whether `pass-syncd` already knows of an existing synced vault on
/// this network (some other device set one up first), without needing a
/// vault open yet. The popup can call this before showing an "import from
/// another device?" option on the create-vault screen.
fn check_sync_import_available(_req: &Value) -> Result<Value, String> {
    Ok(json!({ "available": passlib::sync::discover_existing_salt().is_some() }))
}

/// `importFromSync: true` (optional; default false) additionally imports
/// entries from an existing synced vault on this network right after
/// creating the new one — see [`passlib::sync::import_from_sync`]. The
/// response's `importedCount` is `0` if nothing was found to import (not
/// requested, or `pass-syncd` unreachable/empty), otherwise how many
/// entries were pulled in.
fn init_vault(req: &Value) -> Result<Value, String> {
    let path = field(req, "vaultPath")?;
    let password = field(req, "masterPassword")?;
    let import_from_sync = req.get("importFromSync").and_then(Value::as_bool).unwrap_or(false);

    let mut vault = Vault::init(path, password).map_err(|e| e.to_string())?;
    passlib::remember_last_vault(std::path::Path::new(path));

    let mut imported_count = 0;
    if import_from_sync {
        if let Some(n) = passlib::sync::import_from_sync(&mut vault, password) {
            vault.save(password).map_err(|e| e.to_string())?;
            imported_count = n;
        }
    }

    Ok(json!({ "importedCount": imported_count }))
}

fn unlock_vault(req: &Value) -> Result<Value, String> {
    let path = field(req, "vaultPath")?;
    let password = field(req, "masterPassword")?;

    let mut vault = Vault::unlock(path, password).map_err(|e| e.to_string())?;
    passlib::remember_last_vault(std::path::Path::new(path));
    sync_pull(&mut vault, password);
    let entries = vault.list_entries().map_err(|e| e.to_string())?;
    Ok(json!({ "entries": entries }))
}

/// The vault path to prefill the locked screen with: the last one
/// successfully unlocked/created by *any* pass client on this machine
/// (CLI, GNOME, or this extension), or `~/.vaults/personal.kdbx` if
/// there isn't one yet — see `passlib::propose_vault_path`.
fn default_vault_path(_req: &Value) -> Result<Value, String> {
    Ok(json!({ "vaultPath": passlib::propose_vault_path().to_string_lossy() }))
}

/// Whether the popup should offer "unlock with your face" (`canUnlock`,
/// howdy installed+configured+enrolled for this exact vault) and/or
/// "enable face unlock" after the next manual unlock (`canEnroll`,
/// installed+configured but not yet enrolled) — see `pass-howdy`.
fn howdy_status(req: &Value) -> Result<Value, String> {
    let path = field(req, "vaultPath")?;
    let vault_path = std::path::Path::new(path);
    Ok(json!({
        "canUnlock": pass_howdy::is_available_for(vault_path),
        "canEnroll": pass_howdy::can_enroll() && !pass_howdy::has_stored_password(vault_path),
    }))
}

/// Authenticates via howdy and, on success, unlocks the vault with the
/// password stored for it — same response shape as `unlockVault`, plus
/// `masterPassword` itself, since the caller (background.js) needs it to
/// populate its own session the same way a manual unlock does (this host
/// is stateless between calls — see the module doc comment — so nothing
/// here can hold the session on the extension's behalf instead).
fn howdy_unlock(req: &Value) -> Result<Value, String> {
    let path = field(req, "vaultPath")?;
    let vault_path = std::path::Path::new(path);

    let master_password = pass_howdy::unlock_with_face(vault_path).map_err(|e| e.to_string())?;
    let mut vault = Vault::unlock(vault_path, &master_password).map_err(|e| e.to_string())?;
    passlib::remember_last_vault(vault_path);
    sync_pull(&mut vault, &master_password);
    let entries = vault.list_entries().map_err(|e| e.to_string())?;
    Ok(json!({ "entries": entries, "masterPassword": master_password }))
}

/// Enables face unlock for this vault (stores `masterPassword` in the OS
/// keyring, gated by a howdy face match from then on — see
/// `pass-howdy::store_password`). The caller is expected to have already
/// unlocked with this exact password, same as every other command here.
fn howdy_enroll(req: &Value) -> Result<Value, String> {
    let path = field(req, "vaultPath")?;
    let password = field(req, "masterPassword")?;
    pass_howdy::store_password(std::path::Path::new(path), password).map_err(|e| e.to_string())?;
    Ok(json!({}))
}

fn get_entry(req: &Value) -> Result<Value, String> {
    let path = field(req, "vaultPath")?;
    let password = field(req, "masterPassword")?;
    let id = field(req, "id")?;

    let mut vault = Vault::unlock(path, password).map_err(|e| e.to_string())?;
    sync_pull(&mut vault, password);
    let entry = vault.get_entry(id).map_err(|e| e.to_string())?;
    Ok(json!({ "entry": entry_to_json(&entry) }))
}

/// Previous passwords for an entry (newest first), kept automatically by
/// the KDBX4 history mechanism — see `passlib::vault`'s module docs.
fn get_entry_history(req: &Value) -> Result<Value, String> {
    let path = field(req, "vaultPath")?;
    let password = field(req, "masterPassword")?;
    let id = field(req, "id")?;

    let mut vault = Vault::unlock(path, password).map_err(|e| e.to_string())?;
    sync_pull(&mut vault, password);
    let entry = vault.get_entry(id).map_err(|e| e.to_string())?;
    let history: Vec<Value> = entry
        .history
        .iter()
        .map(|h| json!({ "password": h.password, "changedAt": h.changed_at.to_rfc3339() }))
        .collect();
    Ok(json!({ "history": history }))
}

fn add_entry(req: &Value) -> Result<Value, String> {
    let path = field(req, "vaultPath")?;
    let password = field(req, "masterPassword")?;
    let website = field(req, "website")?.to_string();
    let url = field(req, "url").unwrap_or("").to_string();
    let username = field(req, "username")?.to_string();
    let entry_password = field(req, "entryPassword")?.to_string();

    let mut vault = Vault::unlock(path, password).map_err(|e| e.to_string())?;
    let mut entry = PasswordEntry::new(website, url, username, entry_password);
    entry.notes = optional_field(req, "notes").unwrap_or_default();
    entry.additional_urls = optional_string_array_field(req, "additionalUrls").unwrap_or_default();
    let id = vault.add_entry(entry).map_err(|e| e.to_string())?;
    let salt = vault.ensure_sync_salt();
    vault.save(password).map_err(|e| e.to_string())?;
    sync_push_upsert(&vault, password, salt, &id);
    Ok(json!({ "id": id }))
}

fn update_entry(req: &Value) -> Result<Value, String> {
    let path = field(req, "vaultPath")?;
    let password = field(req, "masterPassword")?;
    let id = field(req, "id")?;

    let mut vault = Vault::unlock(path, password).map_err(|e| e.to_string())?;
    vault
        .update_entry(
            id,
            optional_field(req, "website"),
            optional_field(req, "url"),
            optional_field(req, "username"),
            optional_field(req, "entryPassword"),
            optional_field(req, "notes"),
            optional_string_array_field(req, "additionalUrls"),
        )
        .map_err(|e| e.to_string())?;
    let salt = vault.ensure_sync_salt();
    vault.save(password).map_err(|e| e.to_string())?;
    sync_push_upsert(&vault, password, salt, id);
    Ok(json!({}))
}

fn delete_entry(req: &Value) -> Result<Value, String> {
    let path = field(req, "vaultPath")?;
    let password = field(req, "masterPassword")?;
    let id = field(req, "id")?;

    let mut vault = Vault::unlock(path, password).map_err(|e| e.to_string())?;
    vault.delete_entry(id).map_err(|e| e.to_string())?;
    let salt = vault.ensure_sync_salt();
    vault.save(password).map_err(|e| e.to_string())?;
    sync_push_delete(&vault, password, salt, id);
    Ok(json!({}))
}

fn add_totp_uri(req: &Value) -> Result<Value, String> {
    let path = field(req, "vaultPath")?;
    let password = field(req, "masterPassword")?;
    let id = field(req, "id")?;
    let uri = field(req, "uri")?;

    let totp = passlib::totp::parse_otpauth_uri(uri).map_err(|e| e.to_string())?;

    let mut vault = Vault::unlock(path, password).map_err(|e| e.to_string())?;
    vault.set_entry_totp(id, totp).map_err(|e| e.to_string())?;
    let salt = vault.ensure_sync_salt();
    vault.save(password).map_err(|e| e.to_string())?;
    sync_push_upsert(&vault, password, salt, id);
    Ok(json!({}))
}

fn remove_totp(req: &Value) -> Result<Value, String> {
    let path = field(req, "vaultPath")?;
    let password = field(req, "masterPassword")?;
    let id = field(req, "id")?;

    let mut vault = Vault::unlock(path, password).map_err(|e| e.to_string())?;
    vault.clear_entry_totp(id).map_err(|e| e.to_string())?;
    let salt = vault.ensure_sync_salt();
    vault.save(password).map_err(|e| e.to_string())?;
    sync_push_upsert(&vault, password, salt, id);
    Ok(json!({}))
}

fn merge_from_file(req: &Value) -> Result<Value, String> {
    let path = field(req, "vaultPath")?;
    let password = field(req, "masterPassword")?;
    let other_path = field(req, "otherPath")?;

    let mut vault = Vault::unlock(path, password).map_err(|e| e.to_string())?;
    let summary = vault
        .merge_from_file(other_path, password)
        .map_err(|e| e.to_string())?;
    let salt = vault.ensure_sync_salt();
    vault.save(password).map_err(|e| e.to_string())?;

    // Unlike a single add/update/delete, a merge can touch many entries at
    // once with no single id to push — so every entry gets a (cheap,
    // loopback-only) push instead, ensuring devices don't have to wait for
    // each merged entry's next individual edit to pick it up over sync too.
    if summary.changed() {
        if let Ok(entries) = vault.list_entries() {
            for e in entries {
                sync_push_upsert(&vault, password, salt, &e.id);
            }
        }
    }

    Ok(json!({
        "created": summary.created,
        "updated": summary.updated,
        "unchanged": summary.unchanged,
        "deleted": summary.deleted,
    }))
}

fn entry_to_json(entry: &PasswordEntry) -> Value {
    let mut json = json!({
        "id": entry.id,
        "website": entry.website,
        "url": entry.url,
        "username": entry.username,
        "password": entry.password(),
        "notes": entry.notes,
        "additionalUrls": entry.additional_urls,
        "createdAt": entry.created_at.to_rfc3339(),
        "updatedAt": entry.updated_at.to_rfc3339(),
    });

    if let Some(totp) = &entry.totp {
        let now = chrono::Utc::now();
        if let Ok(code) = passlib::totp::generate_code(totp, now) {
            json["totp"] = json!({
                "code": code,
                "secondsRemaining": passlib::totp::seconds_remaining(totp, now),
            });
        }
    }

    json
}
