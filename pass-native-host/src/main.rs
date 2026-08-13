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

use passlib::{PasswordEntry, Vault};
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
        "initVault" => init_vault(request),
        "unlockVault" => unlock_vault(request),
        "getEntry" => get_entry(request),
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

fn vault_exists(req: &Value) -> Result<Value, String> {
    let path = field(req, "vaultPath")?;
    Ok(json!({ "exists": std::path::Path::new(path).exists() }))
}

fn init_vault(req: &Value) -> Result<Value, String> {
    let path = field(req, "vaultPath")?;
    let password = field(req, "masterPassword")?;
    Vault::init(path, password).map_err(|e| e.to_string())?;
    Ok(json!({}))
}

fn unlock_vault(req: &Value) -> Result<Value, String> {
    let path = field(req, "vaultPath")?;
    let password = field(req, "masterPassword")?;

    let vault = Vault::unlock(path, password).map_err(|e| e.to_string())?;
    let entries = vault.list_entries().map_err(|e| e.to_string())?;
    Ok(json!({ "entries": entries }))
}

fn get_entry(req: &Value) -> Result<Value, String> {
    let path = field(req, "vaultPath")?;
    let password = field(req, "masterPassword")?;
    let id = field(req, "id")?;

    let vault = Vault::unlock(path, password).map_err(|e| e.to_string())?;
    let entry = vault.get_entry(id).map_err(|e| e.to_string())?;
    Ok(json!({ "entry": entry_to_json(entry) }))
}

fn add_entry(req: &Value) -> Result<Value, String> {
    let path = field(req, "vaultPath")?;
    let password = field(req, "masterPassword")?;
    let website = field(req, "website")?.to_string();
    let url = field(req, "url").unwrap_or("").to_string();
    let username = field(req, "username")?.to_string();
    let entry_password = field(req, "entryPassword")?.to_string();

    let mut vault = Vault::unlock(path, password).map_err(|e| e.to_string())?;
    let entry = PasswordEntry::new(website, url, username, entry_password);
    let id = vault.add_entry(entry).map_err(|e| e.to_string())?;
    vault.save(password).map_err(|e| e.to_string())?;
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
        )
        .map_err(|e| e.to_string())?;
    vault.save(password).map_err(|e| e.to_string())?;
    Ok(json!({}))
}

fn delete_entry(req: &Value) -> Result<Value, String> {
    let path = field(req, "vaultPath")?;
    let password = field(req, "masterPassword")?;
    let id = field(req, "id")?;

    let mut vault = Vault::unlock(path, password).map_err(|e| e.to_string())?;
    vault.delete_entry(id).map_err(|e| e.to_string())?;
    vault.save(password).map_err(|e| e.to_string())?;
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
    vault.save(password).map_err(|e| e.to_string())?;
    Ok(json!({}))
}

fn remove_totp(req: &Value) -> Result<Value, String> {
    let path = field(req, "vaultPath")?;
    let password = field(req, "masterPassword")?;
    let id = field(req, "id")?;

    let mut vault = Vault::unlock(path, password).map_err(|e| e.to_string())?;
    vault.clear_entry_totp(id).map_err(|e| e.to_string())?;
    vault.save(password).map_err(|e| e.to_string())?;
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
    vault.save(password).map_err(|e| e.to_string())?;

    Ok(json!({
        "added": summary.added,
        "updated": summary.updated,
        "unchanged": summary.unchanged,
        "conflicts": summary.conflicts,
    }))
}

fn entry_to_json(entry: &PasswordEntry) -> Value {
    let mut json = json!({
        "id": entry.id,
        "website": entry.website,
        "url": entry.url,
        "username": entry.username,
        "password": entry.password(),
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
