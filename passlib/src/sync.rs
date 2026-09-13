//! Real-time cross-device sync via the local `pass-syncd` daemon (see
//! `../../pass-syncd/README.md` for the daemon side of this).
//!
//! `pass-syncd` itself is a content-agnostic CRDT log: it replicates
//! opaque `(entity, value)` blobs between devices with last-writer-wins
//! semantics and never inspects `value`. This module is what makes that
//! safe for a password vault: every entry is serialized to JSON and
//! encrypted with AES-256-GCM, keyed by a value derived from the vault's
//! own master password plus a random salt stored inside the vault itself
//! (see [`crate::vault::Vault::sync_salt`]) — so any device that can
//! unlock the vault can also decrypt its sync traffic, with no extra
//! secret to distribute, and the daemon (and anyone who compromises its
//! ledger or the network it runs on) never sees a password in the clear.
//!
//! [`SyncHandle`] is the entry point every client (CLI, native host, GNOME,
//! and — via `passlib_ffi` — the Apple app) uses: [`SyncHandle::push_upsert`]/
//! [`SyncHandle::push_delete`] right after a local mutation is saved, and
//! [`SyncHandle::pull_and_apply`] before displaying entries or on a
//! periodic timer while the vault is unlocked. Both directions are
//! deliberately best-effort: `pass-syncd` not being installed or not
//! running must never break normal single-device use of the vault, so
//! every network failure here is swallowed (after a best-effort log line),
//! never propagated as an error to the caller.
//!
//! # Joining an existing synced vault from a brand-new device
//!
//! [`import_from_sync`] is the other direction: for a vault with no
//! entries yet, it checks whether `pass-syncd` already knows this vault's
//! salt (pushed by some other device that set it up first — see
//! [`SyncHandle::push_upsert`]/`push_delete`, which both push it alongside
//! every real change) and, if so, adopts that exact salt and immediately
//! pulls in every entry the mesh currently has, instead of generating an
//! incompatible random salt of its own the way [`crate::vault::Vault::init`]
//! plus [`crate::vault::Vault::ensure_sync_salt`] would. This is what makes
//! `pass init` on a fresh device able to hydrate itself from devices
//! already on the same tailnet/LAN, without ever needing the vault file
//! copied there by hand first.
//!
//! The salt itself is the one value here that travels **unencrypted**:
//! like any KDF salt, it's not a secret by design (what protects entry
//! contents is the master password combined with it, never the salt's own
//! secrecy) — see [`SyncHandle::push_upsert`]'s doc comment.

use crate::entry::PasswordEntry;
use crate::totp::TotpConfig;
use crate::vault::Vault;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Default port of a locally running `pass-syncd serve`, used only if
/// neither `PASS_SYNCD_URL` nor the port sidecar file (see
/// `resolve_base_url`) says otherwise.
const DEFAULT_PORT: u16 = 47210;
const KEY_LEN: usize = 32;
const REQUEST_TIMEOUT: Duration = Duration::from_millis(800);

/// Reserved entity id carrying this vault's sync salt (base64 of the raw 16
/// bytes, unencrypted — see the module doc comment). Never collides with a
/// real entry's entity id, which is always a lowercase UUID.
const SALT_ENTITY: &str = "__pass_sync_salt__";

/// `~/.pass-syncd` — must match `pass-syncd`'s own `persist::default_data_dir`
/// exactly, since this is how a client finds a daemon that isn't on the
/// default port without needing `PASS_SYNCD_URL` set. Not shared via a
/// common crate for the same reason the wire types below aren't either.
fn syncd_data_dir() -> PathBuf {
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".pass-syncd")
}

/// Where a locally running `pass-syncd serve` actually is: `PASS_SYNCD_URL`
/// if set (mainly for tests, or a daemon reached some other way); otherwise
/// the port recorded in `~/.pass-syncd/port` (written by `serve` on
/// startup — see `pass-syncd/src/persist.rs`'s `write_port_file`), so a
/// daemon started with a non-default `--port` is still found automatically;
/// otherwise the compiled-in default port.
fn resolve_base_url() -> String {
    if let Ok(url) = std::env::var("PASS_SYNCD_URL") {
        return url;
    }
    let port = std::fs::read_to_string(syncd_data_dir().join("port"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(DEFAULT_PORT);
    format!("http://127.0.0.1:{port}")
}

// ---------------------------------------------------------------- wire types
// Mirrors pass-syncd's local HTTP API request/response shapes (see
// pass-syncd/src/main.rs) — duplicated here rather than shared via a common
// crate, the same way `reading-list-syncd` has no Rust-side client library
// of its own either; the wire format, not shared Rust types, is the
// contract between the two binaries. Reconciliation reads pass-syncd's
// already-resolved `/state` snapshot rather than raw ops (see `SyncState`'s
// doc comment below for why), so that's the only response shape needed
// here — `POST /write`'s response body isn't even parsed, only its status.

type VersionVector = BTreeMap<String, u64>;

#[derive(Serialize)]
struct WriteReq<'a> {
    entity: &'a str,
    value: Option<String>,
}

#[derive(Deserialize)]
struct StateEntry {
    entity: String,
    value: Option<String>,
}

#[derive(Deserialize)]
struct StateResp {
    entries: Vec<StateEntry>,
    #[allow(dead_code)]
    vv: VersionVector,
    fingerprint: String,
}

// ------------------------------------------------------------ entry payload

/// What actually gets encrypted and sent as an `Op`'s `value`. Deliberately
/// excludes `id` (that's the `entity`/CRDT key, not part of the value) and
/// `history` (each device's KDBX4 history keeps archiving locally on its
/// own edits; carrying it over the wire too would just be a second,
/// possibly-diverging copy of information each device already derives on
/// its own — a known, acceptable limitation, not a bug).
#[derive(Serialize, Deserialize)]
struct EntryPayload {
    website: String,
    url: String,
    username: String,
    password: String,
    notes: String,
    additional_urls: Vec<String>,
    totp: Option<TotpConfig>,
}

impl From<&PasswordEntry> for EntryPayload {
    fn from(e: &PasswordEntry) -> Self {
        Self {
            website: e.website.clone(),
            url: e.url.clone(),
            username: e.username.clone(),
            password: e.password().to_string(),
            notes: e.notes.clone(),
            additional_urls: e.additional_urls.clone(),
            totp: e.totp.clone(),
        }
    }
}

// -------------------------------------------------------------- sync state

/// Per-vault bookkeeping this client keeps of what it has already applied
/// from `pass-syncd`'s resolved state, persisted next to the vault file
/// (`<vault>.sync-state.json`) since CLI/native-host processes are
/// one-shot with no in-memory state between invocations.
///
/// Reconciliation works against `pass-syncd`'s already-resolved `/state`
/// snapshot (the winning value per entity, computed daemon-side by its own
/// LWW merge — see `core::Replica::entries`) rather than replaying raw
/// `/ops/since` events and re-deriving the winner client-side: the daemon
/// has already done that CRDT resolution correctly, so re-implementing the
/// same (hlc, device) tie-break here would just be a second place for that
/// logic to drift out of sync. `known_entities` tracks which entity ids
/// this client has ever seen from the daemon, which is what lets
/// `pull_and_apply` tell "entity vanished from remote state because
/// another device deleted it" apart from "entity was never pushed because
/// the daemon was unreachable at the time" — the latter must not delete a
/// perfectly good local-only entry.
#[derive(Default, Serialize, Deserialize)]
struct SyncState {
    #[serde(default)]
    known_entities: HashSet<String>,
    #[serde(default)]
    last_fingerprint: String,
}

fn state_path(vault_path: &Path) -> PathBuf {
    let mut s = vault_path.as_os_str().to_os_string();
    s.push(".sync-state.json");
    PathBuf::from(s)
}

fn load_state(vault_path: &Path) -> SyncState {
    fs::read_to_string(state_path(vault_path))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_state(vault_path: &Path, state: &SyncState) {
    if let Ok(json) = serde_json::to_string(state) {
        let _ = fs::write(state_path(vault_path), json);
    }
}

// -------------------------------------------------------------- SyncHandle

/// A live connection to this vault's `pass-syncd`, scoped to one vault
/// file. Cheap to construct (holds only a small HTTP client and a 32-byte
/// key) — call [`SyncHandle::for_vault`] fresh at each call site rather
/// than trying to keep one alive across a whole session.
pub struct SyncHandle {
    base_url: String,
    key: [u8; KEY_LEN],
    salt: [u8; 16],
    vault_path: PathBuf,
    client: reqwest::blocking::Client,
}

impl SyncHandle {
    /// Derives this vault's sync key from `master_password` and `salt`
    /// (see [`crate::vault::Vault::sync_salt`]/`ensure_sync_salt`) and
    /// returns a handle pointed at the local `pass-syncd` (see
    /// `resolve_base_url` for how its address is found). Never fails on
    /// its own — the daemon's actual reachability is only discovered (and
    /// tolerated) when a push/pull is attempted.
    pub fn new(vault_path: &Path, salt: [u8; 16], master_password: &str) -> Self {
        let mut key = [0u8; KEY_LEN];
        // Argon2id, independent of KDBX's own internal KDF/salt — this key
        // exists purely to encrypt sync traffic, so reusing the vault's
        // internal key material (which the `keepass` crate doesn't expose
        // anyway) isn't an option, and isn't needed either: a second,
        // independently-salted derivation from the same master password is
        // exactly as strong as the vault's own encryption.
        let _ = argon2::Argon2::default().hash_password_into(master_password.as_bytes(), &salt, &mut key);
        let base_url = resolve_base_url();
        let client = reqwest::blocking::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());
        Self { base_url, key, salt, vault_path: vault_path.to_path_buf(), client }
    }

    /// Convenience constructor reading the salt straight off an already
    /// unlocked vault. Returns `None` if the vault has no sync salt yet
    /// (an old vault predating this feature that no mutating command has
    /// touched since upgrading — see [`crate::vault::Vault::sync_salt`]);
    /// callers on a mutating path should call
    /// [`crate::vault::Vault::ensure_sync_salt`] first instead so sync
    /// gets backfilled lazily rather than staying permanently off.
    pub fn for_vault(vault: &Vault, master_password: &str) -> Option<Self> {
        let salt = vault.sync_salt()?;
        Some(Self::new(vault.path(), salt, master_password))
    }

    fn encrypt(&self, plaintext: &[u8]) -> Option<String> {
        let cipher = Aes256Gcm::new_from_slice(&self.key).ok()?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, plaintext).ok()?;
        let mut blob = Vec::with_capacity(nonce.len() + ciphertext.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        Some(BASE64.encode(blob))
    }

    fn decrypt(&self, blob_b64: &str) -> Option<Vec<u8>> {
        let blob = BASE64.decode(blob_b64).ok()?;
        if blob.len() < 12 {
            return None;
        }
        let (nonce_bytes, ciphertext) = blob.split_at(12);
        let cipher = Aes256Gcm::new_from_slice(&self.key).ok()?;
        cipher.decrypt(Nonce::from_slice(nonce_bytes), ciphertext).ok()
    }

    /// Pushes an add/update as the new full state of this entry, alongside
    /// this vault's sync salt (see [`SALT_ENTITY`]) — cheap and idempotent
    /// (same value every time from this device's point of view), and it's
    /// what lets [`import_from_sync`] find the salt from a brand-new device
    /// that has no vault file yet. Best-effort: logs and swallows any
    /// failure (daemon not installed/not running, network hiccup) rather
    /// than surfacing it, since local vault edits must always succeed
    /// regardless of sync's availability.
    ///
    /// The salt itself travels unencrypted — unlike every entry payload,
    /// which is always AES-256-GCM-encrypted first. This is deliberate,
    /// not an oversight: a KDF salt is not a secret by design (the same
    /// reason password hashes are stored right next to their salt), so
    /// there's nothing to protect by encrypting it, and doing so would
    /// only reintroduce the chicken-and-egg problem `import_from_sync`
    /// exists to avoid — a new device needs the salt *before* it can
    /// derive the key that would otherwise decrypt it.
    pub fn push_upsert(&self, entry: &PasswordEntry) {
        self.push_salt();
        let payload = EntryPayload::from(entry);
        let Ok(json) = serde_json::to_vec(&payload) else { return };
        let Some(blob) = self.encrypt(&json) else {
            eprintln!("[sync] failed to encrypt entry {} for push", entry.id);
            return;
        };
        self.write(&entry.id, Some(blob));
    }

    /// Pushes a deletion (and this vault's sync salt, see
    /// [`SyncHandle::push_upsert`]). Best-effort/never-fails, same
    /// contract as `push_upsert`.
    pub fn push_delete(&self, id: &str) {
        self.push_salt();
        self.write(id, None);
    }

    fn push_salt(&self) {
        self.write(SALT_ENTITY, Some(BASE64.encode(self.salt)));
    }

    fn write(&self, entity: &str, value: Option<String>) {
        let result = self
            .client
            .post(format!("{}/write", self.base_url))
            .json(&WriteReq { entity, value })
            .send();
        if let Err(e) = result.and_then(|r| r.error_for_status()) {
            eprintln!("[sync] push failed for {entity} (pass-syncd not running?): {e}");
        }
    }

    /// Pulls `pass-syncd`'s current resolved state and reconciles it into
    /// `vault` (upserting/deleting entries as needed). Does **not** call
    /// [`Vault::save`] — that's left to the caller, exactly like every
    /// other `Vault` mutation method, so callers that also have their own
    /// local change pending in the same request save once for both.
    /// Returns the number of local entries changed; `Ok(0)` (not an error)
    /// if the daemon is unreachable or nothing changed.
    pub fn pull_and_apply(&self, vault: &mut Vault) -> usize {
        let resp = match self.client.get(format!("{}/state", self.base_url)).send() {
            Ok(r) => r,
            Err(_) => return 0, // daemon not running: not an error, just nothing to do
        };
        let state: StateResp = match resp.error_for_status().and_then(|r| r.json()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[sync] pull failed: {e}");
                return 0;
            }
        };

        let mut local_state = load_state(&self.vault_path);
        if state.fingerprint == local_state.last_fingerprint {
            return 0; // nothing changed since our last successful pull
        }

        let mut changed = 0usize;
        let mut seen_now: HashSet<String> = HashSet::new();

        for entry in &state.entries {
            if entry.entity == SALT_ENTITY {
                continue; // not a password entry — see push_upsert/push_delete
            }
            seen_now.insert(entry.entity.clone());
            let Some(value) = &entry.value else { continue };
            let Some(plaintext) = self.decrypt(value) else {
                eprintln!("[sync] could not decrypt entity {} (wrong/rotated key?)", entry.entity);
                continue;
            };
            let Ok(payload) = serde_json::from_slice::<EntryPayload>(&plaintext) else {
                eprintln!("[sync] could not parse decrypted payload for {}", entry.entity);
                continue;
            };
            if apply_upsert(vault, &entry.entity, payload) {
                changed += 1;
            }
        }

        // Anything this client has previously seen from the daemon but
        // that's no longer in its resolved state was deleted by some
        // device (possibly this one). An entity this client has *never*
        // seen from the daemon yet is left alone even if it's not in
        // `seen_now` — that's a local-only entry whose push simply hasn't
        // reached the daemon (e.g. it wasn't running at the time), not a
        // remote deletion.
        for id in local_state.known_entities.difference(&seen_now).cloned().collect::<Vec<_>>() {
            if vault.get_entry(&id).is_ok() && vault.delete_entry(&id).is_ok() {
                changed += 1;
            }
        }

        local_state.known_entities = seen_now;
        local_state.last_fingerprint = state.fingerprint;
        save_state(&self.vault_path, &local_state);

        changed
    }
}

/// Checks whether the locally running `pass-syncd` already knows a sync
/// salt for this vault — i.e. some other device has already pushed at
/// least one change since setting this same vault up for sync — without
/// needing an already-open [`Vault`] (there isn't one yet, for the
/// "join an existing synced vault" flow [`import_from_sync`] is for).
/// Returns `None`, indistinguishably, if the daemon is unreachable *or* no
/// device has pushed anything yet: both mean "nothing to import," the
/// normal case for a genuinely first vault, which should just get a fresh
/// random salt from [`crate::vault::Vault::ensure_sync_salt`] instead.
pub fn discover_existing_salt() -> Option<[u8; 16]> {
    let base_url = resolve_base_url();
    let client = reqwest::blocking::Client::builder().timeout(REQUEST_TIMEOUT).build().ok()?;
    let state: StateResp = client.get(format!("{base_url}/state")).send().ok()?.error_for_status().ok()?.json().ok()?;
    let value = state.entries.iter().find(|e| e.entity == SALT_ENTITY)?.value.as_ref()?;
    BASE64.decode(value).ok()?.try_into().ok()
}

/// For a brand-new vault (typically right after [`crate::vault::Vault::init`],
/// before anything has been added to it): if [`discover_existing_salt`]
/// finds that some other device already set this same vault up for sync,
/// adopts that exact salt (via [`crate::vault::Vault::set_sync_salt`]) and
/// immediately pulls in every entry the mesh currently has for it. This is
/// what lets a brand-new device hydrate itself over the tailnet/LAN
/// without the vault file ever having to be copied there by hand first.
///
/// Returns `None` if there was nothing to import (daemon unreachable, or
/// no device has set this vault up for sync yet) — the caller should treat
/// that the same as "start empty," not as an error. `Some(count)` on
/// success, where `count` (possibly `0`, if the salt exists but the mesh
/// genuinely has no live entries right now) is how many entries were
/// imported. Does **not** call [`Vault::save`]; the caller does, same as
/// every other mutating call in this crate.
pub fn import_from_sync(vault: &mut Vault, master_password: &str) -> Option<usize> {
    let salt = discover_existing_salt()?;
    vault.set_sync_salt(salt);
    let handle = SyncHandle::new(vault.path(), salt, master_password);
    Some(handle.pull_and_apply(vault))
}

/// Applies one entity's resolved remote payload into `vault`: full
/// overwrite of every field (this is the entity's whole current state per
/// the daemon's LWW resolution, not a partial patch), inserting a new
/// entry with that exact id if it doesn't exist locally yet. Returns
/// whether the local vault actually changed.
fn apply_upsert(vault: &mut Vault, id: &str, payload: EntryPayload) -> bool {
    if vault.get_entry(id).is_ok() {
        let totp_changed = vault
            .update_entry(
                id,
                Some(payload.website),
                Some(payload.url),
                Some(payload.username),
                Some(payload.password),
                Some(payload.notes),
                Some(payload.additional_urls),
            )
            .is_ok();
        let totp_result = match payload.totp {
            Some(totp) => vault.set_entry_totp(id, totp),
            None => vault.clear_entry_totp(id),
        };
        totp_changed && totp_result.is_ok()
    } else {
        let entry = PasswordEntry::from_parts(
            id.to_string(),
            payload.website,
            payload.url,
            payload.username,
            payload.password,
            chrono::Utc::now(),
            chrono::Utc::now(),
            payload.totp,
            payload.notes,
            payload.additional_urls,
            Vec::new(),
        );
        vault.add_entry(entry).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Vault;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use tempfile::NamedTempFile;

    fn temp_vault_path() -> PathBuf {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_path_buf();
        drop(f);
        path
    }

    #[test]
    fn encrypt_decrypt_roundtrips_and_is_keyed_by_master_password() {
        let handle_a = SyncHandle::new(&temp_vault_path(), [7u8; 16], "correct horse");
        let handle_b = SyncHandle::new(&temp_vault_path(), [7u8; 16], "wrong horse");

        let blob = handle_a.encrypt(b"super secret payload").unwrap();
        assert_eq!(handle_a.decrypt(&blob).unwrap(), b"super secret payload");
        // A different master password (same salt) must not decrypt it: the
        // whole point of deriving the key from the master password is that
        // pass-syncd (or anyone reading its ledger) can't recover entries
        // without it.
        assert!(handle_b.decrypt(&blob).is_none());
    }

    #[test]
    fn sync_salt_persists_across_save_and_unlock() {
        let path = temp_vault_path();
        let master_password = "test_password";
        let mut vault = Vault::init(&path, master_password).unwrap();
        assert!(vault.sync_salt().is_none());

        let salt = vault.ensure_sync_salt();
        vault.save(master_password).unwrap();

        let reopened = Vault::unlock(&path, master_password).unwrap();
        assert_eq!(reopened.sync_salt(), Some(salt));
    }

    /// A minimal single-purpose HTTP/1.1 server standing in for
    /// `pass-syncd`'s local API in tests: `GET /state` always returns the
    /// body currently held in `state_body`, `POST /write` records the
    /// request body (so tests can assert on what got pushed) and answers
    /// `200 {}`. Good enough for exercising `SyncHandle` without pulling in
    /// a real HTTP server crate as a dev-dependency just for this.
    struct MockSyncd {
        addr: String,
        state_body: Arc<Mutex<String>>,
        writes: Arc<Mutex<Vec<serde_json::Value>>>,
    }

    impl MockSyncd {
        fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap().to_string();
            let state_body = Arc::new(Mutex::new(String::from(r#"{"device":"d","entries":[],"vv":{},"fingerprint":"empty"}"#)));
            let state_body_thread = state_body.clone();
            let writes = Arc::new(Mutex::new(Vec::new()));
            let writes_thread = writes.clone();

            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    let mut buf = [0u8; 8192];
                    let n = match stream.read(&mut buf) {
                        Ok(n) => n,
                        Err(_) => continue,
                    };
                    let request = String::from_utf8_lossy(&buf[..n]);
                    let mut lines = request.split("\r\n\r\n");
                    let head = lines.next().unwrap_or("");
                    let request_body = lines.next().unwrap_or("");
                    let path = head.lines().next().unwrap_or("").split_whitespace().nth(1).unwrap_or("");

                    let body = if path.starts_with("/state") {
                        state_body_thread.lock().unwrap().clone()
                    } else {
                        if path.starts_with("/write") {
                            if let Ok(v) = serde_json::from_str::<serde_json::Value>(request_body) {
                                writes_thread.lock().unwrap().push(v);
                            }
                        }
                        "{}".to_string()
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes());
                }
            });

            Self { addr, state_body, writes }
        }

        fn set_state(&self, body: String) {
            *self.state_body.lock().unwrap() = body;
        }

        fn writes(&self) -> Vec<serde_json::Value> {
            self.writes.lock().unwrap().clone()
        }
    }

    /// Serializes `SyncHandle::PASS_SYNCD_URL` env var mutation across
    /// tests in this module — `std::env::set_var` is process-global, so
    /// tests that point `SyncHandle` at a mock server must not run
    /// concurrently with each other.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn pull_and_apply_adds_updates_and_deletes_by_reconciling_against_remote_state() {
        let _guard = ENV_LOCK.lock().unwrap();
        let mock = MockSyncd::start();
        std::env::set_var("PASS_SYNCD_URL", format!("http://{}", mock.addr));

        let path = temp_vault_path();
        let master_password = "test_password";
        let mut vault = Vault::init(&path, master_password).unwrap();
        let salt = vault.ensure_sync_salt();
        vault.save(master_password).unwrap();
        let handle = SyncHandle::new(&path, salt, master_password);

        // A remote entity appears: pull should add it locally.
        let payload = EntryPayload {
            website: "GitHub".into(),
            url: "https://github.com".into(),
            username: "octocat".into(),
            password: "hunter2".into(),
            notes: String::new(),
            additional_urls: Vec::new(),
            totp: None,
        };
        let blob = handle.encrypt(&serde_json::to_vec(&payload).unwrap()).unwrap();
        mock.set_state(serde_json::json!({
            "device": "other", "vv": {"other": 1}, "fingerprint": "f1",
            "entries": [{"entity": "11111111-1111-4111-8111-111111111111", "value": blob}],
        }).to_string());

        let changed = handle.pull_and_apply(&mut vault);
        assert_eq!(changed, 1);
        let entry = vault.get_entry("11111111-1111-4111-8111-111111111111").unwrap();
        assert_eq!(entry.website, "GitHub");
        assert_eq!(entry.password(), "hunter2");

        // Same fingerprint again: no-op fast path, no re-decryption needed.
        let changed_again = handle.pull_and_apply(&mut vault);
        assert_eq!(changed_again, 0);

        // The remote entity is now gone (deleted on another device): pull
        // should delete it locally too.
        mock.set_state(serde_json::json!({
            "device": "other", "vv": {"other": 2}, "fingerprint": "f2",
            "entries": [],
        }).to_string());
        let changed = handle.pull_and_apply(&mut vault);
        assert_eq!(changed, 1);
        assert!(vault.get_entry("11111111-1111-4111-8111-111111111111").is_err());

        std::env::remove_var("PASS_SYNCD_URL");
    }

    #[test]
    fn pull_and_apply_never_deletes_a_local_entry_the_daemon_never_learned_about() {
        let _guard = ENV_LOCK.lock().unwrap();
        let mock = MockSyncd::start();
        std::env::set_var("PASS_SYNCD_URL", format!("http://{}", mock.addr));

        let path = temp_vault_path();
        let master_password = "test_password";
        let mut vault = Vault::init(&path, master_password).unwrap();
        let salt = vault.ensure_sync_salt();
        vault.save(master_password).unwrap();
        let handle = SyncHandle::new(&path, salt, master_password);

        // A local-only entry that was never pushed successfully (daemon
        // was down at add time, say) must survive a pull even though the
        // daemon's state doesn't mention it.
        let local_only = crate::entry::PasswordEntry::new(
            "Local".into(), "https://local.example".into(), "me".into(), "pw".into(),
        );
        vault.add_entry(local_only).unwrap();

        mock.set_state(serde_json::json!({
            "device": "other", "vv": {}, "fingerprint": "f1", "entries": [],
        }).to_string());
        let changed = handle.pull_and_apply(&mut vault);
        assert_eq!(changed, 0);
        assert_eq!(vault.len(), 1);

        std::env::remove_var("PASS_SYNCD_URL");
    }

    #[test]
    fn push_upsert_and_push_delete_also_push_the_salt_entity() {
        let _guard = ENV_LOCK.lock().unwrap();
        let mock = MockSyncd::start();
        std::env::set_var("PASS_SYNCD_URL", format!("http://{}", mock.addr));

        let handle = SyncHandle::new(&temp_vault_path(), [9u8; 16], "pw");
        let entry = PasswordEntry::new("GitHub".into(), "https://github.com".into(), "me".into(), "pw".into());
        handle.push_upsert(&entry);
        handle.push_delete(&entry.id);

        let writes = mock.writes();
        let salt_writes: Vec<_> = writes.iter().filter(|w| w["entity"] == SALT_ENTITY).collect();
        assert_eq!(salt_writes.len(), 2, "both push_upsert and push_delete should push the salt entity");
        assert_eq!(salt_writes[0]["value"], BASE64.encode([9u8; 16]));

        let entry_writes: Vec<_> = writes.iter().filter(|w| w["entity"] == entry.id).collect();
        assert_eq!(entry_writes.len(), 2);
        assert!(entry_writes[0]["value"].is_string()); // upsert: encrypted blob
        assert!(entry_writes[1]["value"].is_null()); // delete

        std::env::remove_var("PASS_SYNCD_URL");
    }

    #[test]
    fn discover_existing_salt_finds_nothing_on_an_empty_mesh() {
        let _guard = ENV_LOCK.lock().unwrap();
        let mock = MockSyncd::start();
        std::env::set_var("PASS_SYNCD_URL", format!("http://{}", mock.addr));

        mock.set_state(serde_json::json!({
            "device": "other", "vv": {}, "fingerprint": "f1", "entries": [],
        }).to_string());
        assert!(discover_existing_salt().is_none());

        std::env::remove_var("PASS_SYNCD_URL");
    }

    #[test]
    fn import_from_sync_adopts_the_discovered_salt_and_hydrates_a_brand_new_vault() {
        let _guard = ENV_LOCK.lock().unwrap();
        let mock = MockSyncd::start();
        std::env::set_var("PASS_SYNCD_URL", format!("http://{}", mock.addr));

        let salt = [3u8; 16];
        let master_password = "shared_master_password";
        // Another device already pushed its salt and one entry.
        let remote_handle = SyncHandle::new(&temp_vault_path(), salt, master_password);
        let payload = EntryPayload {
            website: "GitHub".into(),
            url: "https://github.com".into(),
            username: "octocat".into(),
            password: "hunter2".into(),
            notes: String::new(),
            additional_urls: Vec::new(),
            totp: None,
        };
        let blob = remote_handle.encrypt(&serde_json::to_vec(&payload).unwrap()).unwrap();
        mock.set_state(serde_json::json!({
            "device": "other", "vv": {"other": 2}, "fingerprint": "f1",
            "entries": [
                {"entity": SALT_ENTITY, "value": BASE64.encode(salt)},
                {"entity": "22222222-2222-4222-8222-222222222222", "value": blob},
            ],
        }).to_string());

        // A brand-new, empty vault with no salt of its own yet.
        let path = temp_vault_path();
        let mut vault = Vault::init(&path, master_password).unwrap();
        assert!(vault.sync_salt().is_none());

        let imported = import_from_sync(&mut vault, master_password);
        assert_eq!(imported, Some(1));
        assert_eq!(vault.sync_salt(), Some(salt));
        let entry = vault.get_entry("22222222-2222-4222-8222-222222222222").unwrap();
        assert_eq!(entry.website, "GitHub");
        assert_eq!(entry.password(), "hunter2");

        std::env::remove_var("PASS_SYNCD_URL");
    }
}
