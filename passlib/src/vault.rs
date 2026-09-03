//! Vault storage backed by a real KDBX4 database (via the `keepass` crate),
//! the native file format used by KeePass/KeePassXC. This is what makes a
//! vault written by `pass` openable directly in KeePassXC (and vice versa)
//! instead of a proprietary format only `pass` understands.
//!
//! Mapping from [`PasswordEntry`] to a KDBX entry:
//! - website/url/username/password -> the standard Title/URL/UserName/Password fields
//! - TOTP -> the standard `otp` field (an `otpauth://` URI), the same
//!   convention KeePassXC itself uses
//! - deletion -> moving the entry into a "Recycle Bin" group (KeePassXC's
//!   own soft-delete convention), not a hard remove, so it stays
//!   recoverable and still participates in cross-device merges
//! - cross-device merge -> [`keepass::Database::merge`], which reconciles
//!   two independently-edited copies of the database using each object's
//!   last-modification time — no custom merge algorithm needed here
//!   anymore.

use crate::entry::{PasswordEntry, PasswordEntrySummary, PasswordHistoryEntry};
use crate::error::{PassError, Result};
use crate::share::ShareIdentity;
use crate::sync::{DeviceIdentity, SyncKey};
use crate::sshkey::{self, SshKey, SshKeySummary, KEEAGENT_SETTINGS_FIELD};
use crate::totp::{self, TotpConfig};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::{DateTime, NaiveDateTime, Utc};
use keepass::config::KdfConfig;
use keepass::db::{fields, merge::MergeLog, DatabaseOpenError, EntryId, EntryRef, GroupId, Times, Value};
use keepass::error::DatabaseKeyError;
use keepass::{Database, DatabaseKey};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use uuid::Uuid;

const RECYCLE_BIN_GROUP_NAME: &str = "Recycle Bin";

/// Group `pass` files the SSH keys it creates under. Keys stored anywhere
/// else in the database (e.g. added from KeePassXC's own SSH Agent tab) are
/// still found by [`Vault::list_ssh_keys`] — this group only decides where
/// *new* keys land, and keeps them out of the password listing.
const SSH_KEYS_GROUP_NAME: &str = "SSH Keys";

/// Group holding `pass`'s own configuration entries (currently just the
/// sharing identity). Excluded from the password listing for the same reason.
const PASS_GROUP_NAME: &str = "Pass";

const SHARE_IDENTITY_ENTRY_TITLE: &str = "Sharing Identity";
/// Protected custom field holding this vault's X25519 sharing private key,
/// base64-encoded. Protected, so KDBX's inner stream cipher covers it too and
/// it isn't sitting in the clear in the decrypted XML.
const SHARE_SECRET_FIELD: &str = "Pass_ShareSecretKey";
/// Unprotected custom field listing known sharing contacts, one
/// `label<TAB>public-key` per line. Public keys are public; keeping them
/// unprotected means they stay readable in KeePassXC.
const SHARE_CONTACTS_FIELD: &str = "Pass_ShareContacts";

const SYNC_ENTRY_TITLE: &str = "Sync";
/// Protected custom field holding the 32-byte key every device replicating
/// this vault seals op payloads with, base64-encoded. See [`crate::sync`].
const SYNC_KEY_FIELD: &str = "Pass_SyncKey";

/// Title prefix of the per-device entries making up the sync roster. One
/// entry per device that has ever replicated this vault.
const DEVICE_ENTRY_PREFIX: &str = "Device: ";
/// Protected custom field holding that device's Ed25519 signing key.
const DEVICE_SECRET_FIELD: &str = "Pass_DeviceSecretKey";
/// Unprotected: the device's key fingerprint, which is what trust is
/// granted to and what the device id is built from.
const DEVICE_FINGERPRINT_FIELD: &str = "Pass_DeviceFingerprint";
/// Unprotected: the device's current op-log epoch (see [`crate::sync`]).
const DEVICE_EPOCH_FIELD: &str = "Pass_DeviceEpoch";

/// Custom KDBX string field holding this entry's extra URLs (beyond the
/// standard `URL` field), newline-separated. Not a real KeePassXC feature —
/// KDBX4 has no native "multiple URLs" field — just a plain custom
/// attribute, so it shows up (and is editable) as one in KeePassXC/any
/// other KDBX tool, they just won't know to match against it themselves.
const ADDITIONAL_URLS_FIELD: &str = "Pass_AdditionalURLs";

fn encode_additional_urls(urls: &[String]) -> String {
    urls.join("\n")
}

fn decode_additional_urls(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

/// An open (decrypted) KDBX4 password vault.
#[derive(Debug)]
pub struct Vault {
    db: Database,
    path: PathBuf,
}

impl Vault {
    /// Initialize a new vault file with a master password
    ///
    /// Creates a new encrypted KDBX4 vault file. Returns an error if the file already exists.
    pub fn init<P: AsRef<Path>>(path: P, master_password: &str) -> Result<Self> {
        let path = path.as_ref();

        if path.exists() {
            return Err(PassError::SaveError(format!(
                "Vault file already exists: {}",
                path.display()
            )));
        }

        let mut db = Database::new();
        strengthen_kdf(&mut db);

        let mut vault = Self {
            db,
            path: path.to_path_buf(),
        };
        vault.save(master_password)?;

        Ok(vault)
    }

    /// Unlock an existing vault with the master password
    ///
    /// Reads and decrypts the KDBX4 vault file. Returns an error if the password is incorrect.
    pub fn unlock<P: AsRef<Path>>(path: P, master_password: &str) -> Result<Self> {
        let path = path.as_ref();

        if !path.exists() {
            return Err(PassError::VaultNotFound(path.display().to_string()));
        }

        let mut file = File::open(path)?;
        let db = Database::open(&mut file, DatabaseKey::new().with_password(master_password))
            .map_err(map_open_error)?;

        Ok(Self {
            db,
            path: path.to_path_buf(),
        })
    }

    /// Save the vault to disk, re-encrypting it with the given master password
    pub fn save(&mut self, master_password: &str) -> Result<()> {
        let temp_path = self.path.with_extension("kdbx.tmp");
        let mut file = File::create(&temp_path)?;

        self.db
            .save(&mut file, DatabaseKey::new().with_password(master_password))
            .map_err(|e| PassError::SaveError(e.to_string()))?;
        file.sync_all()?;
        drop(file);

        fs::rename(&temp_path, &self.path)?;
        Ok(())
    }

    /// Add a new password entry
    pub fn add_entry(&mut self, entry: PasswordEntry) -> Result<String> {
        let entry_id = parse_entry_id(&entry.id)?;

        let mut root = self.db.root_mut();
        let mut new_entry = root
            .add_entry_with_id(entry_id)
            .map_err(|e| PassError::SaveError(e.to_string()))?;

        new_entry.edit(|e| {
            e.set_unprotected(fields::TITLE, entry.website.clone());
            e.set_unprotected(fields::URL, entry.url.clone());
            e.set_unprotected(fields::USERNAME, entry.username.clone());
            e.set_protected(fields::PASSWORD, entry.password().to_string());
            if !entry.notes.is_empty() {
                e.set_unprotected(fields::NOTES, entry.notes.clone());
            }
            if !entry.additional_urls.is_empty() {
                e.set_unprotected(ADDITIONAL_URLS_FIELD, encode_additional_urls(&entry.additional_urls));
            }
            if let Some(totp) = &entry.totp {
                e.set_unprotected(fields::OTP, totp.to_otpauth_uri());
            }
        });

        Ok(entry.id)
    }

    /// Get all entries as summaries (without passwords), excluding
    /// anything in the Recycle Bin and in `pass`'s own bookkeeping groups
    /// (`SSH Keys`, `Pass`) — those hold SSH keys and the sharing identity,
    /// which have their own accessors and would only be noise here.
    pub fn list_entries(&self) -> Result<Vec<PasswordEntrySummary>> {
        let hidden = self.hidden_group_ids();

        Ok(self
            .db
            .iter_all_entries()
            .filter(|e| !hidden.contains(&e.parent().id()))
            .map(|e| PasswordEntrySummary::from(&to_password_entry(&e)))
            .collect())
    }

    /// Get a specific entry by ID (including password)
    pub fn get_entry(&self, id: &str) -> Result<PasswordEntry> {
        let entry_id = parse_entry_id(id)?;
        let entry_ref = self
            .db
            .entry(entry_id)
            .filter(|e| self.is_visible_entry(e))
            .ok_or_else(|| PassError::EntryNotFound(id.to_string()))?;

        Ok(to_password_entry(&entry_ref))
    }

    /// Delete an entry by ID
    ///
    /// This moves the entry into the vault's Recycle Bin group (creating
    /// it if needed) rather than removing it outright — the same
    /// soft-delete convention KeePassXC itself uses, so the entry stays
    /// recoverable and the deletion still propagates correctly through
    /// [`Vault::merge_entries`]/[`Vault::merge_from_file`].
    pub fn delete_entry(&mut self, id: &str) -> Result<()> {
        let entry_id = parse_entry_id(id)?;
        self.require_active_entry(entry_id, id)?;

        let recycle_bin_id = self.ensure_recycle_bin();

        let mut entry_mut = self
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| PassError::EntryNotFound(id.to_string()))?;
        entry_mut
            .track_changes()
            .move_to(recycle_bin_id)
            .map_err(|e| PassError::SaveError(e.to_string()))?;

        Ok(())
    }

    /// Update an existing entry. `password`, if present, is archived into
    /// the entry's KDBX4 history automatically — the same `track_changes`
    /// mechanism KeePassXC itself relies on for its own history — so past
    /// passwords stay recoverable via [`Vault::get_entry`]'s `history`.
    #[allow(clippy::too_many_arguments)]
    pub fn update_entry(
        &mut self,
        id: &str,
        website: Option<String>,
        url: Option<String>,
        username: Option<String>,
        password: Option<String>,
        notes: Option<String>,
        additional_urls: Option<Vec<String>>,
    ) -> Result<()> {
        let entry_id = parse_entry_id(id)?;
        self.require_active_entry(entry_id, id)?;

        let mut entry_mut = self
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| PassError::EntryNotFound(id.to_string()))?;
        let mut tracked = entry_mut.track_changes();

        if let Some(w) = website {
            tracked.set_unprotected(fields::TITLE, w);
        }
        if let Some(u) = url {
            tracked.set_unprotected(fields::URL, u);
        }
        if let Some(un) = username {
            tracked.set_unprotected(fields::USERNAME, un);
        }
        if let Some(p) = password {
            tracked.set_protected(fields::PASSWORD, p);
        }
        if let Some(n) = notes {
            tracked.set_unprotected(fields::NOTES, n);
        }
        if let Some(urls) = additional_urls {
            tracked.set_unprotected(ADDITIONAL_URLS_FIELD, encode_additional_urls(&urls));
        }

        Ok(())
    }

    /// Attach (or replace) the TOTP/MFA secret for an entry
    pub fn set_entry_totp(&mut self, id: &str, totp: TotpConfig) -> Result<()> {
        let entry_id = parse_entry_id(id)?;
        self.require_active_entry(entry_id, id)?;

        let mut entry_mut = self
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| PassError::EntryNotFound(id.to_string()))?;
        entry_mut
            .track_changes()
            .set_unprotected(fields::OTP, totp.to_otpauth_uri());

        Ok(())
    }

    /// Remove the TOTP/MFA secret from an entry, if any
    pub fn clear_entry_totp(&mut self, id: &str) -> Result<()> {
        let entry_id = parse_entry_id(id)?;
        self.require_active_entry(entry_id, id)?;

        let mut entry_mut = self
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| PassError::EntryNotFound(id.to_string()))?;
        let mut tracked = entry_mut.track_changes();
        tracked.fields.remove(fields::OTP);
        tracked.times.last_modification = Some(Times::now());

        Ok(())
    }

    /// Merge another set of entries (e.g. pulled from a copy of this vault
    /// synced from another device) into this vault. Does not save
    /// automatically.
    pub fn merge_entries(&mut self, other: &Database) -> Result<MergeSummary> {
        let log = self.db.merge(other).map_err(|e| PassError::MergeError(e.to_string()))?;
        self.merge_attachments(other);
        Ok(MergeSummary::from_log(&log, self.db.num_entries()))
    }

    /// Carry attachments across a merge.
    ///
    /// `keepass` 0.13's own merge deliberately skips them — there is a
    /// literal `TODO: attachments` where entry data is copied — and for a
    /// database that holds SSH keys that is not a cosmetic gap: an entry the
    /// merge brings over from the other side arrives referencing attachment
    /// ids that only ever existed in *that* database, so the first attempt to
    /// read its key panics. Here we re-attach the binaries from the source
    /// for every entry the merge resolved in the source's favour, which after
    /// the merge is exactly the set of entries whose last-modification time
    /// now equals the source's (either because the source won, or because the
    /// entry was created wholesale from it).
    fn merge_attachments(&mut self, other: &Database) {
        let mut pending: Vec<(EntryId, String, Value<Vec<u8>>)> = Vec::new();

        for source in other.iter_all_entries() {
            let id = source.id();
            let Some(dest) = self.db.entry(id) else {
                continue;
            };
            if dest.times.last_modification != source.times.last_modification {
                // The local side won this entry; its own attachments stand.
                continue;
            }
            for (name, attachment) in source.attachments_named() {
                pending.push((id, name.to_string(), attachment.data.clone()));
            }
        }

        for (id, name, data) in pending {
            if let Some(mut entry) = self.db.entry_mut(id) {
                // Drop the stale binding *before* adding, never by letting
                // `add_attachment` replace it: the id it hands out is the
                // lowest free one, and a dangling id is by definition free,
                // so it routinely hands back the very id it is replacing —
                // whereupon `add_attachment`'s own cleanup deletes the
                // attachment it just inserted. Removing by name first is
                // safe because a dangling id resolves to `None` there.
                entry.remove_attachment_by_name(&name);
                // Plain `add_attachment`, not a tracked edit: re-attaching a
                // binary the merge failed to copy is repair work, not a user
                // edit, and must not bump timestamps or write history.
                entry.add_attachment(name, data);
            }
        }
    }

    /// Convenience wrapper: unlock another copy of this vault at `path`
    /// with the same master password and merge its entries into this one.
    /// Does not save automatically — call [`Vault::save`] afterwards to
    /// persist (and re-encrypt) the merged result.
    pub fn merge_from_file<P: AsRef<Path>>(&mut self, path: P, master_password: &str) -> Result<MergeSummary> {
        let other = Vault::unlock(path, master_password)?;
        self.merge_entries(&other.db)
    }

    /// Get the vault file path
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the number of (non-deleted) password entries
    pub fn len(&self) -> usize {
        let hidden = self.hidden_group_ids();
        self.db
            .iter_all_entries()
            .filter(|e| !hidden.contains(&e.parent().id()))
            .count()
    }

    /// Check if the vault is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn recycle_bin_id(&self) -> Option<GroupId> {
        self.db.meta.recyclebin_uuid.map(GroupId::from_uuid)
    }

    /// Groups whose entries are not password entries: the Recycle Bin plus
    /// `pass`'s own bookkeeping groups.
    fn hidden_group_ids(&self) -> Vec<GroupId> {
        let mut ids: Vec<GroupId> = self.recycle_bin_id().into_iter().collect();
        ids.extend(self.root_group_id(SSH_KEYS_GROUP_NAME));
        ids.extend(self.root_group_id(PASS_GROUP_NAME));
        ids
    }

    fn is_visible_entry(&self, entry: &EntryRef) -> bool {
        !self.hidden_group_ids().contains(&entry.parent().id())
    }

    fn require_active_entry(&self, entry_id: EntryId, display_id: &str) -> Result<()> {
        self.db
            .entry(entry_id)
            .filter(|e| self.is_visible_entry(e))
            .map(|_| ())
            .ok_or_else(|| PassError::EntryNotFound(display_id.to_string()))
    }

    /// The id of a direct child group of the root with this name, if it exists.
    fn root_group_id(&self, name: &str) -> Option<GroupId> {
        self.db.root().group_by_name(name).map(|g| g.id())
    }

    /// Get (creating if needed) a direct child group of the root.
    fn ensure_root_group(&mut self, name: &str) -> GroupId {
        if let Some(id) = self.root_group_id(name) {
            return id;
        }

        let mut root = self.db.root_mut();
        let mut group = root.add_group();
        group.name = name.to_string();
        group.id()
    }

    fn ensure_recycle_bin(&mut self) -> GroupId {
        if let Some(id) = self.recycle_bin_id() {
            if self.db.group(id).is_some() {
                return id;
            }
        }

        let mut root = self.db.root_mut();
        let mut group = root.add_group();
        group.name = RECYCLE_BIN_GROUP_NAME.to_string();
        let group_id = group.id();
        drop(group);

        self.db.meta.recyclebin_uuid = Some(group_id.uuid());
        self.db.meta.recyclebin_enabled = Some(true);
        self.db.meta.recyclebin_changed = Some(Times::now());

        group_id
    }

    // ---------------------------------------------------------------------
    // SSH keys
    //
    // Stored the way KeePassXC's own SSH-agent integration stores them: the
    // private key as an entry attachment, described by a `KeeAgent.settings`
    // custom field. See [`crate::sshkey`].
    // ---------------------------------------------------------------------

    /// Store an SSH key in the vault. Returns the id of the entry created.
    pub fn add_ssh_key(&mut self, key: &SshKey) -> Result<String> {
        if self.find_ssh_key_entry_by_fingerprint(&key.fingerprint).is_some() {
            return Err(PassError::SshKey(format!(
                "a key with fingerprint {} is already in this vault",
                key.fingerprint
            )));
        }

        let pem = key.private_key_pem()?;
        let settings = key.keeagent_settings();
        let attachment_name = key.attachment_name.clone();
        let group_id = self.ensure_root_group(SSH_KEYS_GROUP_NAME);

        let mut group = self
            .db
            .group_mut(group_id)
            .ok_or_else(|| PassError::SaveError("SSH Keys group vanished".to_string()))?;
        let mut entry = group.add_entry();
        let entry_id = entry.id();

        entry.edit(|e| {
            e.set_unprotected(fields::TITLE, key.name.clone());
            e.set_unprotected(fields::USERNAME, key.comment.clone());
            // The public key is public and useful to copy out of KeePassXC.
            e.set_unprotected(fields::NOTES, key.public_key.clone());
            e.set_unprotected(KEEAGENT_SETTINGS_FIELD, settings.clone());
            e.add_attachment(attachment_name.clone(), Value::protected(pem.as_slice().to_vec()));
        });

        Ok(entry_id.uuid().to_string())
    }

    /// All SSH keys in the vault, wherever they are stored — including keys
    /// added by KeePassXC itself, since both tools use the same convention.
    pub fn list_ssh_keys(&self) -> Result<Vec<SshKeySummary>> {
        let recycle_bin_id = self.recycle_bin_id();
        let mut keys = Vec::new();

        for entry in self.db.iter_all_entries() {
            if Some(entry.parent().id()) == recycle_bin_id {
                continue;
            }
            // A key we can't parse shouldn't make the whole listing fail —
            // it's more useful to list the ones that do work.
            if let Some(Ok(key)) = read_ssh_key_from_entry(&entry) {
                keys.push(SshKeySummary::from(&key));
            }
        }

        keys.sort_by_key(|k| k.name.to_lowercase());
        Ok(keys)
    }

    /// Look up one SSH key by entry id, name, or fingerprint.
    pub fn get_ssh_key(&self, query: &str) -> Result<SshKey> {
        let recycle_bin_id = self.recycle_bin_id();
        let mut by_name = None;

        for entry in self.db.iter_all_entries() {
            if Some(entry.parent().id()) == recycle_bin_id {
                continue;
            }
            let Some(key) = read_ssh_key_from_entry(&entry) else {
                continue;
            };
            let key = key?;

            // An exact id or fingerprint match is unambiguous, so return at
            // once; a name match is a convenience and only wins if nothing
            // exact turns up.
            if key.id == query || key.fingerprint == query {
                return Ok(key);
            }
            if by_name.is_none() && key.name.eq_ignore_ascii_case(query) {
                by_name = Some(key);
            }
        }

        by_name.ok_or_else(|| PassError::EntryNotFound(query.to_string()))
    }

    /// Delete an SSH key, moving its entry to the Recycle Bin like any other
    /// deletion so it still propagates through a merge.
    pub fn delete_ssh_key(&mut self, query: &str) -> Result<()> {
        let key = self.get_ssh_key(query)?;
        let entry_id = parse_entry_id(&key.id)?;
        let recycle_bin_id = self.ensure_recycle_bin();

        let mut entry_mut = self
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| PassError::EntryNotFound(query.to_string()))?;
        entry_mut
            .track_changes()
            .move_to(recycle_bin_id)
            .map_err(|e| PassError::SaveError(e.to_string()))?;

        Ok(())
    }

    fn find_ssh_key_entry_by_fingerprint(&self, fingerprint: &str) -> Option<EntryId> {
        let recycle_bin_id = self.recycle_bin_id();
        self.db.iter_all_entries().find_map(|entry| {
            if Some(entry.parent().id()) == recycle_bin_id {
                return None;
            }
            match read_ssh_key_from_entry(&entry) {
                Some(Ok(key)) if key.fingerprint == fingerprint => Some(entry.id()),
                _ => None,
            }
        })
    }

    // ---------------------------------------------------------------------
    // Serverless sharing (see [`crate::share`])
    // ---------------------------------------------------------------------

    /// This vault's sharing identity, if one has been created.
    pub fn share_identity(&self) -> Result<Option<ShareIdentity>> {
        let Some(entry) = self.share_identity_entry() else {
            return Ok(None);
        };
        let Some(encoded) = entry.get(SHARE_SECRET_FIELD) else {
            return Ok(None);
        };

        let bytes = BASE64
            .decode(encoded.trim())
            .map_err(|_| PassError::Share("stored sharing key is not valid base64".to_string()))?;
        let label = entry.get_username().unwrap_or_default().to_string();

        ShareIdentity::from_secret_bytes(&label, &bytes).map(Some)
    }

    /// This vault's sharing identity, creating one on first use.
    ///
    /// The identity is per-vault rather than per-device on purpose: it is the
    /// name *other people* share with, and it should keep working when the
    /// vault moves to a new laptop.
    pub fn ensure_share_identity(&mut self, label: &str) -> Result<ShareIdentity> {
        if let Some(existing) = self.share_identity()? {
            return Ok(existing);
        }

        let identity = ShareIdentity::generate(label)?;
        let secret = BASE64.encode(identity.secret_key_bytes()?);
        let group_id = self.ensure_root_group(PASS_GROUP_NAME);

        let mut group = self
            .db
            .group_mut(group_id)
            .ok_or_else(|| PassError::SaveError("Pass group vanished".to_string()))?;
        let mut entry = group.add_entry();
        entry.edit(|e| {
            e.set_unprotected(fields::TITLE, SHARE_IDENTITY_ENTRY_TITLE);
            e.set_unprotected(fields::USERNAME, label.to_string());
            e.set_unprotected(fields::NOTES, identity.public_key_string());
            e.set_protected(SHARE_SECRET_FIELD, secret.clone());
        });

        Ok(identity)
    }

    /// Known sharing contacts: the people this vault can seal bundles for.
    pub fn share_contacts(&self) -> Vec<ShareContact> {
        self.share_identity_entry()
            .and_then(|e| e.get(SHARE_CONTACTS_FIELD).map(decode_share_contacts))
            .unwrap_or_default()
    }

    /// Remember a contact's public key under `label`, replacing any existing
    /// contact with the same label.
    pub fn add_share_contact(&mut self, label: &str, public_key: [u8; 32]) -> Result<()> {
        if label.trim().is_empty() {
            return Err(PassError::Share("a contact needs a label".to_string()));
        }
        if label.contains('\t') || label.contains('\n') {
            return Err(PassError::Share(
                "a contact label cannot contain tabs or newlines".to_string(),
            ));
        }

        let mut contacts = self.share_contacts();
        contacts.retain(|c| !c.label.eq_ignore_ascii_case(label));
        contacts.push(ShareContact {
            label: label.to_string(),
            public_key,
        });
        self.write_share_contacts(&contacts)
    }

    /// Forget a contact. Returns whether one was actually removed.
    pub fn remove_share_contact(&mut self, label: &str) -> Result<bool> {
        let mut contacts = self.share_contacts();
        let before = contacts.len();
        contacts.retain(|c| !c.label.eq_ignore_ascii_case(label));

        if contacts.len() == before {
            return Ok(false);
        }
        self.write_share_contacts(&contacts)?;
        Ok(true)
    }

    fn write_share_contacts(&mut self, contacts: &[ShareContact]) -> Result<()> {
        let entry_id = self
            .share_identity_entry()
            .map(|e| e.id())
            .ok_or_else(|| PassError::Share("no sharing identity yet — create one first".to_string()))?;

        let encoded = encode_share_contacts(contacts);
        let mut entry = self
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| PassError::Share("sharing identity entry vanished".to_string()))?;
        entry.track_changes().set_unprotected(SHARE_CONTACTS_FIELD, encoded);

        Ok(())
    }


    // ---------------------------------------------------------------------
    // Peer-to-peer sync (see [`crate::sync`])
    //
    // Three things live in the vault: the shared key that makes op payloads
    // opaque, one signing key per device, and — as the set of those entries
    // — the roster of devices allowed to write into this replica.
    //
    // Keeping the *private* device keys in the vault looks wrong at first
    // and is not: anyone holding the vault file and its master password
    // already has every password in it, so a per-device key hidden from
    // them would protect nothing. What the roster does protect against is
    // the case that actually exists — a machine on the same tailnet that
    // does *not* hold the vault, which can reach the sync port and is
    // refused because it cannot sign as any listed device.
    // ---------------------------------------------------------------------

    /// The key this vault's devices seal op payloads with, if sync has been
    /// set up.
    pub fn sync_key(&self) -> Result<Option<SyncKey>> {
        let Some(entry) = self.pass_entry(SYNC_ENTRY_TITLE) else {
            return Ok(None);
        };
        let Some(encoded) = entry.get(SYNC_KEY_FIELD) else {
            return Ok(None);
        };
        let bytes = BASE64
            .decode(encoded.trim())
            .map_err(|_| PassError::Sync("stored sync key is not valid base64".to_string()))?;
        SyncKey::from_bytes(&bytes).map(Some)
    }

    /// The sync key, creating one on first use. Does not save.
    pub fn ensure_sync_key(&mut self) -> Result<SyncKey> {
        if let Some(existing) = self.sync_key()? {
            return Ok(existing);
        }

        let key = SyncKey::generate()?;
        let encoded = BASE64.encode(key.to_bytes()?);
        let group_id = self.ensure_root_group(PASS_GROUP_NAME);

        let mut group = self
            .db
            .group_mut(group_id)
            .ok_or_else(|| PassError::SaveError("Pass group vanished".to_string()))?;
        let mut entry = group.add_entry();
        entry.edit(|e| {
            e.set_unprotected(fields::TITLE, SYNC_ENTRY_TITLE);
            e.set_unprotected(
                fields::NOTES,
                "Key shared by every device replicating this vault. Deleting it stops peer-to-peer sync.",
            );
            e.set_protected(SYNC_KEY_FIELD, encoded);
        });

        Ok(key)
    }

    /// Every device registered with this vault, ordered by label.
    pub fn sync_devices(&self) -> Vec<SyncDevice> {
        let Some(group_id) = self.root_group_id(PASS_GROUP_NAME) else {
            return Vec::new();
        };

        let mut devices: Vec<SyncDevice> = self
            .db
            .iter_all_entries()
            .filter(|e| e.parent().id() == group_id)
            .filter_map(|e| {
                let title = e.get_title()?;
                let label = title.strip_prefix(DEVICE_ENTRY_PREFIX)?.to_string();
                let public_key = crate::sync::crypto::parse_public_key(e.get(fields::NOTES)?).ok()?;
                Some(SyncDevice {
                    label,
                    fingerprint: e.get(DEVICE_FINGERPRINT_FIELD)?.trim().to_string(),
                    public_key,
                    epoch: e.get(DEVICE_EPOCH_FIELD).and_then(|v| v.trim().parse().ok()).unwrap_or(0),
                })
            })
            .collect();

        devices.sort_by(|a, b| a.label.cmp(&b.label));
        devices
    }

    /// This device's signing identity, looked up by the fingerprint the
    /// agent remembers locally.
    pub fn sync_device_identity(&self, fingerprint: &str) -> Result<Option<DeviceIdentity>> {
        let Some(entry) = self.device_entry(fingerprint) else {
            return Ok(None);
        };
        let Some(encoded) = entry.get(DEVICE_SECRET_FIELD) else {
            return Ok(None);
        };

        let bytes = BASE64
            .decode(encoded.trim())
            .map_err(|_| PassError::Sync("stored device key is not valid base64".to_string()))?;
        let label = entry
            .get_title()
            .and_then(|t| t.strip_prefix(DEVICE_ENTRY_PREFIX))
            .unwrap_or_default()
            .to_string();
        let epoch = entry
            .get(DEVICE_EPOCH_FIELD)
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);

        DeviceIdentity::from_secret_bytes(&label, &bytes, epoch).map(Some)
    }

    /// Register *this* device, signing key and all. Does not save.
    pub fn add_sync_device(&mut self, identity: &DeviceIdentity) -> Result<()> {
        let secret = BASE64.encode(identity.secret_key_bytes()?);
        self.write_device_entry(
            &identity.label,
            &identity.fingerprint(),
            identity.public_key(),
            identity.epoch(),
            Some(secret),
        )
    }

    /// Trust *another* device: accept ops it signs, from now on.
    ///
    /// This is the pairing step, and it is deliberately explicit. Trusting
    /// on first contact would mean any machine that can reach the sync port
    /// gets to write into the vault, and "it showed up, so it must be mine"
    /// is not a security decision a password manager should make on the
    /// user's behalf.
    ///
    /// Returns the fingerprint now trusted. Does not save.
    pub fn trust_sync_device(&mut self, label: &str, public_key: [u8; 32]) -> Result<String> {
        if label.trim().is_empty() {
            return Err(PassError::Sync("a device needs a label".to_string()));
        }

        let fingerprint = crate::sync::crypto::fingerprint_of_key(&public_key);
        self.write_device_entry(label, &fingerprint, public_key, 0, None)?;
        Ok(fingerprint)
    }

    /// Write or refresh one roster entry.
    ///
    /// An existing entry is left alone rather than rewritten: re-trusting a
    /// device already on the roster must not clobber the signing key of the
    /// device this vault belongs to, and must not reset an epoch.
    fn write_device_entry(
        &mut self,
        label: &str,
        fingerprint: &str,
        public_key: [u8; 32],
        epoch: u64,
        secret: Option<String>,
    ) -> Result<()> {
        if self.device_entry(fingerprint).is_some() {
            return Ok(());
        }

        let group_id = self.ensure_root_group(PASS_GROUP_NAME);
        let mut group = self
            .db
            .group_mut(group_id)
            .ok_or_else(|| PassError::SaveError("Pass group vanished".to_string()))?;

        let mut entry = group.add_entry();
        entry.edit(|e| {
            e.set_unprotected(fields::TITLE, format!("{DEVICE_ENTRY_PREFIX}{label}"));
            e.set_unprotected(
                fields::NOTES,
                format!("{}{}", crate::sync::DEVICE_KEY_PREFIX, BASE64.encode(public_key)),
            );
            e.set_unprotected(DEVICE_FINGERPRINT_FIELD, fingerprint.to_string());
            e.set_unprotected(DEVICE_EPOCH_FIELD, epoch.to_string());
            if let Some(secret) = secret {
                e.set_protected(DEVICE_SECRET_FIELD, secret);
            }
        });

        Ok(())
    }

    /// Record a device's new epoch, after its op-log was found rewound.
    /// Does not save.
    pub fn set_sync_device_epoch(&mut self, fingerprint: &str, epoch: u64) -> Result<()> {
        let entry_id = self
            .device_entry(fingerprint)
            .map(|e| e.id())
            .ok_or_else(|| PassError::Sync(format!("device {fingerprint} is not registered")))?;

        let mut entry = self
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| PassError::Sync("device entry vanished".to_string()))?;
        entry
            .track_changes()
            .set_unprotected(DEVICE_EPOCH_FIELD, epoch.to_string());

        Ok(())
    }

    /// Forget a device: its ops stop being accepted from the next round.
    ///
    /// This is not revocation of anything it already read — see
    /// `docs/SYNC_STRATEGY.md` on why that cannot exist without a server —
    /// only of its ability to write into this replica. Does not save.
    pub fn remove_sync_device(&mut self, fingerprint: &str) -> Result<bool> {
        let Some(entry_id) = self.device_entry(fingerprint).map(|e| e.id()) else {
            return Ok(false);
        };

        let recycle_bin_id = self.ensure_recycle_bin();
        let mut entry = self
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| PassError::Sync("device entry vanished".to_string()))?;
        entry
            .track_changes()
            .move_to(recycle_bin_id)
            .map_err(|e| PassError::SaveError(e.to_string()))?;

        Ok(true)
    }

    /// Ids of *password* entries sitting in the Recycle Bin — the vault's
    /// record of what has been deleted, and so what the sync layer must
    /// publish as a tombstone rather than as an entry that simply never
    /// existed here.
    ///
    /// Bookkeeping entries are filtered out for the same reason
    /// [`Vault::list_entries`] hides them, but the test has to be different:
    /// once deleted they are in the Recycle Bin, not in the group they came
    /// from, so what identifies them is the fields they carry. Without this,
    /// removing a device with [`Vault::remove_sync_device`] would broadcast
    /// a tombstone for the roster entry to every other device.
    pub fn recycled_entry_ids(&self) -> Vec<String> {
        let Some(bin) = self.recycle_bin_id() else {
            return Vec::new();
        };
        self.db
            .iter_all_entries()
            .filter(|e| e.parent().id() == bin && !is_bookkeeping_entry(e))
            .map(|e| e.id().uuid().to_string())
            .collect()
    }

    /// An entry by id wherever it lives, Recycle Bin included — the sync
    /// layer needs to resurrect a deleted entry when a peer's later edit
    /// wins, which [`Vault::get_entry`] deliberately refuses to see.
    pub fn get_entry_including_deleted(&self, id: &str) -> Result<PasswordEntry> {
        let entry_id = parse_entry_id(id)?;
        self.db
            .entry(entry_id)
            .map(|e| to_password_entry(&e))
            .ok_or_else(|| PassError::EntryNotFound(id.to_string()))
    }

    /// Move an entry back out of the Recycle Bin, for when a peer's edit
    /// beats a local delete. Does not save.
    pub fn restore_entry(&mut self, id: &str) -> Result<()> {
        let entry_id = parse_entry_id(id)?;
        let root_id = self.db.root().id();
        let mut entry = self
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| PassError::EntryNotFound(id.to_string()))?;
        entry
            .track_changes()
            .move_to(root_id)
            .map_err(|e| PassError::SaveError(e.to_string()))?;

        Ok(())
    }

    fn device_entry(&self, fingerprint: &str) -> Option<EntryRef<'_>> {
        let group_id = self.root_group_id(PASS_GROUP_NAME)?;
        self.db.iter_all_entries().find(|e| {
            e.parent().id() == group_id
                && e.get(DEVICE_FINGERPRINT_FIELD).is_some_and(|f| f.trim() == fingerprint)
        })
    }

    /// An entry in the `Pass` bookkeeping group, by title.
    ///
    /// Iterates the database rather than the group's own `entries()`: the
    /// latter borrows from a temporary `GroupRef` that cannot outlive this
    /// function.
    fn pass_entry(&self, title: &str) -> Option<EntryRef<'_>> {
        let group_id = self.root_group_id(PASS_GROUP_NAME)?;
        self.db
            .iter_all_entries()
            .find(|e| e.parent().id() == group_id && e.get_title() == Some(title))
    }

    fn share_identity_entry(&self) -> Option<EntryRef<'_>> {
        self.pass_entry(SHARE_IDENTITY_ENTRY_TITLE)
    }
}

/// One device registered to replicate this vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncDevice {
    pub label: String,
    pub fingerprint: String,
    pub public_key: [u8; 32],
    pub epoch: u64,
}

impl SyncDevice {
    pub fn public_key_string(&self) -> String {
        format!("{}{}", crate::sync::DEVICE_KEY_PREFIX, BASE64.encode(self.public_key))
    }
}

/// One known sharing contact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareContact {
    pub label: String,
    pub public_key: [u8; 32],
}

impl ShareContact {
    pub fn public_key_string(&self) -> String {
        format!("pass-share-pk1:{}", BASE64.encode(self.public_key))
    }
}

fn encode_share_contacts(contacts: &[ShareContact]) -> String {
    contacts
        .iter()
        .map(|c| format!("{}\t{}", c.label, BASE64.encode(c.public_key)))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Parse the contacts field, skipping any line that doesn't decode — a
/// hand-edited field in KeePassXC shouldn't be able to break the listing.
fn decode_share_contacts(raw: &str) -> Vec<ShareContact> {
    raw.lines()
        .filter_map(|line| {
            let (label, encoded) = line.split_once('\t')?;
            let key: [u8; 32] = BASE64.decode(encoded.trim()).ok()?.try_into().ok()?;
            Some(ShareContact {
                label: label.trim().to_string(),
                public_key: key,
            })
        })
        .collect()
}

/// Read an SSH key out of a KDBX entry, if that entry is one.
///
/// Returns `None` for an ordinary entry, and `Some(Err(..))` for one that
/// claims to hold a key but whose key can't be read — the caller decides
/// whether that's fatal.
fn read_ssh_key_from_entry(entry: &EntryRef) -> Option<Result<SshKey>> {
    let settings = entry.get(KEEAGENT_SETTINGS_FIELD)?;
    if !sshkey::keeagent_allows_ssh_key(settings) {
        return None;
    }

    let attachment_name = sshkey::keeagent_attachment_name(settings)?;
    let Some(attachment) = entry.attachment_by_name(&attachment_name) else {
        return Some(Err(PassError::SshKey(format!(
            "entry claims an SSH key in attachment '{attachment_name}', but no such attachment exists"
        ))));
    };

    let pem = match std::str::from_utf8(attachment.data.get()) {
        Ok(pem) => pem,
        Err(_) => {
            return Some(Err(PassError::SshKey(format!(
                "attachment '{attachment_name}' is not a text SSH key"
            ))))
        }
    };

    Some(SshKey::from_stored(
        entry.id().uuid().to_string(),
        entry.get_title().unwrap_or_default().to_string(),
        attachment_name,
        pem,
    ))
}

/// Set Argon2id KDF parameters explicit enough to be secure (64 MiB / 10
/// iterations / 4 lanes) rather than trusting the crate's own default,
/// which is deliberately cheap for fast test runs (1 MiB / 50 iterations)
/// and not something a real vault should ship with.
fn strengthen_kdf(db: &mut Database) {
    let version = match db.config.kdf_config {
        KdfConfig::Argon2 { version, .. } | KdfConfig::Argon2id { version, .. } => version,
        _ => return,
    };

    db.config.kdf_config = KdfConfig::Argon2id {
        iterations: 10,
        memory: 64 * 1024 * 1024, // bytes
        parallelism: 4,
        version,
    };
}

/// Whether an entry is one of `pass`'s own records rather than a password.
///
/// Identified by the fields it carries, so it still works for an entry that
/// has been moved out of the group it was created in — which is exactly what
/// deleting one does.
fn is_bookkeeping_entry(entry: &EntryRef) -> bool {
    [
        SYNC_KEY_FIELD,
        DEVICE_FINGERPRINT_FIELD,
        SHARE_SECRET_FIELD,
        KEEAGENT_SETTINGS_FIELD,
    ]
    .iter()
    .any(|field| entry.get(field).is_some())
}

fn parse_entry_id(id: &str) -> Result<EntryId> {
    Uuid::parse_str(id)
        .map(EntryId::from_uuid)
        .map_err(|_| PassError::EntryNotFound(id.to_string()))
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    naive.and_utc()
}

fn to_password_entry(entry: &EntryRef) -> PasswordEntry {
    let id = entry.id().uuid().to_string();
    let website = entry.get_title().unwrap_or_default().to_string();
    let url = entry.get_url().unwrap_or_default().to_string();
    let username = entry.get_username().unwrap_or_default().to_string();
    let password = entry.get_password().unwrap_or_default().to_string();
    let created_at = entry.times.creation.map(to_utc).unwrap_or_else(Utc::now);
    let updated_at = entry.times.last_modification.map(to_utc).unwrap_or(created_at);
    let totp = entry.get_raw_otp_value().and_then(|uri| totp::parse_otpauth_uri(uri).ok());
    let notes = entry.get(fields::NOTES).unwrap_or_default().to_string();
    let additional_urls = entry
        .get(ADDITIONAL_URLS_FIELD)
        .map(decode_additional_urls)
        .unwrap_or_default();
    let history = read_password_history(entry, &password, created_at);

    PasswordEntry::from_parts(
        id,
        website,
        url,
        username,
        password,
        created_at,
        updated_at,
        totp,
        notes,
        additional_urls,
        history,
    )
}

/// Previous passwords from the KDBX4 history, newest first, deduplicated
/// so an edit that didn't touch the password (notes, username, ...) — which
/// still archives a snapshot via `track_changes` — doesn't show up as a
/// fake password change.
fn read_password_history(
    entry: &EntryRef,
    current_password: &str,
    fallback_time: DateTime<Utc>,
) -> Vec<PasswordHistoryEntry> {
    let mut history: Vec<PasswordHistoryEntry> = entry
        .history
        .as_ref()
        .map(|h| {
            h.get_entries()
                .iter()
                .filter_map(|old| {
                    let password = old.get_password()?.to_string();
                    let changed_at = old.times.last_modification.map(to_utc).unwrap_or(fallback_time);
                    Some(PasswordHistoryEntry { password, changed_at })
                })
                .collect()
        })
        .unwrap_or_default();

    history.dedup_by(|a, b| a.password == b.password);
    if history.first().is_some_and(|h| h.password == current_password) {
        history.remove(0);
    }
    history
}

/// A wrong master password surfaces as `DatabaseOpenError::Key(DatabaseKeyError::IncorrectKey)`.
fn map_open_error(e: DatabaseOpenError) -> PassError {
    if matches!(e, DatabaseOpenError::Key(DatabaseKeyError::IncorrectKey)) {
        PassError::InvalidPassword
    } else {
        PassError::VaultCorrupted(e.to_string())
    }
}

/// Summary of a merge operation, useful for logging/notifying the user.
/// Counts only entry-level changes (group/icon changes aren't
/// user-visible in `pass`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MergeSummary {
    /// Entries that existed only on the other side and were added here.
    pub created: usize,
    /// Entries that were updated with a newer version from the other side.
    pub updated: usize,
    /// Entries deleted (or moved to the Recycle Bin) as a result of the merge.
    pub deleted: usize,
    /// Entries that were already identical or already newer on this side.
    pub unchanged: usize,
}

impl MergeSummary {
    /// Whether the merge actually changed this vault.
    pub fn changed(&self) -> bool {
        self.created > 0 || self.updated > 0 || self.deleted > 0
    }

    fn from_log(log: &MergeLog, entries_after: usize) -> Self {
        use keepass::db::merge::{MergeEventTarget, MergeEventType};

        let mut created = 0;
        let mut updated = 0;
        let mut deleted = 0;

        for event in &log.events {
            if !matches!(event.target, MergeEventTarget::Entry(_)) {
                continue;
            }
            match event.event_type {
                MergeEventType::Created => created += 1,
                MergeEventType::Updated => updated += 1,
                MergeEventType::Deleted | MergeEventType::LocationUpdated => deleted += 1,
                _ => {}
            }
        }

        let unchanged = entries_after.saturating_sub(created + updated);
        Self {
            created,
            updated,
            deleted,
            unchanged,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A vault path inside a private temporary directory that lives exactly
    /// as long as the test using it.
    ///
    /// The obvious shortcut — take a `NamedTempFile`'s path and drop it — is
    /// unsound here: dropping deletes the file and frees the name, so two of
    /// the tests below running in parallel can be handed the same path and
    /// clobber each other's vault. Owning a directory per test makes the name
    /// unique by construction and still cleans up on drop.
    struct TempVault {
        _dir: tempfile::TempDir,
        path: PathBuf,
    }

    impl AsRef<Path> for TempVault {
        fn as_ref(&self) -> &Path {
            &self.path
        }
    }

    fn temp_vault_path() -> TempVault {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        TempVault { _dir: dir, path }
    }

    #[test]
    fn test_vault_init_and_unlock() {
        let path = temp_vault_path();
        let master_password = "super_secret_password_123";

        let vault = Vault::init(&path, master_password).unwrap();
        assert_eq!(vault.len(), 0);

        let vault = Vault::unlock(&path, master_password).unwrap();
        assert_eq!(vault.len(), 0);
    }

    #[test]
    fn test_wrong_password_fails() {
        let path = temp_vault_path();
        Vault::init(&path, "correct_password").unwrap();

        let result = Vault::unlock(&path, "wrong_password");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PassError::InvalidPassword));
    }

    #[test]
    fn test_add_and_retrieve_entry() {
        let path = temp_vault_path();
        let master_password = "test_password";
        let mut vault = Vault::init(&path, master_password).unwrap();

        let entry = PasswordEntry::new(
            "GitHub".to_string(),
            "https://github.com/login".to_string(),
            "user@example.com".to_string(),
            "github_password_123".to_string(),
        );
        let id = vault.add_entry(entry).unwrap();
        vault.save(master_password).unwrap();

        let vault = Vault::unlock(&path, master_password).unwrap();
        assert_eq!(vault.len(), 1);

        let retrieved = vault.get_entry(&id).unwrap();
        assert_eq!(retrieved.website, "GitHub");
        assert_eq!(retrieved.username, "user@example.com");
        assert_eq!(retrieved.password(), "github_password_123");
    }

    #[test]
    fn test_delete_entry() {
        let path = temp_vault_path();
        let master_password = "test_password";
        let mut vault = Vault::init(&path, master_password).unwrap();

        let entry = PasswordEntry::new(
            "Test".to_string(),
            "https://test.com".to_string(),
            "user".to_string(),
            "pass".to_string(),
        );
        let id = vault.add_entry(entry).unwrap();
        assert_eq!(vault.len(), 1);

        vault.delete_entry(&id).unwrap();
        assert_eq!(vault.len(), 0);
    }

    #[test]
    fn test_deleted_entry_moves_to_recycle_bin_not_removed() {
        let path = temp_vault_path();
        let master_password = "test_password";
        let mut vault = Vault::init(&path, master_password).unwrap();

        let entry = PasswordEntry::new(
            "Test".to_string(),
            "https://test.com".to_string(),
            "user".to_string(),
            "pass".to_string(),
        );
        let id = vault.add_entry(entry).unwrap();
        vault.delete_entry(&id).unwrap();

        // Gone from the visible view...
        assert_eq!(vault.len(), 0);
        assert!(vault.get_entry(&id).is_err());

        // ...but still present in the database, inside the Recycle Bin.
        assert_eq!(vault.db.num_entries(), 1);
        let recycle_bin = vault.db.recycle_bin().expect("recycle bin should exist");
        assert_eq!(recycle_bin.name, RECYCLE_BIN_GROUP_NAME);
    }

    #[test]
    fn test_merge_from_file_reconciles_two_devices() {
        let device_a_path = temp_vault_path();
        let device_b_path = temp_vault_path();
        let master_password = "shared_master_password";

        // Both devices start from the same vault contents.
        let mut vault_a = Vault::init(&device_a_path, master_password).unwrap();
        let entry = PasswordEntry::new(
            "GitHub".to_string(),
            "https://github.com".to_string(),
            "user".to_string(),
            "old_password".to_string(),
        );
        let shared_id = vault_a.add_entry(entry).unwrap();
        vault_a.save(master_password).unwrap();

        // Device B gets a copy (e.g. via Nextcloud) and adds its own entry.
        std::fs::copy(&device_a_path, &device_b_path).unwrap();
        let mut vault_b = Vault::unlock(&device_b_path, master_password).unwrap();
        let b_only_entry = PasswordEntry::new(
            "GitLab".to_string(),
            "https://gitlab.com".to_string(),
            "user".to_string(),
            "gitlab_password".to_string(),
        );
        vault_b.add_entry(b_only_entry).unwrap();
        vault_b.save(master_password).unwrap();

        // Meanwhile device A updates the shared entry, ensuring its
        // modification time is strictly newer than device B's copy (KDBX
        // times only have second resolution).
        std::thread::sleep(std::time::Duration::from_secs(1));
        vault_a
            .update_entry(&shared_id, None, None, None, Some("new_password".to_string()), None, None)
            .unwrap();
        vault_a.save(master_password).unwrap();

        // Device A pulls device B's copy and merges.
        let summary = vault_a.merge_from_file(&device_b_path, master_password).unwrap();
        vault_a.save(master_password).unwrap();

        assert_eq!(summary.created, 1); // GitLab entry from device B
        assert_eq!(vault_a.len(), 2);
        assert_eq!(vault_a.get_entry(&shared_id).unwrap().password(), "new_password");
    }

    #[test]
    fn test_notes_and_additional_urls_roundtrip() {
        let path = temp_vault_path();
        let master_password = "test_password";
        let mut vault = Vault::init(&path, master_password).unwrap();

        let mut entry = PasswordEntry::new(
            "Apple".to_string(),
            "https://appleid.apple.com".to_string(),
            "user@example.com".to_string(),
            "pass".to_string(),
        );
        entry.notes = "Recovery key: XXXX-XXXX".to_string();
        entry.additional_urls = vec!["https://icloud.com".to_string(), "https://account.apple.com".to_string()];
        let id = vault.add_entry(entry).unwrap();
        vault.save(master_password).unwrap();

        let vault = Vault::unlock(&path, master_password).unwrap();
        let retrieved = vault.get_entry(&id).unwrap();
        assert_eq!(retrieved.notes, "Recovery key: XXXX-XXXX");
        assert_eq!(
            retrieved.additional_urls,
            vec!["https://icloud.com".to_string(), "https://account.apple.com".to_string()]
        );
        assert_eq!(
            retrieved.all_urls().collect::<Vec<_>>(),
            vec!["https://appleid.apple.com", "https://icloud.com", "https://account.apple.com"]
        );
    }

    #[test]
    fn test_update_notes_and_additional_urls() {
        let path = temp_vault_path();
        let master_password = "test_password";
        let mut vault = Vault::init(&path, master_password).unwrap();

        let entry = PasswordEntry::new(
            "Apple".to_string(),
            "https://appleid.apple.com".to_string(),
            "user@example.com".to_string(),
            "pass".to_string(),
        );
        let id = vault.add_entry(entry).unwrap();

        vault
            .update_entry(
                &id,
                None,
                None,
                None,
                None,
                Some("updated notes".to_string()),
                Some(vec!["https://icloud.com".to_string()]),
            )
            .unwrap();

        let updated = vault.get_entry(&id).unwrap();
        assert_eq!(updated.notes, "updated notes");
        assert_eq!(updated.additional_urls, vec!["https://icloud.com".to_string()]);
    }

    #[test]
    fn test_password_history_tracks_previous_passwords() {
        let path = temp_vault_path();
        let master_password = "test_password";
        let mut vault = Vault::init(&path, master_password).unwrap();

        let entry = PasswordEntry::new(
            "GitHub".to_string(),
            "https://github.com".to_string(),
            "user".to_string(),
            "first_password".to_string(),
        );
        let id = vault.add_entry(entry).unwrap();
        assert!(vault.get_entry(&id).unwrap().history.is_empty());

        vault
            .update_entry(&id, None, None, None, Some("second_password".to_string()), None, None)
            .unwrap();
        vault
            .update_entry(&id, None, None, None, Some("third_password".to_string()), None, None)
            .unwrap();

        let current = vault.get_entry(&id).unwrap();
        assert_eq!(current.password(), "third_password");
        let history_passwords: Vec<&str> = current.history.iter().map(|h| h.password.as_str()).collect();
        assert_eq!(history_passwords, vec!["second_password", "first_password"]);
    }

    #[test]
    fn test_ssh_key_survives_a_save_and_reload() {
        let path = temp_vault_path();
        let master_password = "test_password";
        let mut vault = Vault::init(&path, master_password).unwrap();

        let key = SshKey::generate("work laptop", "antonio@laptop").unwrap();
        let fingerprint = key.fingerprint.clone();
        let public_key = key.public_key.clone();
        let id = vault.add_ssh_key(&key).unwrap();
        vault.save(master_password).unwrap();

        let vault = Vault::unlock(&path, master_password).unwrap();
        let loaded = vault.get_ssh_key(&id).unwrap();

        assert_eq!(loaded.fingerprint, fingerprint);
        assert_eq!(loaded.public_key, public_key);
        assert_eq!(loaded.name, "work laptop");
        // Still a usable signing key after the KDBX round-trip.
        assert!(loaded.sign(b"payload", 0).is_ok());
    }

    #[test]
    fn test_ssh_keys_do_not_show_up_as_password_entries() {
        let path = temp_vault_path();
        let mut vault = Vault::init(&path, "pw").unwrap();

        vault
            .add_entry(PasswordEntry::new(
                "GitHub".to_string(),
                "https://github.com".to_string(),
                "user".to_string(),
                "pw".to_string(),
            ))
            .unwrap();
        vault.add_ssh_key(&SshKey::generate("key", "c").unwrap()).unwrap();

        let entries = vault.list_entries().unwrap();
        assert_eq!(entries.len(), 1, "the SSH key leaked into the password listing");
        assert_eq!(entries[0].website, "GitHub");
        assert_eq!(vault.len(), 1);
        assert_eq!(vault.list_ssh_keys().unwrap().len(), 1);
    }

    #[test]
    fn test_ssh_key_lookup_by_name_and_fingerprint() {
        let path = temp_vault_path();
        let mut vault = Vault::init(&path, "pw").unwrap();

        let key = SshKey::generate("Deploy Key", "ci@example.com").unwrap();
        let fingerprint = key.fingerprint.clone();
        vault.add_ssh_key(&key).unwrap();

        assert!(vault.get_ssh_key("Deploy Key").is_ok());
        assert!(vault.get_ssh_key("deploy key").is_ok(), "name lookup should ignore case");
        assert!(vault.get_ssh_key(&fingerprint).is_ok());
        assert!(vault.get_ssh_key("nonexistent").is_err());
    }

    #[test]
    fn test_duplicate_ssh_key_is_rejected() {
        let path = temp_vault_path();
        let mut vault = Vault::init(&path, "pw").unwrap();

        let key = SshKey::generate("k", "c").unwrap();
        vault.add_ssh_key(&key).unwrap();

        let err = vault.add_ssh_key(&key).unwrap_err();
        assert!(matches!(err, PassError::SshKey(_)), "unexpected error: {err}");
    }

    #[test]
    fn test_deleted_ssh_key_disappears_from_the_listing() {
        let path = temp_vault_path();
        let mut vault = Vault::init(&path, "pw").unwrap();

        let key = SshKey::generate("k", "c").unwrap();
        let id = vault.add_ssh_key(&key).unwrap();
        assert_eq!(vault.list_ssh_keys().unwrap().len(), 1);

        vault.delete_ssh_key(&id).unwrap();
        assert!(vault.list_ssh_keys().unwrap().is_empty());
        assert!(vault.get_ssh_key(&id).is_err());
    }

    /// The interoperability claim: an SSH key written by `pass` is described
    /// by a `KeeAgent.settings` field pointing at a real attachment, which is
    /// exactly what KeePassXC's SSH Agent tab looks for.
    #[test]
    fn test_ssh_key_is_stored_in_the_keepassxc_convention() {
        let path = temp_vault_path();
        let mut vault = Vault::init(&path, "pw").unwrap();
        vault.add_ssh_key(&SshKey::generate("k", "c").unwrap()).unwrap();
        vault.save("pw").unwrap();

        let vault = Vault::unlock(&path, "pw").unwrap();
        let entry = vault
            .db
            .iter_all_entries()
            .find(|e| e.get(KEEAGENT_SETTINGS_FIELD).is_some())
            .expect("no entry carries KeeAgent.settings");

        let settings = entry.get(KEEAGENT_SETTINGS_FIELD).unwrap();
        assert!(sshkey::keeagent_allows_ssh_key(settings));

        let attachment_name = sshkey::keeagent_attachment_name(settings).unwrap();
        assert_eq!(attachment_name, "id_ed25519");

        let attachment = entry
            .attachment_by_name(&attachment_name)
            .expect("KeeAgent.settings points at a missing attachment");
        assert!(attachment.data.is_protected(), "private key stored unprotected");
        assert!(std::str::from_utf8(attachment.data.get())
            .unwrap()
            .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
    }

    #[test]
    fn test_ssh_keys_merge_across_devices() {
        let device_a = temp_vault_path();
        let device_b = temp_vault_path();
        let password = "shared";

        let mut vault_a = Vault::init(&device_a, password).unwrap();
        vault_a.add_ssh_key(&SshKey::generate("laptop", "a@a").unwrap()).unwrap();
        vault_a.save(password).unwrap();

        std::fs::copy(&device_a, &device_b).unwrap();
        let mut vault_b = Vault::unlock(&device_b, password).unwrap();
        vault_b.add_ssh_key(&SshKey::generate("desktop", "b@b").unwrap()).unwrap();
        vault_b.save(password).unwrap();

        vault_a.merge_from_file(&device_b, password).unwrap();

        let names: Vec<String> = vault_a.list_ssh_keys().unwrap().into_iter().map(|k| k.name).collect();
        assert_eq!(names, vec!["desktop".to_string(), "laptop".to_string()]);
    }

    /// Regression test for the gap `merge_attachments` fills: before it, an
    /// entry brought over by a merge referenced attachment ids that only
    /// existed in the other database, and reading its key panicked.
    #[test]
    fn test_merged_ssh_key_is_still_usable() {
        let device_a = temp_vault_path();
        let device_b = temp_vault_path();
        let password = "shared";

        let mut vault_a = Vault::init(&device_a, password).unwrap();
        vault_a.save(password).unwrap();

        std::fs::copy(&device_a, &device_b).unwrap();
        let mut vault_b = Vault::unlock(&device_b, password).unwrap();
        let key = SshKey::generate("desktop", "b@b").unwrap();
        let fingerprint = key.fingerprint.clone();
        vault_b.add_ssh_key(&key).unwrap();
        vault_b.save(password).unwrap();

        vault_a.merge_from_file(&device_b, password).unwrap();
        vault_a.save(password).unwrap();

        // Readable, and still the same key — not just present in the listing.
        let vault_a = Vault::unlock(&device_a, password).unwrap();
        let merged = vault_a.get_ssh_key("desktop").unwrap();
        assert_eq!(merged.fingerprint, fingerprint);
        assert!(merged.sign(b"payload", 0).is_ok());
    }

    /// Both sides' keys must survive a merge *and still sign* — a key that
    /// merges into the listing but whose attachment was lost is worse than
    /// one that fails loudly.
    #[test]
    fn test_merge_keeps_both_sides_keys_usable() {
        let device_a = temp_vault_path();
        let device_b = temp_vault_path();
        let password = "shared";

        let mut vault_a = Vault::init(&device_a, password).unwrap();
        let a_key = SshKey::generate("laptop", "a@a").unwrap();
        vault_a.add_ssh_key(&a_key).unwrap();
        vault_a.save(password).unwrap();

        std::fs::copy(&device_a, &device_b).unwrap();
        let mut vault_b = Vault::unlock(&device_b, password).unwrap();
        let b_key = SshKey::generate("desktop", "b@b").unwrap();
        vault_b.add_ssh_key(&b_key).unwrap();
        vault_b.save(password).unwrap();

        vault_a.merge_from_file(&device_b, password).unwrap();

        for (name, expected) in [("laptop", &a_key.fingerprint), ("desktop", &b_key.fingerprint)] {
            let key = vault_a.get_ssh_key(name).unwrap();
            assert_eq!(&key.fingerprint, expected, "{name} came back as the wrong key");
            assert!(key.sign(b"payload", 0).is_ok(), "{name} cannot sign after the merge");
        }
    }

    /// Merging the same vault repeatedly must be a no-op. This is the case
    /// that first exposed `add_attachment` handing back the very id it was
    /// replacing: the second merge re-attached over a live binding.
    #[test]
    fn test_repeated_merges_do_not_corrupt_attachments() {
        let device_a = temp_vault_path();
        let device_b = temp_vault_path();
        let password = "shared";

        let mut vault_a = Vault::init(&device_a, password).unwrap();
        vault_a.save(password).unwrap();

        std::fs::copy(&device_a, &device_b).unwrap();
        let mut vault_b = Vault::unlock(&device_b, password).unwrap();
        let key = SshKey::generate("desktop", "b@b").unwrap();
        vault_b.add_ssh_key(&key).unwrap();
        vault_b.save(password).unwrap();

        for round in 1..=3 {
            vault_a.merge_from_file(&device_b, password).unwrap();
            let keys = vault_a.list_ssh_keys().unwrap();
            assert_eq!(keys.len(), 1, "merge round {round} changed the key count");
            assert_eq!(
                vault_a.get_ssh_key("desktop").unwrap().fingerprint,
                key.fingerprint,
                "merge round {round} lost the key"
            );
        }
    }

    #[test]
    fn test_share_identity_is_created_once_and_persists() {
        let path = temp_vault_path();
        let mut vault = Vault::init(&path, "pw").unwrap();

        assert!(vault.share_identity().unwrap().is_none());

        let created = vault.ensure_share_identity("antonio").unwrap();
        let again = vault.ensure_share_identity("someone else").unwrap();
        assert_eq!(again.public_key(), created.public_key(), "a second identity was created");

        vault.save("pw").unwrap();
        let vault = Vault::unlock(&path, "pw").unwrap();
        let loaded = vault.share_identity().unwrap().unwrap();
        assert_eq!(loaded.public_key(), created.public_key());
        assert_eq!(loaded.label, "antonio");
    }

    #[test]
    fn test_share_identity_entry_is_hidden_from_the_password_listing() {
        let path = temp_vault_path();
        let mut vault = Vault::init(&path, "pw").unwrap();
        vault.ensure_share_identity("me").unwrap();

        assert!(vault.list_entries().unwrap().is_empty());
        assert_eq!(vault.len(), 0);
    }

    #[test]
    fn test_share_contacts_roundtrip() {
        let path = temp_vault_path();
        let mut vault = Vault::init(&path, "pw").unwrap();
        vault.ensure_share_identity("me").unwrap();

        let marta = crate::share::ShareIdentity::generate("marta").unwrap();
        vault.add_share_contact("Marta", marta.public_key()).unwrap();
        vault.save("pw").unwrap();

        let mut vault = Vault::unlock(&path, "pw").unwrap();
        let contacts = vault.share_contacts();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].label, "Marta");
        assert_eq!(contacts[0].public_key, marta.public_key());

        // Re-adding under the same label replaces rather than duplicates.
        let new_key = crate::share::ShareIdentity::generate("marta2").unwrap();
        vault.add_share_contact("marta", new_key.public_key()).unwrap();
        assert_eq!(vault.share_contacts().len(), 1);
        assert_eq!(vault.share_contacts()[0].public_key, new_key.public_key());

        assert!(vault.remove_share_contact("MARTA").unwrap());
        assert!(vault.share_contacts().is_empty());
        assert!(!vault.remove_share_contact("nobody").unwrap());
    }

    #[test]
    fn test_share_contact_labels_cannot_break_the_encoding() {
        let path = temp_vault_path();
        let mut vault = Vault::init(&path, "pw").unwrap();
        vault.ensure_share_identity("me").unwrap();
        let key = crate::share::ShareIdentity::generate("x").unwrap().public_key();

        assert!(vault.add_share_contact("has\ttab", key).is_err());
        assert!(vault.add_share_contact("has\nnewline", key).is_err());
        assert!(vault.add_share_contact("   ", key).is_err());
    }

    #[test]
    fn test_password_history_ignores_non_password_edits() {
        let path = temp_vault_path();
        let master_password = "test_password";
        let mut vault = Vault::init(&path, master_password).unwrap();

        let entry = PasswordEntry::new(
            "GitHub".to_string(),
            "https://github.com".to_string(),
            "user".to_string(),
            "only_password".to_string(),
        );
        let id = vault.add_entry(entry).unwrap();

        // A notes-only edit still archives a snapshot via track_changes,
        // but it shouldn't look like a password change in the history.
        vault
            .update_entry(&id, None, None, None, None, Some("a note".to_string()), None)
            .unwrap();

        let current = vault.get_entry(&id).unwrap();
        assert_eq!(current.password(), "only_password");
        assert!(current.history.is_empty(), "notes-only edit should not create fake password history");
    }

    // -- peer-to-peer sync storage -------------------------------------

    #[test]
    fn the_sync_key_is_created_once_and_then_reused() {
        let path = temp_vault_path();
        let mut vault = Vault::init(&path, "pw").unwrap();

        assert!(vault.sync_key().unwrap().is_none());
        let first = vault.ensure_sync_key().unwrap().to_bytes().unwrap();
        let second = vault.ensure_sync_key().unwrap().to_bytes().unwrap();
        assert_eq!(first, second, "a second call minted a new key and orphaned every existing op");
    }

    #[test]
    fn the_sync_key_survives_a_save_and_reopen() {
        let path = temp_vault_path();
        let expected = {
            let mut vault = Vault::init(&path, "pw").unwrap();
            let key = vault.ensure_sync_key().unwrap().to_bytes().unwrap();
            vault.save("pw").unwrap();
            key
        };

        let vault = Vault::unlock(&path, "pw").unwrap();
        assert_eq!(vault.sync_key().unwrap().unwrap().to_bytes().unwrap(), expected);
    }

    #[test]
    fn a_registered_device_can_be_read_back_and_signs_the_same_way() {
        let path = temp_vault_path();
        let identity = DeviceIdentity::generate("laptop").unwrap();
        {
            let mut vault = Vault::init(&path, "pw").unwrap();
            vault.add_sync_device(&identity).unwrap();
            vault.save("pw").unwrap();
        }

        let vault = Vault::unlock(&path, "pw").unwrap();
        let restored = vault.sync_device_identity(&identity.fingerprint()).unwrap().unwrap();

        assert_eq!(restored.label, "laptop");
        assert_eq!(restored.public_key(), identity.public_key());
        assert_eq!(restored.device_id(), identity.device_id());
    }

    #[test]
    fn registering_the_same_device_twice_does_not_duplicate_it() {
        let path = temp_vault_path();
        let mut vault = Vault::init(&path, "pw").unwrap();
        let identity = DeviceIdentity::generate("laptop").unwrap();

        vault.add_sync_device(&identity).unwrap();
        vault.add_sync_device(&identity).unwrap();
        assert_eq!(vault.sync_devices().len(), 1);
    }

    #[test]
    fn the_roster_lists_every_device_with_its_public_key() {
        let path = temp_vault_path();
        let mut vault = Vault::init(&path, "pw").unwrap();

        let laptop = DeviceIdentity::generate("laptop").unwrap();
        let phone = DeviceIdentity::generate("phone").unwrap();
        vault.add_sync_device(&laptop).unwrap();
        vault.add_sync_device(&phone).unwrap();

        let devices = vault.sync_devices();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].label, "laptop");
        assert_eq!(devices[0].public_key, laptop.public_key());
        assert_eq!(devices[1].fingerprint, phone.fingerprint());
    }

    #[test]
    fn a_trusted_peer_joins_the_roster_without_a_signing_key() {
        let path = temp_vault_path();
        let mut vault = Vault::init(&path, "pw").unwrap();
        let peer = DeviceIdentity::generate("phone").unwrap();

        let fingerprint = vault.trust_sync_device("phone", peer.public_key()).unwrap();
        assert_eq!(fingerprint, peer.fingerprint());
        assert_eq!(vault.sync_devices()[0].public_key, peer.public_key());

        // Its ops are accepted; its key is not ours to sign with.
        assert!(vault.sync_device_identity(&fingerprint).unwrap().is_none());
    }

    #[test]
    fn trusting_a_device_again_does_not_clobber_its_signing_key() {
        let path = temp_vault_path();
        let mut vault = Vault::init(&path, "pw").unwrap();
        let me = DeviceIdentity::generate("laptop").unwrap();

        vault.add_sync_device(&me).unwrap();
        vault.trust_sync_device("laptop-again", me.public_key()).unwrap();

        assert_eq!(vault.sync_devices().len(), 1);
        assert!(
            vault.sync_device_identity(&me.fingerprint()).unwrap().is_some(),
            "re-trusting this device threw away its own signing key"
        );
    }

    #[test]
    fn a_device_needs_a_label() {
        let path = temp_vault_path();
        let mut vault = Vault::init(&path, "pw").unwrap();
        assert!(vault.trust_sync_device("  ", [0u8; 32]).is_err());
    }

    #[test]
    fn a_removed_device_leaves_the_roster() {
        let path = temp_vault_path();
        let mut vault = Vault::init(&path, "pw").unwrap();
        let identity = DeviceIdentity::generate("lost-phone").unwrap();
        vault.add_sync_device(&identity).unwrap();

        assert!(vault.remove_sync_device(&identity.fingerprint()).unwrap());
        assert!(vault.sync_devices().is_empty());
        assert!(vault.sync_device_identity(&identity.fingerprint()).unwrap().is_none());
        assert!(!vault.remove_sync_device(&identity.fingerprint()).unwrap());
    }

    #[test]
    fn a_new_epoch_is_persisted_against_the_device() {
        let path = temp_vault_path();
        let identity = DeviceIdentity::generate("laptop").unwrap();
        {
            let mut vault = Vault::init(&path, "pw").unwrap();
            vault.add_sync_device(&identity).unwrap();
            vault.set_sync_device_epoch(&identity.fingerprint(), 999).unwrap();
            vault.save("pw").unwrap();
        }

        let vault = Vault::unlock(&path, "pw").unwrap();
        assert_eq!(vault.sync_devices()[0].epoch, 999);
        assert_eq!(vault.sync_device_identity(&identity.fingerprint()).unwrap().unwrap().epoch(), 999);
    }

    #[test]
    fn setting_an_epoch_for_an_unknown_device_is_an_error() {
        let path = temp_vault_path();
        let mut vault = Vault::init(&path, "pw").unwrap();
        assert!(vault.set_sync_device_epoch("nope", 1).is_err());
    }

    #[test]
    fn sync_bookkeeping_stays_out_of_the_password_listing() {
        let path = temp_vault_path();
        let mut vault = Vault::init(&path, "pw").unwrap();

        vault.ensure_sync_key().unwrap();
        vault.add_sync_device(&DeviceIdentity::generate("laptop").unwrap()).unwrap();
        vault
            .add_entry(PasswordEntry::new("GitHub".into(), String::new(), String::new(), "pw".into()))
            .unwrap();

        assert_eq!(vault.len(), 1);
        assert_eq!(vault.list_entries().unwrap().len(), 1);
    }

    #[test]
    fn a_forgotten_device_is_not_broadcast_as_a_deleted_password() {
        let path = temp_vault_path();
        let mut vault = Vault::init(&path, "pw").unwrap();
        let identity = DeviceIdentity::generate("lost-phone").unwrap();
        vault.add_sync_device(&identity).unwrap();
        vault.add_ssh_key(&SshKey::generate("laptop", "me@laptop").unwrap()).unwrap();

        vault.remove_sync_device(&identity.fingerprint()).unwrap();
        vault.delete_ssh_key("laptop").unwrap();

        assert!(
            vault.recycled_entry_ids().is_empty(),
            "pass's own records would be published to every peer as deleted passwords"
        );
    }

    #[test]
    fn a_deleted_entry_is_reported_as_recycled_and_can_be_restored() {
        let path = temp_vault_path();
        let mut vault = Vault::init(&path, "pw").unwrap();
        let id = vault
            .add_entry(PasswordEntry::new("GitHub".into(), String::new(), String::new(), "pw".into()))
            .unwrap();

        assert!(vault.recycled_entry_ids().is_empty());
        vault.delete_entry(&id).unwrap();
        assert_eq!(vault.recycled_entry_ids(), vec![id.clone()]);

        // Deleted entries stay readable for the sync layer, which has to
        // compare them against what a peer sends.
        assert!(vault.get_entry(&id).is_err());
        assert_eq!(vault.get_entry_including_deleted(&id).unwrap().website, "GitHub");

        vault.restore_entry(&id).unwrap();
        assert!(vault.recycled_entry_ids().is_empty());
        assert_eq!(vault.get_entry(&id).unwrap().website, "GitHub");
    }
}
