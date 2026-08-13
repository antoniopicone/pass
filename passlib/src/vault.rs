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

use crate::entry::{PasswordEntry, PasswordEntrySummary};
use crate::error::{PassError, Result};
use crate::totp::{self, TotpConfig};
use chrono::{DateTime, NaiveDateTime, Utc};
use keepass::config::KdfConfig;
use keepass::db::{fields, merge::MergeLog, DatabaseOpenError, EntryId, EntryRef, GroupId, Times};
use keepass::error::DatabaseKeyError;
use keepass::{Database, DatabaseKey};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use uuid::Uuid;

const RECYCLE_BIN_GROUP_NAME: &str = "Recycle Bin";

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
            if let Some(totp) = &entry.totp {
                e.set_unprotected(fields::OTP, totp.to_otpauth_uri());
            }
        });

        Ok(entry.id)
    }

    /// Get all entries as summaries (without passwords), excluding
    /// anything in the Recycle Bin
    pub fn list_entries(&self) -> Result<Vec<PasswordEntrySummary>> {
        let recycle_bin_id = self.recycle_bin_id();

        Ok(self
            .db
            .iter_all_entries()
            .filter(|e| Some(e.parent().id()) != recycle_bin_id)
            .map(|e| PasswordEntrySummary::from(&to_password_entry(&e)))
            .collect())
    }

    /// Get a specific entry by ID (including password)
    pub fn get_entry(&self, id: &str) -> Result<PasswordEntry> {
        let entry_id = parse_entry_id(id)?;
        let entry_ref = self
            .db
            .entry(entry_id)
            .filter(|e| !self.is_in_recycle_bin(e))
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

    /// Update an existing entry
    pub fn update_entry(
        &mut self,
        id: &str,
        website: Option<String>,
        url: Option<String>,
        username: Option<String>,
        password: Option<String>,
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
        Ok(MergeSummary::from_log(&log, self.db.num_entries()))
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

    /// Get the number of (non-deleted) entries
    pub fn len(&self) -> usize {
        let recycle_bin_id = self.recycle_bin_id();
        self.db
            .iter_all_entries()
            .filter(|e| Some(e.parent().id()) != recycle_bin_id)
            .count()
    }

    /// Check if the vault is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn recycle_bin_id(&self) -> Option<GroupId> {
        self.db.meta.recyclebin_uuid.map(GroupId::from_uuid)
    }

    fn is_in_recycle_bin(&self, entry: &EntryRef) -> bool {
        Some(entry.parent().id()) == self.recycle_bin_id()
    }

    fn require_active_entry(&self, entry_id: EntryId, display_id: &str) -> Result<()> {
        self.db
            .entry(entry_id)
            .filter(|e| !self.is_in_recycle_bin(e))
            .map(|_| ())
            .ok_or_else(|| PassError::EntryNotFound(display_id.to_string()))
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

    PasswordEntry::from_parts(id, website, url, username, password, created_at, updated_at, totp)
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
    use tempfile::NamedTempFile;

    fn temp_vault_path() -> PathBuf {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_path_buf();
        drop(f);
        path
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
            .update_entry(&shared_id, None, None, None, Some("new_password".to_string()))
            .unwrap();
        vault_a.save(master_password).unwrap();

        // Device A pulls device B's copy and merges.
        let summary = vault_a.merge_from_file(&device_b_path, master_password).unwrap();
        vault_a.save(master_password).unwrap();

        assert_eq!(summary.created, 1); // GitLab entry from device B
        assert_eq!(vault_a.len(), 2);
        assert_eq!(vault_a.get_entry(&shared_id).unwrap().password(), "new_password");
    }
}
