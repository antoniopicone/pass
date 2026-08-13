use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::crypto::{self, NONCE_SIZE, SALT_SIZE};
use crate::entry::{PasswordEntry, PasswordEntrySummary};
use crate::error::{PassError, Result};
use crate::merge::{self, MergeSummary};

/// Magic bytes to identify vault files: "PSVT"
const MAGIC_BYTES: &[u8; 4] = b"PSVT";
/// Current vault format version
const VAULT_VERSION: u32 = 1;

/// Internal structure for serializing vault data
#[derive(Serialize, Deserialize)]
struct VaultData {
    version: String,
    entries: Vec<PasswordEntry>,
}

/// An in-memory password vault
#[derive(Debug)]
pub struct Vault {
    entries: Vec<PasswordEntry>,
    path: PathBuf,
    is_unlocked: bool,
}

impl Vault {
    /// Create a new empty vault
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            entries: Vec::new(),
            path: path.as_ref().to_path_buf(),
            is_unlocked: false,
        }
    }

    /// Initialize a new vault file with a master password
    ///
    /// Creates a new encrypted vault file. Returns an error if the file already exists.
    pub fn init<P: AsRef<Path>>(path: P, master_password: &str) -> Result<Self> {
        let path = path.as_ref();
        
        if path.exists() {
            return Err(PassError::CryptoError(
                "Vault file already exists".to_string(),
            ));
        }

        let mut vault = Self::new(path);
        vault.is_unlocked = true;
        vault.save(master_password)?;
        
        Ok(vault)
    }

    /// Unlock an existing vault with the master password
    ///
    /// Reads and decrypts the vault file. Returns an error if the password is incorrect.
    pub fn unlock<P: AsRef<Path>>(path: P, master_password: &str) -> Result<Self> {
        let path = path.as_ref();
        
        if !path.exists() {
            return Err(PassError::VaultNotFound(path.display().to_string()));
        }

        // Read the vault file
        let mut file = File::open(path)?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;

        // Validate minimum size
        if contents.len() < 4 + 4 + SALT_SIZE + NONCE_SIZE + 16 {
            return Err(PassError::InvalidVaultFormat);
        }

        // Parse header
        let mut offset = 0;
        
        // Check magic bytes
        if &contents[offset..offset + 4] != MAGIC_BYTES {
            return Err(PassError::InvalidVaultFormat);
        }
        offset += 4;

        // Check version
        let version = u32::from_le_bytes([
            contents[offset],
            contents[offset + 1],
            contents[offset + 2],
            contents[offset + 3],
        ]);
        offset += 4;
        
        if version != VAULT_VERSION {
            return Err(PassError::InvalidVaultFormat);
        }

        // Extract salt
        let salt = &contents[offset..offset + SALT_SIZE];
        offset += SALT_SIZE;

        // Extract nonce
        let nonce_bytes = &contents[offset..offset + NONCE_SIZE];
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(nonce_bytes);
        offset += NONCE_SIZE;

        // Extract encrypted data (rest of the file)
        let encrypted_data = &contents[offset..];

        // Derive key from master password
        let mut key = crypto::derive_key(master_password, salt)?;
        
        // Decrypt data
        let decrypted_data = crypto::decrypt(encrypted_data, &key, &nonce)?;
        crypto::zeroize_key(&mut key);

        // Deserialize vault data
        let mut vault_data: VaultData = serde_json::from_slice(&decrypted_data)
            .map_err(|_| PassError::VaultCorrupted)?;

        // Restore password data after deserialization
        for entry in &mut vault_data.entries {
            entry.restore_after_deserialization();
        }

        Ok(Self {
            entries: vault_data.entries,
            path: path.to_path_buf(),
            is_unlocked: true,
        })
    }

    /// Save the vault to disk with encryption
    pub fn save(&mut self, master_password: &str) -> Result<()> {
        if !self.is_unlocked {
            return Err(PassError::CryptoError("Vault is locked".to_string()));
        }

        // Prepare entries for serialization
        for entry in &mut self.entries {
            entry.prepare_for_serialization();
        }

        // Serialize vault data
        let vault_data = VaultData {
            version: env!("CARGO_PKG_VERSION").to_string(),
            entries: self.entries.clone(),
        };
        
        let json_data = serde_json::to_vec(&vault_data)?;

        // Generate salt and nonce
        let salt = crypto::generate_salt();
        let nonce = crypto::generate_nonce();

        // Derive key from master password
        let mut key = crypto::derive_key(master_password, &salt)?;

        // Encrypt data
        let encrypted_data = crypto::encrypt(&json_data, &key, &nonce)?;
        crypto::zeroize_key(&mut key);

        // Build file contents
        let mut file_contents = Vec::new();
        file_contents.extend_from_slice(MAGIC_BYTES);
        file_contents.extend_from_slice(&VAULT_VERSION.to_le_bytes());
        file_contents.extend_from_slice(&salt);
        file_contents.extend_from_slice(&nonce);
        file_contents.extend_from_slice(&encrypted_data);

        // Write to file (atomic write using temp file)
        let temp_path = self.path.with_extension("vault.tmp");
        let mut file = File::create(&temp_path)?;
        file.write_all(&file_contents)?;
        file.sync_all()?;
        drop(file);

        // Atomic rename
        fs::rename(&temp_path, &self.path)?;

        Ok(())
    }

    /// Add a new password entry
    pub fn add_entry(&mut self, entry: PasswordEntry) -> Result<String> {
        if !self.is_unlocked {
            return Err(PassError::CryptoError("Vault is locked".to_string()));
        }

        let id = entry.id.clone();
        self.entries.push(entry);
        Ok(id)
    }

    /// Get all entries as summaries (without passwords)
    pub fn list_entries(&self) -> Result<Vec<PasswordEntrySummary>> {
        if !self.is_unlocked {
            return Err(PassError::CryptoError("Vault is locked".to_string()));
        }

        Ok(self
            .entries
            .iter()
            .filter(|e| !e.is_deleted())
            .map(PasswordEntrySummary::from)
            .collect())
    }

    /// Get a specific entry by ID (including password)
    pub fn get_entry(&self, id: &str) -> Result<&PasswordEntry> {
        if !self.is_unlocked {
            return Err(PassError::CryptoError("Vault is locked".to_string()));
        }

        self.entries
            .iter()
            .find(|e| e.id == id && !e.is_deleted())
            .ok_or_else(|| PassError::EntryNotFound(id.to_string()))
    }

    /// Delete an entry by ID
    ///
    /// This is a soft delete: the entry is kept as a tombstone so the
    /// deletion can be merged into other copies of the vault instead of
    /// disappearing only locally. See [`Vault::merge_entries`].
    pub fn delete_entry(&mut self, id: &str) -> Result<()> {
        if !self.is_unlocked {
            return Err(PassError::CryptoError("Vault is locked".to_string()));
        }

        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.id == id && !e.is_deleted())
            .ok_or_else(|| PassError::EntryNotFound(id.to_string()))?;

        entry.mark_deleted();
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
        if !self.is_unlocked {
            return Err(PassError::CryptoError("Vault is locked".to_string()));
        }

        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| PassError::EntryNotFound(id.to_string()))?;

        entry.update(website, url, username);
        if let Some(pass) = password {
            entry.set_password(pass);
        }

        Ok(())
    }

    /// Get the vault file path
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Check if the vault is unlocked
    pub fn is_unlocked(&self) -> bool {
        self.is_unlocked
    }

    /// Get the number of (non-deleted) entries
    pub fn len(&self) -> usize {
        self.entries.iter().filter(|e| !e.is_deleted()).count()
    }

    /// Check if the vault is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// All entries, including tombstoned (deleted) ones. Needed for
    /// syncing/merging, since deletions must propagate to other copies of
    /// the vault rather than just being filtered out here.
    pub fn entries_snapshot(&self) -> &[PasswordEntry] {
        &self.entries
    }

    /// Merge another set of entries (e.g. pulled from a copy of this vault
    /// synced from another device) into this vault, keeping whichever
    /// version of each entry is newest. Does not save automatically.
    ///
    /// See the [`crate::merge`] module for the conflict-resolution rules.
    pub fn merge_entries(&mut self, other: &[PasswordEntry]) -> MergeSummary {
        let (merged, summary) = merge::merge_entries(&self.entries, other);
        self.entries = merged;
        summary
    }

    /// Convenience wrapper: unlock another copy of this vault at `path`
    /// with the same master password and merge its entries into this one.
    /// Does not save automatically — call [`Vault::save`] afterwards to
    /// persist (and re-encrypt) the merged result.
    pub fn merge_from_file<P: AsRef<Path>>(
        &mut self,
        path: P,
        master_password: &str,
    ) -> Result<MergeSummary> {
        let other = Vault::unlock(path, master_password)?;
        Ok(self.merge_entries(&other.entries))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_vault_init_and_unlock() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();
        
        // Remove the file so we can test init
        drop(temp_file);

        let master_password = "super_secret_password_123";

        // Initialize vault
        let vault = Vault::init(&path, master_password).unwrap();
        assert!(vault.is_unlocked());
        assert_eq!(vault.len(), 0);

        // Unlock vault
        let vault = Vault::unlock(&path, master_password).unwrap();
        assert!(vault.is_unlocked());
        assert_eq!(vault.len(), 0);
    }

    #[test]
    fn test_wrong_password_fails() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();
        drop(temp_file);

        Vault::init(&path, "correct_password").unwrap();
        
        let result = Vault::unlock(&path, "wrong_password");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PassError::InvalidPassword));
    }

    #[test]
    fn test_add_and_retrieve_entry() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();
        drop(temp_file);

        let master_password = "test_password";
        let mut vault = Vault::init(&path, master_password).unwrap();

        // Add entry
        let entry = PasswordEntry::new(
            "GitHub".to_string(),
            "https://github.com/login".to_string(),
            "user@example.com".to_string(),
            "github_password_123".to_string(),
        );
        let id = vault.add_entry(entry).unwrap();
        vault.save(master_password).unwrap();

        // Reload and verify
        let vault = Vault::unlock(&path, master_password).unwrap();
        assert_eq!(vault.len(), 1);
        
        let retrieved = vault.get_entry(&id).unwrap();
        assert_eq!(retrieved.website, "GitHub");
        assert_eq!(retrieved.username, "user@example.com");
        assert_eq!(retrieved.password(), "github_password_123");
    }

    #[test]
    fn test_delete_entry() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();
        drop(temp_file);

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
    fn test_deleted_entry_is_a_tombstone_not_a_removal() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();
        drop(temp_file);

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

        // ...but retained as a tombstone so it can be merged/synced.
        assert_eq!(vault.entries_snapshot().len(), 1);
        assert!(vault.entries_snapshot()[0].is_deleted());
    }

    #[test]
    fn test_merge_from_file_reconciles_two_devices() {
        let device_a_file = NamedTempFile::new().unwrap();
        let device_a_path = device_a_file.path().to_path_buf();
        drop(device_a_file);
        let device_b_file = NamedTempFile::new().unwrap();
        let device_b_path = device_b_file.path().to_path_buf();
        drop(device_b_file);

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

        // Meanwhile device A updates the shared entry and deletes nothing.
        vault_a
            .update_entry(&shared_id, None, None, None, Some("new_password".to_string()))
            .unwrap();
        vault_a.save(master_password).unwrap();

        // Device A pulls device B's copy and merges.
        let summary = vault_a.merge_from_file(&device_b_path, master_password).unwrap();
        vault_a.save(master_password).unwrap();

        assert_eq!(summary.added, 1); // GitLab entry from device B
        assert_eq!(vault_a.len(), 2);
        assert_eq!(vault_a.get_entry(&shared_id).unwrap().password(), "new_password");
    }
}
