use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

/// A password entry containing website credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordEntry {
    /// Unique identifier for this entry
    pub id: String,
    /// Human-readable name/title for the website
    pub website: String,
    /// Full URL to the login page
    pub url: String,
    /// Username or email address
    pub username: String,
    /// Password (stored in memory, zeroized on drop)
    #[serde(skip)]
    password_data: String,
    /// Serialized password for vault storage
    #[serde(rename = "password")]
    password_serialized: String,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp
    pub updated_at: DateTime<Utc>,
    /// Monotonically increasing per-entry edit counter. Bumped on every
    /// edit (including deletion). Used to resolve merge conflicts between
    /// devices deterministically, without depending on clock sync.
    pub revision: u64,
    /// Soft-delete marker. Deletions are tombstones rather than removals
    /// so that a deletion made on one device can be merged into another
    /// device's copy of the vault instead of silently failing to
    /// propagate.
    pub deleted_at: Option<DateTime<Utc>>,
}

impl PasswordEntry {
    /// Create a new password entry
    pub fn new(website: String, url: String, username: String, password: String) -> Self {
        let now = Utc::now();
        let password_clone = password.clone();
        
        Self {
            id: Uuid::new_v4().to_string(),
            website,
            url,
            username,
            password_data: password,
            password_serialized: password_clone,
            created_at: now,
            updated_at: now,
            revision: 1,
            deleted_at: None,
        }
    }

    /// Get the password for this entry
    pub fn password(&self) -> &str {
        if !self.password_data.is_empty() {
            &self.password_data
        } else {
            &self.password_serialized
        }
    }

    /// Update the password
    pub fn set_password(&mut self, password: String) {
        self.password_data.zeroize();
        self.password_data = password.clone();
        self.password_serialized = password;
        self.touch();
    }

    /// Update metadata
    pub fn update(&mut self, website: Option<String>, url: Option<String>, username: Option<String>) {
        let mut changed = false;
        if let Some(w) = website {
            self.website = w;
            changed = true;
        }
        if let Some(u) = url {
            self.url = u;
            changed = true;
        }
        if let Some(un) = username {
            self.username = un;
            changed = true;
        }
        if changed {
            self.touch();
        }
    }

    /// Mark this entry as deleted without removing it from the list, so
    /// the deletion itself can be merged into other copies of the vault
    /// instead of silently failing to propagate to devices that haven't
    /// seen it yet.
    pub fn mark_deleted(&mut self) {
        self.deleted_at = Some(Utc::now());
        self.touch();
    }

    /// Whether this entry is a tombstone (soft-deleted).
    pub fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }

    /// Bump the revision counter and refresh the modification timestamp.
    /// Called on every edit, including deletion.
    fn touch(&mut self) {
        self.revision += 1;
        self.updated_at = Utc::now();
    }

    /// Deterministic content signature used to break merge ties between
    /// two copies of an entry that share the same revision number.
    pub(crate) fn fingerprint(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.website,
            self.url,
            self.username,
            self.password_serialized,
            self.deleted_at.map(|d| d.to_rfc3339()).unwrap_or_default(),
        )
    }

    /// Prepare entry for serialization
    pub(crate) fn prepare_for_serialization(&mut self) {
        if !self.password_data.is_empty() {
            self.password_serialized = self.password_data.clone();
        }
    }

    /// Restore entry after deserialization
    pub(crate) fn restore_after_deserialization(&mut self) {
        self.password_data = self.password_serialized.clone();
    }
}

impl Drop for PasswordEntry {
    fn drop(&mut self) {
        self.password_data.zeroize();
        self.password_serialized.zeroize();
    }
}

/// Summary view of a password entry (without the actual password)
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordEntrySummary {
    pub id: String,
    pub website: String,
    pub url: String,
    pub username: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<&PasswordEntry> for PasswordEntrySummary {
    fn from(entry: &PasswordEntry) -> Self {
        Self {
            id: entry.id.clone(),
            website: entry.website.clone(),
            url: entry.url.clone(),
            username: entry.username.clone(),
            created_at: entry.created_at,
            updated_at: entry.updated_at,
        }
    }
}
