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
        self.updated_at = Utc::now();
    }

    /// Update metadata
    pub fn update(&mut self, website: Option<String>, url: Option<String>, username: Option<String>) {
        if let Some(w) = website {
            self.website = w;
        }
        if let Some(u) = url {
            self.url = u;
        }
        if let Some(un) = username {
            self.username = un;
        }
        self.updated_at = Utc::now();
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
