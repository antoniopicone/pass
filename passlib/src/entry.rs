use crate::totp::TotpConfig;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

/// A password entry containing website credentials.
///
/// This is a plain, owned snapshot — not a live view into the vault. Read
/// it via [`crate::vault::Vault::get_entry`] /
/// [`list_entries`][crate::vault::Vault::list_entries], and write changes
/// back through [`crate::vault::Vault::add_entry`] /
/// [`update_entry`][crate::vault::Vault::update_entry], which translate it
/// to and from the underlying KDBX4 entry.
#[derive(Debug, Clone)]
pub struct PasswordEntry {
    /// Unique identifier for this entry (a UUID, matching the KDBX entry's UUID)
    pub id: String,
    /// Human-readable name/title for the website
    pub website: String,
    /// Full URL to the login page
    pub url: String,
    /// Username or email address
    pub username: String,
    /// Password, zeroized on drop
    password: Zeroizing<String>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp
    pub updated_at: DateTime<Utc>,
    /// Optional MFA/2FA secret (from a service's QR code), stored in the
    /// KDBX entry's standard `otp` field — the same convention KeePassXC
    /// itself uses, so a TOTP configured by either tool works in both.
    pub totp: Option<TotpConfig>,
    /// Free-form notes, stored in the KDBX entry's standard `Notes` field.
    pub notes: String,
    /// Extra URLs this entry should also be treated as belonging to — e.g.
    /// one Apple account entry also matching `appleid.apple.com` and
    /// `icloud.com`, on top of its primary `url`. Stored as a Pass-specific
    /// custom string field (see [`crate::vault`]'s `ADDITIONAL_URLS_FIELD`),
    /// newline-separated — a plain, visible custom attribute in
    /// KeePassXC/other KDBX tools, just not specially understood by them.
    pub additional_urls: Vec<String>,
    /// Previous passwords, newest first, kept automatically by the KDBX4
    /// history mechanism (every [`crate::vault::Vault::update_entry`] call
    /// archives the pre-change state — the same mechanism KeePassXC itself
    /// relies on). Empty for an entry whose password has never changed.
    pub history: Vec<PasswordHistoryEntry>,
}

/// One previous version of an entry's password, from the KDBX4 history.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordHistoryEntry {
    pub password: String,
    pub changed_at: DateTime<Utc>,
}

impl PasswordEntry {
    /// Create a new password entry
    pub fn new(website: String, url: String, username: String, password: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            website,
            url,
            username,
            password: Zeroizing::new(password),
            created_at: now,
            updated_at: now,
            totp: None,
            notes: String::new(),
            additional_urls: Vec::new(),
            history: Vec::new(),
        }
    }

    /// Reconstruct an entry snapshot from stored data (used when reading
    /// back from the KDBX vault). Unlike [`PasswordEntry::new`], this does
    /// not touch `created_at`/`updated_at` — they're taken as given.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts(
        id: String,
        website: String,
        url: String,
        username: String,
        password: String,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
        totp: Option<TotpConfig>,
        notes: String,
        additional_urls: Vec<String>,
        history: Vec<PasswordHistoryEntry>,
    ) -> Self {
        Self {
            id,
            website,
            url,
            username,
            password: Zeroizing::new(password),
            created_at,
            updated_at,
            totp,
            notes,
            additional_urls,
            history,
        }
    }

    /// Get the password for this entry
    pub fn password(&self) -> &str {
        &self.password
    }

    /// Update the password
    pub fn set_password(&mut self, password: String) {
        self.password = Zeroizing::new(password);
        self.updated_at = Utc::now();
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
            self.updated_at = Utc::now();
        }
    }

    /// All URLs this entry should match against: its primary `url` followed
    /// by any `additional_urls`.
    pub fn all_urls(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.url.as_str()).chain(self.additional_urls.iter().map(String::as_str))
    }
}

/// Summary view of a password entry (without the actual password)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordEntrySummary {
    pub id: String,
    pub website: String,
    pub url: String,
    pub username: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Whether this entry has an MFA/TOTP secret attached. The current
    /// code itself is deliberately not included here — like the password,
    /// it's only computed on demand (see [`crate::totp::generate_code`])
    /// rather than handed out in bulk listings.
    pub has_totp: bool,
    pub additional_urls: Vec<String>,
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
            has_totp: entry.totp.is_some(),
            additional_urls: entry.additional_urls.clone(),
        }
    }
}
