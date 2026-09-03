//! Peer-to-peer replication of a vault between a person's own devices.
//!
//! `docs/SYNC_STRATEGY.md` calls this L0.b: getting the bytes across
//! without a third party. The file-sync transport (`pass watch` over
//! Syncthing/Nextcloud) stays, and stays useful for devices that are never
//! awake together. This is the other half — devices that *can* reach each
//! other talk directly, with nobody in the middle and nothing to keep
//! running.
//!
//! ## The shape of it
//!
//! Every node is identical; none is authoritative. Convergence comes from
//! a CRDT ([`core`]) plus periodic anti-entropy, not from anyone being in
//! charge:
//!
//! ```text
//!   vault (KDBX4, the truth on disk)
//!     │  ingest: an entry whose content moved since we last synced it
//!     ▼          becomes one signed, sealed op
//!   op-log (append-only, per device, gapless seq)
//!     │  anti-entropy: "here is my version vector, send what I lack"
//!     ▼
//!   peers (agent, one port per device, discovered on the tailnet)
//!     │  materialise: the op that wins the LWW is written back
//!     ▼
//!   vault
//! ```
//!
//! ## What each layer is responsible for
//!
//! - [`core`] — the merge rule, and nothing else. No I/O, no crypto keys,
//!   no KDBX. This is the part that must be identical on every device.
//! - [`crypto`] — who signed an op ([`DeviceIdentity`]) and what it says
//!   ([`SyncKey`]). An op is ciphertext signed by a named device.
//! - [`SyncEntry`] — the payload: one vault entry, sealed.
//! - The agent (`pass-agent`) — discovery, transport, the anti-entropy
//!   loop, and the two directions of the bridge below.
//!
//! ## Why the op-log is not the storage format
//!
//! The vault stays a plain KDBX4 file that KeePassXC opens, because that
//! property is the reason to use `pass` at all. The op-log is a *changelog
//! in front of* the vault, kept in the agent's runtime directory; delete it
//! and nothing is lost but the ability to answer "what changed since your
//! version vector said 7" cheaply.
//!
//! ## What this deliberately does not do
//!
//! It does not replicate SSH keys or the sharing identity — only password
//! entries. Those live in the vault's own groups, travel with the file, and
//! an SSH private key is not something to put on the wire for a
//! convenience feature.

pub mod core;
pub mod crypto;

pub use core::{
    device_id, fingerprint_of, DeviceId, Hlc, Op, OpKind, Rejected, Replica, Roster, StateEntry,
    VersionVector, SERVICE,
};
pub use crypto::{DeviceIdentity, SyncKey, DEVICE_KEY_PREFIX};

use crate::entry::PasswordEntry;
use crate::error::{PassError, Result};
use crate::totp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One vault entry as it travels inside an op, before sealing.
///
/// A flat, self-describing copy — the same shape as
/// [`crate::share::SharedEntry`] and for the same reason — but with one
/// deliberate difference: this one keeps no timestamps.
///
/// **Why no timestamps.** The op's HLC already says when the change
/// happened, and it is the value the merge uses. A second time field in the
/// payload would be a second answer to the same question, and the two would
/// disagree the first time a vault was written by something other than
/// `pass` — at which point the merge would follow one of them and the user
/// would have no way to tell which.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SyncEntry {
    pub website: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub username: String,
    pub password: String,
    /// `otpauth://` URI, when the entry carries an MFA secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp_uri: Option<String>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub additional_urls: Vec<String>,
}

/// Hand-written so a stray `{:?}` — in a log line, a panic message, an
/// error being wrapped — cannot put a password on someone's terminal. The
/// rest of this crate holds the same line ([`crate::secmem::Shielded`],
/// [`crate::sync::DeviceIdentity`]), and it is worth nothing if the type
/// that carries the plaintext is the one exception.
impl std::fmt::Debug for SyncEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncEntry")
            .field("website", &self.website)
            .field("url", &self.url)
            .field("username", &self.username)
            .field("password", &"[redacted]")
            .field("totp_uri", &self.totp_uri.as_ref().map(|_| "[redacted]"))
            .field("notes", &"[redacted]")
            .field("additional_urls", &self.additional_urls)
            .finish()
    }
}

impl From<&PasswordEntry> for SyncEntry {
    fn from(entry: &PasswordEntry) -> Self {
        Self {
            website: entry.website.clone(),
            url: entry.url.clone(),
            username: entry.username.clone(),
            password: entry.password().to_string(),
            totp_uri: entry.totp.as_ref().map(|t| t.to_otpauth_uri()),
            notes: entry.notes.clone(),
            additional_urls: entry.additional_urls.clone(),
        }
    }
}

impl SyncEntry {
    /// Rebuild a vault entry, keeping the id it has on every other device.
    ///
    /// The id is what makes this replication rather than copying: the same
    /// credential must be the same KDBX object everywhere, or the next
    /// merge sees two entries and keeps both.
    pub fn into_password_entry(self, id: &str) -> Result<PasswordEntry> {
        let mut entry = PasswordEntry::new(self.website, self.url, self.username, self.password);
        entry.id = id.to_string();
        entry.notes = self.notes;
        entry.additional_urls = self.additional_urls;
        if let Some(uri) = self.totp_uri {
            entry.totp = Some(totp::parse_otpauth_uri(&uri)?);
        }
        Ok(entry)
    }

    /// A stable hash of everything a user can change.
    ///
    /// This — not a timestamp — is what decides whether a local edit needs
    /// publishing. Writing a peer's change into the vault bumps the KDBX
    /// modification time, so a timestamp test would see that as a fresh
    /// local edit, publish it back, and leave two devices bouncing the same
    /// entry between them forever.
    pub fn content_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"pass-sync-entry-v1");
        let mut urls = self.additional_urls.clone();
        // The order of extra URLs is not meaningful and not preserved
        // through every client, so it must not make two identical entries
        // look different.
        urls.sort();
        for field in [
            self.website.as_str(),
            self.url.as_str(),
            self.username.as_str(),
            self.password.as_str(),
            self.totp_uri.as_deref().unwrap_or(""),
            self.notes.as_str(),
        ]
        .into_iter()
        .chain(urls.iter().map(String::as_str))
        {
            hasher.update((field.len() as u64).to_be_bytes());
            hasher.update(field.as_bytes());
        }
        crypto::hex_encode(&hasher.finalize())
    }

    /// Serialise and seal, ready to become an op's payload.
    pub fn seal(&self, key: &SyncKey, entity: &str) -> Result<String> {
        use zeroize::Zeroize;

        let mut json = serde_json::to_vec(self)
            .map_err(|e| PassError::Sync(format!("failed to encode an entry for sync: {e}")))?;
        let sealed = key.seal(entity, &json);
        json.zeroize();
        sealed
    }

    /// Open a sealed payload.
    pub fn open(key: &SyncKey, entity: &str, sealed: &str) -> Result<Self> {
        let plaintext = key.open(entity, sealed)?;
        serde_json::from_slice(plaintext.as_slice())
            .map_err(|e| PassError::Sync(format!("a sync payload is malformed: {e}")))
    }
}

/// What this device knows about one entity the last time vault and op-log
/// agreed about it.
///
/// Local bookkeeping, never replicated. It is what breaks the symmetry
/// between "the vault changed, publish it" and "an op arrived, write it":
/// without a record of where the two last agreed, both tests fire on the
/// same difference and the entry ping-pongs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntityMark {
    /// Content hash the vault and the op-log last shared.
    pub content: String,
    /// The winning op's clock at that moment.
    pub hlc: Hlc,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SyncEntry {
        SyncEntry {
            website: "GitHub".into(),
            url: "https://github.com".into(),
            username: "me".into(),
            password: "hunter2".into(),
            totp_uri: None,
            notes: "note".into(),
            additional_urls: vec!["https://gist.github.com".into()],
        }
    }

    #[test]
    fn an_entry_round_trips_through_a_sealed_payload() {
        let key = SyncKey::generate().unwrap();
        let sealed = sample().seal(&key, "entity-1").unwrap();

        assert!(!sealed.contains("hunter2"));
        assert_eq!(SyncEntry::open(&key, "entity-1", &sealed).unwrap(), sample());
    }

    #[test]
    fn an_entry_round_trips_through_a_password_entry() {
        let entry = sample().into_password_entry("11111111-2222-3333-4444-555555555555").unwrap();

        assert_eq!(entry.id, "11111111-2222-3333-4444-555555555555");
        assert_eq!(entry.password(), "hunter2");
        assert_eq!(SyncEntry::from(&entry), sample());
    }

    #[test]
    fn a_totp_secret_survives_the_round_trip() {
        let mut original = sample();
        original.totp_uri = Some("otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP&issuer=GitHub".into());

        let entry = original.clone().into_password_entry("id").unwrap();
        assert!(entry.totp.is_some());
        assert!(SyncEntry::from(&entry).totp_uri.is_some());
    }

    #[test]
    fn debug_does_not_print_the_secrets() {
        let mut entry = sample();
        entry.totp_uri = Some("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".into());
        let printed = format!("{entry:?}");

        assert!(!printed.contains("hunter2"), "{printed}");
        assert!(!printed.contains("JBSWY3DPEHPK3PXP"), "{printed}");
        assert!(printed.contains("GitHub"), "the useful half should survive: {printed}");
    }

    #[test]
    fn the_content_hash_changes_with_every_user_visible_field() {
        let base = sample().content_hash();

        for changed in [
            SyncEntry { website: "GitLab".into(), ..sample() },
            SyncEntry { url: "https://gitlab.com".into(), ..sample() },
            SyncEntry { username: "you".into(), ..sample() },
            SyncEntry { password: "hunter3".into(), ..sample() },
            SyncEntry { notes: "other".into(), ..sample() },
            SyncEntry { totp_uri: Some("otpauth://x".into()), ..sample() },
            SyncEntry { additional_urls: vec![], ..sample() },
        ] {
            assert_ne!(changed.content_hash(), base);
        }
    }

    #[test]
    fn the_content_hash_ignores_the_order_of_additional_urls() {
        let a = SyncEntry { additional_urls: vec!["b".into(), "a".into()], ..sample() };
        let b = SyncEntry { additional_urls: vec!["a".into(), "b".into()], ..sample() };
        assert_eq!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn the_content_hash_cannot_be_fooled_by_moving_a_field_boundary() {
        let a = SyncEntry { website: "ab".into(), url: String::new(), ..Default::default() };
        let b = SyncEntry { website: "a".into(), url: "b".into(), ..Default::default() };
        assert_ne!(a.content_hash(), b.content_hash());
    }
}
