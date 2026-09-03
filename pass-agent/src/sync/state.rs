//! What the sync layer keeps on disk between runs.
//!
//! Three things, all in one JSON file under [`crate::paths::state_dir`]:
//!
//! - the **op-log**, so a restart does not make every peer re-send its
//!   whole history;
//! - the **entity marks**, so a restart does not look like every entry
//!   having changed at once (see [`super::bridge`]);
//! - the **roster and peer cache**, so a locked agent can still verify and
//!   relay ops for the mesh without opening the vault.
//!
//! ## What is *not* in it
//!
//! No plaintext. Op payloads are sealed with the vault's sync key, which
//! lives only in the vault, so this file is opaque even though it is a
//! plain file — and the private signing key is not here either. The worst
//! an attacker who reads it learns is which entry UUIDs changed when, and
//! by which device. That is not nothing, which is why the file is `0600` in
//! a `0700` directory like everything else the agent writes; but it is not
//! a password.
//!
//! ## Why signatures are re-checked on load
//!
//! The file is plain JSON that a local process could edit. Ops are verified
//! against the roster when they are read back, exactly as if they had
//! arrived from the network, so editing the file can remove history but
//! cannot forge it.

use super::bridge::Marks;
use super::discovery::Peer;
use crate::paths;
use passlib::sync::{Op, Replica, Roster};
use passlib::SyncDevice;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

const STATE_FILE: &str = "sync-state.json";

/// The devices allowed to write into this replica, as public keys.
///
/// A snapshot of the vault's roster, kept here so the check survives the
/// vault being locked — the alternative is an agent that stops verifying
/// when it can no longer read the vault, which is the wrong way round.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrustedDevices {
    /// Fingerprint to base64 Ed25519 public key.
    keys: BTreeMap<String, String>,
    /// Fingerprint to the label the vault gives that device, for messages.
    #[serde(default)]
    labels: BTreeMap<String, String>,
}

impl TrustedDevices {
    pub fn from_vault(devices: &[SyncDevice]) -> Self {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine;

        Self {
            keys: devices
                .iter()
                .map(|d| (d.fingerprint.clone(), BASE64.encode(d.public_key)))
                .collect(),
            labels: devices
                .iter()
                .map(|d| (d.fingerprint.clone(), d.label.clone()))
                .collect(),
        }
    }

    /// What to call a device in a message to the user.
    pub fn label(&self, fingerprint: &str) -> String {
        self.labels.get(fingerprint).cloned().unwrap_or_else(|| fingerprint.to_string())
    }

    pub fn contains(&self, fingerprint: &str) -> bool {
        self.keys.contains_key(fingerprint)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl Roster for TrustedDevices {
    fn verifying_key(&self, fingerprint: &str) -> Option<[u8; 32]> {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine;

        let encoded = self.keys.get(fingerprint)?;
        BASE64.decode(encoded).ok()?.try_into().ok()
    }
}

/// The on-disk form.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncState {
    /// This replica's wire id, `<fingerprint>@<epoch>`. Empty before the
    /// vault has ever been unlocked with sync enabled.
    #[serde(default)]
    pub device: String,
    /// Highest `seq` this device has ever published.
    ///
    /// Kept separately from the log so that a log restored from a backup —
    /// or truncated by hand — can be *detected*: if the log rewound below
    /// this, the device must start a new epoch or its future ops will be
    /// discarded by every peer as already-seen. See [`passlib::sync`].
    #[serde(default)]
    pub high_water: u64,
    #[serde(default)]
    pub ops: Vec<Op>,
    #[serde(default)]
    pub marks: Marks,
    #[serde(default)]
    pub peers: Vec<Peer>,
    #[serde(default)]
    pub trusted: TrustedDevices,
}

impl SyncState {
    pub fn path() -> io::Result<PathBuf> {
        Ok(paths::state_dir()?.join(STATE_FILE))
    }

    /// Read the state, or start from empty.
    ///
    /// A file that cannot be parsed is reported rather than silently
    /// replaced: it holds the op-log, and quietly starting over would look
    /// to the user like sync working while every peer re-sends everything.
    pub fn load(path: &Path) -> io::Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {e}", path.display()))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    /// Write atomically, `0600`.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            paths::restrict_to_owner(parent, 0o700)?;
        }

        // Temp file then rename: a crash mid-write must not leave a
        // half-written op-log that fails to parse on the next start.
        let temp = path.with_extension("json.tmp");
        std::fs::write(&temp, serde_json::to_vec_pretty(self)?)?;
        paths::restrict_to_owner(&temp, 0o600)?;
        std::fs::rename(&temp, path)?;
        Ok(())
    }

    /// Rebuild a replica from the stored log.
    ///
    /// Returns the replica and how many stored ops failed verification —
    /// non-zero means the file was tampered with or the roster shrank
    /// (a device was removed), and the caller says so rather than hiding it.
    pub fn replica(&self) -> (Replica, usize) {
        let mut replica = Replica::new(self.device.clone());
        let mut rejected = 0;

        // Sorted so a hand-edited file cannot introduce a causal gap purely
        // by reordering.
        let mut ops = self.ops.clone();
        ops.sort_by(|a, b| (&a.device, a.seq).cmp(&(&b.device, b.seq)));

        for op in ops {
            if replica.apply(op, &self.trusted).is_err() {
                rejected += 1;
            }
        }

        (replica, rejected)
    }

    /// Whether the log has rewound below what this device already
    /// published — the restored-backup case that silently breaks sync.
    pub fn log_rewound(&self, replica: &Replica) -> bool {
        log_rewound(&self.device, replica.next_seq().saturating_sub(1), self.high_water)
    }
}

/// Has this device published ops it can no longer account for?
///
/// The one place the rule lives, called both when state is loaded and by the
/// running node — two copies of a rule this consequential is how they end up
/// disagreeing. A device with no identity yet has published nothing, so it
/// can never be rewound.
pub fn log_rewound(device: &str, published: u64, high_water: u64) -> bool {
    !device.is_empty() && published < high_water
}

#[cfg(test)]
mod tests {
    use super::*;
    use passlib::sync::{device_id, fingerprint_of, DeviceIdentity, OpKind, SyncKey};

    fn identity_and_roster(label: &str) -> (DeviceIdentity, TrustedDevices) {
        let identity = DeviceIdentity::generate(label).unwrap();
        let roster = TrustedDevices::from_vault(&[SyncDevice {
            label: label.to_string(),
            fingerprint: identity.fingerprint(),
            public_key: identity.public_key(),
            epoch: identity.epoch(),
        }]);
        (identity, roster)
    }

    fn state_with_ops(count: u64) -> (SyncState, DeviceIdentity) {
        let (identity, trusted) = identity_and_roster("laptop");
        let key = SyncKey::generate().unwrap();
        let mut replica = Replica::new(identity.device_id());

        for i in 0..count {
            let payload = key.seal(&format!("entity-{i}"), b"{}").unwrap();
            replica
                .local_change(&format!("entity-{i}"), OpKind::Upsert, payload, |op| identity.sign_op(op))
                .unwrap();
        }

        let state = SyncState {
            device: identity.device_id(),
            high_water: replica.next_seq() - 1,
            ops: replica.export_log(),
            marks: Marks::new(),
            peers: Vec::new(),
            trusted,
        };
        (state, identity)
    }

    #[test]
    fn a_stored_log_rebuilds_the_same_replica() {
        let (state, _) = state_with_ops(3);
        let (replica, rejected) = state.replica();

        assert_eq!(rejected, 0);
        assert_eq!(replica.op_count(), 3);
        assert_eq!(replica.entries().len(), 3);
        assert_eq!(replica.next_seq(), 4);
    }

    #[test]
    fn a_shuffled_log_still_rebuilds() {
        let (mut state, _) = state_with_ops(4);
        state.ops.reverse();

        let (replica, rejected) = state.replica();
        assert_eq!(rejected, 0);
        assert_eq!(replica.op_count(), 4);
    }

    #[test]
    fn a_tampered_op_is_rejected_on_load_rather_than_trusted() {
        let (mut state, _) = state_with_ops(2);
        state.ops[1].payload = "swapped by someone with write access".into();

        let (replica, rejected) = state.replica();
        assert_eq!(rejected, 1);
        assert_eq!(replica.op_count(), 1);
    }

    #[test]
    fn ops_from_a_device_no_longer_on_the_roster_are_dropped() {
        let (mut state, _) = state_with_ops(2);
        state.trusted = TrustedDevices::default();

        let (replica, rejected) = state.replica();
        assert_eq!(rejected, 2);
        assert_eq!(replica.op_count(), 0);
    }

    #[test]
    fn a_rewound_log_is_detected() {
        let (state, _) = state_with_ops(3);
        let (replica, _) = state.replica();
        assert!(!state.log_rewound(&replica));

        // The state file says we published 3, the log only has 1: a restore.
        let restored = SyncState { ops: state.ops[..1].to_vec(), ..state };
        let (replica, _) = restored.replica();
        assert!(restored.log_rewound(&replica));
    }

    #[test]
    fn a_fresh_state_is_not_mistaken_for_a_rewind() {
        let state = SyncState::default();
        let (replica, _) = state.replica();
        assert!(!state.log_rewound(&replica));
    }

    #[test]
    fn state_round_trips_through_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync-state.json");
        let (state, _) = state_with_ops(2);

        state.save(&path).unwrap();
        let loaded = SyncState::load(&path).unwrap();

        assert_eq!(loaded.device, state.device);
        assert_eq!(loaded.ops.len(), 2);
        assert_eq!(loaded.replica().0.fingerprint(), state.replica().0.fingerprint());
    }

    #[cfg(unix)]
    #[test]
    fn the_state_file_is_not_readable_by_anyone_else() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync-state.json");
        state_with_ops(1).0.save(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_missing_file_starts_empty_but_a_corrupt_one_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.json");
        assert_eq!(SyncState::load(&missing).unwrap().ops.len(), 0);

        let corrupt = dir.path().join("corrupt.json");
        std::fs::write(&corrupt, b"{ this is not json").unwrap();
        assert!(
            SyncState::load(&corrupt).is_err(),
            "a corrupt op-log must not be silently replaced with an empty one"
        );
    }

    #[test]
    fn trust_is_granted_to_the_key_across_epochs() {
        let (state, identity) = state_with_ops(1);

        assert!(state.trusted.contains(&identity.fingerprint()));
        assert!(state.trusted.contains(fingerprint_of(&device_id(&identity.fingerprint(), 999))));
        assert!(!state.trusted.contains("someone-else"));
    }

    #[test]
    fn a_device_label_falls_back_to_its_fingerprint() {
        let (_, roster) = identity_and_roster("laptop");
        assert_eq!(roster.label("unknown-fingerprint"), "unknown-fingerprint");
        assert_eq!(roster.len(), 1);
    }
}
