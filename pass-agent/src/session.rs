//! The unlocked session the agent holds on the user's behalf.
//!
//! ## What stays in memory, and why
//!
//! The agent does **not** keep the decrypted vault around between requests.
//! It keeps two things:
//!
//! - the master password, [`Shielded`] (encrypted in RAM, decrypted for the
//!   instant a vault is opened);
//! - the SSH keys, each with its private half likewise shielded.
//!
//! Everything else — entries, passwords, TOTP secrets — is read by reopening
//! the vault from disk for that one request and dropping it immediately, so
//! between requests there is no decrypted database in this process at all.
//!
//! SSH keys are the deliberate exception. Opening the vault means running
//! Argon2id at 64 MiB × 10 iterations, which is hundreds of milliseconds by
//! design; paying that on every `git push` would make the agent unusable, and
//! an unusable agent gets replaced by a plaintext `~/.ssh/id_ed25519`, which
//! is the outcome this whole feature exists to avoid. Caching them shielded
//! is the trade that keeps the safer option the convenient one.

use passlib::secmem::Shielded;
use passlib::{PassError, Result, SshKey, Vault};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

/// How long an unlocked session survives without being used.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

pub struct Session {
    vault_path: PathBuf,
    master: Shielded,
    ssh_keys: Vec<SshKey>,
    idle_timeout: Duration,
    last_activity: Instant,
    unlocked_at: SystemTime,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("vault_path", &self.vault_path)
            .field("ssh_keys", &self.ssh_keys.len())
            .field("idle_timeout", &self.idle_timeout)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Unlock `vault_path` and start a session.
    ///
    /// The vault is opened once here — which both validates the password and
    /// loads the SSH keys — and then dropped.
    pub fn unlock(vault_path: &Path, master_password: &str, idle_timeout: Duration) -> Result<Self> {
        let mut vault = Vault::unlock(vault_path, master_password)?;
        let ssh_keys = load_ssh_keys(&mut vault)?;

        Ok(Self {
            vault_path: vault_path.to_path_buf(),
            master: Shielded::new(master_password.as_bytes())?,
            ssh_keys,
            idle_timeout,
            last_activity: Instant::now(),
            unlocked_at: SystemTime::now(),
        })
    }

    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }

    pub fn unlocked_at(&self) -> SystemTime {
        self.unlocked_at
    }

    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// How long until this session auto-locks, if nothing touches it.
    pub fn time_to_lock(&self) -> Duration {
        self.idle_timeout.saturating_sub(self.last_activity.elapsed())
    }

    /// Whether the idle timeout has run out. A zero timeout means "never
    /// auto-lock", for a session the user has deliberately pinned open.
    pub fn is_expired(&self) -> bool {
        !self.idle_timeout.is_zero() && self.last_activity.elapsed() >= self.idle_timeout
    }

    /// Reset the idle countdown.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// The SSH keys this session serves.
    pub fn ssh_keys(&self) -> &[SshKey] {
        &self.ssh_keys
    }

    /// Find the key whose public blob a client asked to sign with.
    ///
    /// Compares the wire-format public blob rather than the fingerprint,
    /// because that is what the client actually sends and what uniquely
    /// identifies a key on the protocol.
    pub fn ssh_key_for_blob(&self, blob: &[u8]) -> Option<&SshKey> {
        self.ssh_keys
            .iter()
            .find(|key| key.public_key_blob().is_ok_and(|k| k == blob))
    }

    /// Open the vault, run `f` against it, and drop it again.
    ///
    /// The decrypted database exists only for the duration of the call. Note
    /// that `f` receives `&mut Vault` and may modify it: persisting is `f`'s
    /// job (via [`Vault::save`]), and [`Session::master_password`] is
    /// available for that.
    pub fn with_vault<T>(&mut self, f: impl FnOnce(&mut Vault, &str) -> Result<T>) -> Result<T> {
        self.touch();
        self.with_vault_untouched(f)
    }

    /// The same, without resetting the idle countdown.
    ///
    /// For work the *agent* initiated rather than the user: the sync loop
    /// reconciles the vault every so often, and if that counted as activity
    /// the vault would never auto-lock again. Auto-lock is a security
    /// property; a background feature must not be able to suspend it.
    pub fn with_vault_untouched<T>(&self, f: impl FnOnce(&mut Vault, &str) -> Result<T>) -> Result<T> {
        let master = self.master.expose()?;
        let password = master.as_str()?;
        let mut vault = Vault::unlock(&self.vault_path, password)?;
        f(&mut vault, password)
    }

    /// Re-read the SSH keys from the vault, after something changed them.
    pub fn reload_ssh_keys(&mut self) -> Result<()> {
        self.ssh_keys = self.with_vault(|vault, _| load_ssh_keys(vault))?;
        Ok(())
    }

    /// Check that `candidate` is this session's master password. Used to
    /// authorise a second client without re-deriving a whole new session.
    pub fn verify_master_password(&self, candidate: &str) -> Result<bool> {
        let master = self.master.expose()?;
        Ok(master.as_str()? == candidate)
    }
}

fn load_ssh_keys(vault: &mut Vault) -> Result<Vec<SshKey>> {
    vault
        .list_ssh_keys()?
        .into_iter()
        .map(|summary| vault.get_ssh_key(&summary.id))
        .collect::<Result<Vec<_>>>()
        .map_err(|e| PassError::SshKey(format!("failed to load SSH keys from the vault: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use passlib::PasswordEntry;

    struct TempVault {
        _dir: tempfile::TempDir,
        path: PathBuf,
    }

    fn new_vault(password: &str) -> TempVault {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        Vault::init(&path, password).unwrap().save(password).unwrap();
        TempVault { _dir: dir, path }
    }

    #[test]
    fn unlock_rejects_a_wrong_password() {
        let vault = new_vault("correct-password");
        assert!(Session::unlock(&vault.path, "wrong-password", DEFAULT_IDLE_TIMEOUT).is_err());
    }

    #[test]
    fn a_session_reads_entries_through_the_vault() {
        let vault = new_vault("pw");
        let mut session = Session::unlock(&vault.path, "pw", DEFAULT_IDLE_TIMEOUT).unwrap();

        session
            .with_vault(|vault, password| {
                vault.add_entry(PasswordEntry::new(
                    "GitHub".to_string(),
                    "https://github.com".to_string(),
                    "me".to_string(),
                    "secret".to_string(),
                ))?;
                vault.save(password)
            })
            .unwrap();

        let entries = session.with_vault(|vault, _| vault.list_entries()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].website, "GitHub");
    }

    #[test]
    fn ssh_keys_are_loaded_at_unlock_and_can_sign() {
        let vault = new_vault("pw");
        {
            let mut v = Vault::unlock(&vault.path, "pw").unwrap();
            v.add_ssh_key(&SshKey::generate("laptop", "me@laptop").unwrap()).unwrap();
            v.save("pw").unwrap();
        }

        let session = Session::unlock(&vault.path, "pw", DEFAULT_IDLE_TIMEOUT).unwrap();
        assert_eq!(session.ssh_keys().len(), 1);

        let key = &session.ssh_keys()[0];
        let blob = key.public_key_blob().unwrap();
        assert!(session.ssh_key_for_blob(&blob).is_some());
        assert!(session.ssh_key_for_blob(b"some other blob").is_none());
    }

    #[test]
    fn reload_picks_up_a_key_added_after_unlock() {
        let vault = new_vault("pw");
        let mut session = Session::unlock(&vault.path, "pw", DEFAULT_IDLE_TIMEOUT).unwrap();
        assert!(session.ssh_keys().is_empty());

        session
            .with_vault(|vault, password| {
                vault.add_ssh_key(&SshKey::generate("new", "c").unwrap())?;
                vault.save(password)
            })
            .unwrap();

        // Not visible until an explicit reload — the cache is the whole point.
        assert!(session.ssh_keys().is_empty());
        session.reload_ssh_keys().unwrap();
        assert_eq!(session.ssh_keys().len(), 1);
    }

    #[test]
    fn a_session_expires_after_its_idle_timeout() {
        let vault = new_vault("pw");
        let session = Session::unlock(&vault.path, "pw", Duration::from_millis(50)).unwrap();

        assert!(!session.is_expired());
        std::thread::sleep(Duration::from_millis(80));
        assert!(session.is_expired());
    }

    #[test]
    fn activity_postpones_expiry() {
        let vault = new_vault("pw");
        let mut session = Session::unlock(&vault.path, "pw", Duration::from_millis(120)).unwrap();

        for _ in 0..3 {
            std::thread::sleep(Duration::from_millis(50));
            session.touch();
            assert!(!session.is_expired(), "a session in use locked itself");
        }
    }

    #[test]
    fn background_vault_access_does_not_postpone_auto_lock() {
        let vault = new_vault("pw");
        let session = Session::unlock(&vault.path, "pw", Duration::from_millis(80)).unwrap();

        std::thread::sleep(Duration::from_millis(50));
        session.with_vault_untouched(|vault, _| vault.list_entries()).unwrap();
        std::thread::sleep(Duration::from_millis(50));

        assert!(
            session.is_expired(),
            "a background sync pass kept an idle vault unlocked"
        );
    }

    #[test]
    fn a_zero_timeout_never_expires() {
        let vault = new_vault("pw");
        let session = Session::unlock(&vault.path, "pw", Duration::ZERO).unwrap();

        std::thread::sleep(Duration::from_millis(20));
        assert!(!session.is_expired());
        assert_eq!(session.time_to_lock(), Duration::ZERO);
    }

    #[test]
    fn the_master_password_can_be_checked_without_being_returned() {
        let vault = new_vault("hunter2");
        let session = Session::unlock(&vault.path, "hunter2", DEFAULT_IDLE_TIMEOUT).unwrap();

        assert!(session.verify_master_password("hunter2").unwrap());
        assert!(!session.verify_master_password("hunter3").unwrap());
    }

    #[test]
    fn debug_does_not_leak_the_master_password() {
        let vault = new_vault("hunter2");
        let session = Session::unlock(&vault.path, "hunter2", DEFAULT_IDLE_TIMEOUT).unwrap();
        assert!(!format!("{session:?}").contains("hunter2"));
    }
}
