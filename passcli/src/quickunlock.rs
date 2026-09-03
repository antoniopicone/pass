//! `pass quick-unlock` — unlock with a short PIN (and optionally a
//! fingerprint) instead of the full master password.
//!
//! ## The problem
//!
//! A master password strong enough to protect a vault is too long to retype
//! every time the agent auto-locks. People respond by disabling auto-lock, or
//! by choosing a weaker master password. Both are worse than what this
//! feature costs.
//!
//! ## The construction
//!
//! The master password is sealed with XChaCha20-Poly1305 under a key derived
//! from the PIN with Argon2id, and the sealed blob is written to a `0600`
//! file. Unlocking asks for the PIN, re-derives the key, and opens the blob.
//! The PIN itself is never stored, and the file alone is useless without it.
//!
//! ## Two attacks, two defences
//!
//! - **Someone at your keyboard guessing PINs.** Every failure is counted in
//!   the file itself; after [`MAX_FAILURES`] the blob is deleted and the
//!   master password is the only way back in.
//! - **Someone who copied the file and guesses offline.** No counter can help
//!   there, only the cost of each guess. Argon2id at 64 MiB makes a guess
//!   expensive, but a 4-digit PIN is still only 10 000 guesses — which is why
//!   [`MIN_PIN_LENGTH`] is enforced and a numeric PIN is called out as the
//!   weak choice it is.
//!
//! ## Biometrics
//!
//! `--verify-command` runs a local authentication command (`fprintd-verify`
//! on Linux with a fingerprint reader, or anything else that exits 0 only on
//! success) *before* the PIN is accepted. It is a second factor, not a
//! replacement: a fingerprint cannot derive a key, so something the user
//! knows still has to unseal the blob. Replacing the PIN entirely would mean
//! storing the master password where the OS can hand it back after a
//! biometric check, which on Linux means trusting the login keyring rather
//! than any hardware — strictly weaker, and not what this does.

use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Shortest PIN we will accept. Six characters of *mixed* input is around 35
/// bits; six digits is under 20, which Argon2id slows down but does not save.
pub const MIN_PIN_LENGTH: usize = 6;

/// Wrong PINs tolerated before the sealed master password is destroyed.
pub const MAX_FAILURES: u32 = 5;

/// Argon2id cost for the PIN. Higher than the vault's own KDF on purpose:
/// this key protects a much smaller secret space, so each guess has to cost
/// more to compensate.
const ARGON2_MEMORY_KIB: u32 = 128 * 1024;
const ARGON2_ITERATIONS: u32 = 12;
const ARGON2_PARALLELISM: u32 = 4;

const FORMAT_VERSION: u8 = 1;

/// The on-disk record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickUnlock {
    v: u8,
    /// Vault this record unlocks, so a stale record for another vault is
    /// noticed rather than silently failing to decrypt.
    vault: PathBuf,
    salt: String,
    nonce: String,
    ciphertext: String,
    /// Optional local-authentication command run before the PIN is accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verify_command: Option<Vec<String>>,
    /// Consecutive wrong PINs so far.
    #[serde(default)]
    failures: u32,
}

impl QuickUnlock {
    /// Seal `master_password` under `pin`.
    pub fn seal(vault: &Path, master_password: &str, pin: &str, verify_command: Option<Vec<String>>) -> Result<Self> {
        validate_pin(pin)?;

        let mut salt = [0u8; 32];
        let mut nonce = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce);

        let mut key = derive_key(pin, &salt)?;
        let aad = associated_data(vault, &salt);

        let ciphertext = XChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| anyhow::anyhow!("invalid quick-unlock key"))?
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: master_password.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("failed to seal the master password"))?;
        key.zeroize();

        Ok(Self {
            v: FORMAT_VERSION,
            vault: vault.to_path_buf(),
            salt: BASE64.encode(salt),
            nonce: BASE64.encode(nonce),
            ciphertext: BASE64.encode(&ciphertext),
            verify_command,
            failures: 0,
        })
    }

    /// Open the record with `pin`, returning the master password.
    ///
    /// On success the failure counter resets; on failure it advances, and the
    /// caller is told whether the record has now been destroyed.
    pub fn open(&mut self, pin: &str) -> std::result::Result<String, OpenError> {
        if self.v != FORMAT_VERSION {
            return Err(OpenError::Unsupported(self.v));
        }

        let salt = BASE64.decode(&self.salt).map_err(|_| OpenError::Corrupt)?;
        let nonce: [u8; 24] = BASE64
            .decode(&self.nonce)
            .map_err(|_| OpenError::Corrupt)?
            .try_into()
            .map_err(|_| OpenError::Corrupt)?;
        let ciphertext = BASE64.decode(&self.ciphertext).map_err(|_| OpenError::Corrupt)?;

        let mut key = derive_key(pin, &salt).map_err(|_| OpenError::Corrupt)?;
        let aad = associated_data(&self.vault, &salt);

        let opened = XChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| OpenError::Corrupt)?
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            );
        key.zeroize();

        match opened {
            Ok(mut plaintext) => {
                self.failures = 0;
                let password = String::from_utf8(plaintext.clone()).map_err(|_| OpenError::Corrupt)?;
                plaintext.zeroize();
                Ok(password)
            }
            Err(_) => {
                self.failures += 1;
                let remaining = MAX_FAILURES.saturating_sub(self.failures);
                Err(OpenError::WrongPin { remaining })
            }
        }
    }

    pub fn vault(&self) -> &Path {
        &self.vault
    }

    pub fn verify_command(&self) -> Option<&[String]> {
        self.verify_command.as_deref()
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// Whether too many wrong PINs have been tried and the record must go.
    pub fn is_burned(&self) -> bool {
        self.failures >= MAX_FAILURES
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("wrong PIN ({remaining} attempt(s) left before quick unlock is disabled)")]
    WrongPin { remaining: u32 },

    #[error("the quick-unlock record is corrupt; disable and re-enable it")]
    Corrupt,

    #[error("quick-unlock record format v{0} is not supported by this version of pass")]
    Unsupported(u8),
}

fn validate_pin(pin: &str) -> Result<()> {
    if pin.chars().count() < MIN_PIN_LENGTH {
        anyhow::bail!("PIN must be at least {MIN_PIN_LENGTH} characters long");
    }
    Ok(())
}

/// Whether a PIN is all digits — allowed, but worth warning about, since it
/// collapses the offline search space to 10^n.
pub fn is_numeric_pin(pin: &str) -> bool {
    !pin.is_empty() && pin.chars().all(|c| c.is_ascii_digit())
}

fn derive_key(pin: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_PARALLELISM, Some(32))
        .map_err(|e| anyhow::anyhow!("invalid Argon2 parameters: {e}"))?;

    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pin.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("failed to derive the quick-unlock key: {e}"))?;
    Ok(key)
}

/// Bind the record to its vault path and salt, so a record cannot be moved
/// onto a different vault or have its salt swapped without the tag failing.
fn associated_data(vault: &Path, salt: &[u8]) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.push(FORMAT_VERSION);
    aad.extend_from_slice(vault.to_string_lossy().as_bytes());
    aad.extend_from_slice(salt);
    aad
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

/// Where the record lives: `$XDG_CONFIG_HOME/pass/quick-unlock.json`, or the
/// platform equivalent.
pub fn record_path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("PASS_QUICK_UNLOCK_FILE") {
        return Ok(PathBuf::from(path));
    }

    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .ok_or_else(|| anyhow::anyhow!("cannot locate a config directory: neither XDG_CONFIG_HOME nor HOME is set"))?;
            home.join(".config")
        }
    };

    Ok(base.join("pass").join("quick-unlock.json"))
}

pub fn load(path: &Path) -> Result<Option<QuickUnlock>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(
            serde_json::from_str(&text).context("quick-unlock record is not valid JSON")?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("failed to read {}", path.display())),
    }
}

pub fn store(path: &Path, record: &QuickUnlock) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let json = serde_json::to_string_pretty(record).context("failed to encode quick-unlock record")?;
    write_private(path, json.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

pub fn remove(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("failed to remove {}", path.display())),
    }
}

/// Write owner-only, creating the file with the right mode rather than
/// widening it and narrowing it afterwards.
fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    // Write to a temporary file and rename, so an interrupted write cannot
    // leave a truncated record that locks the user out of quick unlock.
    let temp = path.with_extension("json.tmp");

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(&temp)?;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);

    std::fs::rename(&temp, path)
}

/// Run a local-authentication command; success is exit status 0.
pub fn run_verify_command(command: &[String]) -> Result<bool> {
    let Some((program, args)) = command.split_first() else {
        anyhow::bail!("empty verify command");
    };

    let status = std::process::Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("failed to run the verify command `{program}`"))?;

    Ok(status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAULT: &str = "/home/me/passwords.kdbx";

    fn seal(pin: &str) -> QuickUnlock {
        QuickUnlock::seal(Path::new(VAULT), "the-real-master-password", pin, None).unwrap()
    }

    #[test]
    fn the_right_pin_returns_the_master_password() {
        let mut record = seal("correct-pin");
        assert_eq!(record.open("correct-pin").unwrap(), "the-real-master-password");
    }

    #[test]
    fn the_sealed_record_does_not_contain_the_master_password() {
        let record = seal("correct-pin");
        let json = serde_json::to_string(&record).unwrap();
        assert!(
            !json.contains("the-real-master-password"),
            "master password found in the record: {json}"
        );
    }

    #[test]
    fn a_wrong_pin_is_refused_and_counted() {
        let mut record = seal("correct-pin");

        match record.open("wrong-pin").unwrap_err() {
            OpenError::WrongPin { remaining } => assert_eq!(remaining, MAX_FAILURES - 1),
            other => panic!("unexpected error: {other}"),
        }
        assert_eq!(record.failures(), 1);
    }

    #[test]
    fn a_correct_pin_clears_earlier_failures() {
        let mut record = seal("correct-pin");
        let _ = record.open("wrong");
        let _ = record.open("wrong");
        assert_eq!(record.failures(), 2);

        record.open("correct-pin").unwrap();
        assert_eq!(record.failures(), 0, "a success must reset the counter");
    }

    #[test]
    fn repeated_failures_burn_the_record() {
        let mut record = seal("correct-pin");

        for _ in 0..MAX_FAILURES {
            assert!(!record.is_burned());
            let _ = record.open("wrong");
        }

        assert!(record.is_burned(), "the record should be destroyed after {MAX_FAILURES} failures");
    }

    #[test]
    fn a_record_cannot_be_moved_onto_another_vault() {
        // Without the vault path in the AAD, copying this file next to a
        // different vault would still decrypt, and the PIN would appear to
        // unlock a vault it was never set up for.
        let mut record = seal("correct-pin");
        record.vault = PathBuf::from("/home/me/other.kdbx");

        assert!(matches!(
            record.open("correct-pin").unwrap_err(),
            OpenError::WrongPin { .. }
        ));
    }

    #[test]
    fn tampering_with_the_salt_is_detected() {
        let mut record = seal("correct-pin");
        let mut salt = BASE64.decode(&record.salt).unwrap();
        salt[0] ^= 0xff;
        record.salt = BASE64.encode(&salt);

        assert!(record.open("correct-pin").is_err());
    }

    #[test]
    fn short_pins_are_rejected() {
        let short = "12345";
        assert_eq!(short.len(), MIN_PIN_LENGTH - 1);
        assert!(QuickUnlock::seal(Path::new(VAULT), "master", short, None).is_err());
        assert!(QuickUnlock::seal(Path::new(VAULT), "master", "123456", None).is_ok());
    }

    #[test]
    fn numeric_pins_are_recognised_so_they_can_be_warned_about() {
        assert!(is_numeric_pin("123456"));
        assert!(!is_numeric_pin("12345a"));
        assert!(!is_numeric_pin(""));
    }

    #[test]
    fn future_formats_are_rejected_clearly() {
        let mut record = seal("correct-pin");
        record.v = 99;
        assert!(matches!(record.open("correct-pin").unwrap_err(), OpenError::Unsupported(99)));
    }

    #[test]
    fn records_roundtrip_through_a_private_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("quick-unlock.json");

        assert!(load(&path).unwrap().is_none(), "a missing file is not an error");

        let record = QuickUnlock::seal(Path::new(VAULT), "master", "correct-pin", Some(vec!["true".into()])).unwrap();
        store(&path, &record).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "quick-unlock record is not 0600");
        }

        let mut loaded = load(&path).unwrap().unwrap();
        assert_eq!(loaded.verify_command(), Some(&["true".to_string()][..]));
        assert_eq!(loaded.open("correct-pin").unwrap(), "master");

        remove(&path).unwrap();
        assert!(load(&path).unwrap().is_none());
        remove(&path).unwrap(); // removing twice is not an error
    }

    #[test]
    fn a_verify_command_gates_on_its_exit_status() {
        assert!(run_verify_command(&["true".to_string()]).unwrap());
        assert!(!run_verify_command(&["false".to_string()]).unwrap());
        assert!(run_verify_command(&["this-command-does-not-exist-anywhere".to_string()]).is_err());
        assert!(run_verify_command(&[]).is_err());
    }

    #[test]
    fn each_record_uses_a_fresh_salt_and_nonce() {
        let first = seal("same-pin");
        let second = seal("same-pin");
        assert_ne!(first.salt, second.salt);
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
    }
}
