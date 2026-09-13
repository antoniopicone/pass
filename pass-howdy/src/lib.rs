//! Linux "unlock with your face" via [howdy](https://github.com/boltgolt/howdy)
//! — the Linux counterpart to `pass-apple`'s `BiometricUnlock.swift` (Face
//! ID/Touch ID). Howdy only recognizes a face; it derives no key. So,
//! exactly like the Apple side, the actual master password is stored
//! (once the user opts in) in the OS keyring (secret-service —
//! GNOME Keyring/KWallet, via the `keyring` crate), and a successful howdy
//! face match is what gates *retrieving* it — never the vault's
//! encryption directly. That's a real, deliberate trade-off, the same one
//! already accepted for Face ID/Touch ID: the master password exists at
//! rest in the keyring, protected by whatever the keyring itself
//! provides, rather than never existing on disk at all. A user who
//! doesn't opt in is unaffected — the master password prompt works
//! exactly as before.
//!
//! # The isolated PAM service
//!
//! Authentication runs against a PAM service named `pass-howdy`
//! (`/etc/pam.d/pass-howdy`, installed by the repo's top-level
//! `install.sh` — see `pass-howdy/pass-howdy.pam`), deliberately its own
//! service file rather than piggybacking on `sudo`/`login`: it's
//! configured to succeed via `pam_howdy.so` alone and deny otherwise, so
//! it never touches or depends on the system's existing password/2FA
//! stack, and a failed face match never falls back to asking for a system
//! password on our behalf (see [`unlock_with_face`], which uses PAM's
//! "null" conversation handler for exactly this reason — it errors out
//! rather than prompting for anything).
//!
//! Used by `passcli`, `pass-gnome`, and (via `pass-native-host`) the
//! Chromium extension — all three just call [`is_available_for`] to
//! decide whether to show a "Unlock with your face" option, [`can_enroll`]
//! /[`store_password`] to offer enabling it after a normal unlock, and
//! [`unlock_with_face`] to actually use it.

use keyring::Entry;
use pam_client::conv_null::Conversation;
use pam_client::{Context, Flag};
use std::path::{Path, PathBuf};

const KEYRING_SERVICE: &str = "pass";
const PAM_SERVICE: &str = "pass-howdy";
const PAM_SERVICE_FILE: &str = "/etc/pam.d/pass-howdy";

#[derive(Debug, thiserror::Error)]
pub enum HowdyError {
    #[error("face authentication failed: {0}")]
    Authentication(#[from] pam_client::Error),
    #[error("could not access the system keyring: {0}")]
    Keyring(#[from] keyring::Error),
    #[error("could not determine the current username ($USER is not set)")]
    NoUsername,
}

pub type Result<T> = std::result::Result<T, HowdyError>;

/// Whether howdy itself looks installed on this machine (the `howdy` CLI
/// and its PAM module both present) — independent of whether the
/// dedicated `pass-howdy` PAM service has been set up (see
/// [`is_configured`]). A quick, cheap filesystem check; safe to call often
/// (e.g. every time a locked-vault screen renders).
pub fn is_installed() -> bool {
    Path::new("/usr/bin/howdy").exists() && find_howdy_pam_module().is_some()
}

/// Debian/Ubuntu (and derivatives) ship PAM modules under an
/// architecture-specific multiarch directory; check the common ones
/// rather than hardcoding one, plus the non-multiarch fallbacks other
/// distros use.
fn find_howdy_pam_module() -> Option<PathBuf> {
    const CANDIDATES: &[&str] = &[
        "/usr/lib/x86_64-linux-gnu/security/pam_howdy.so",
        "/usr/lib/aarch64-linux-gnu/security/pam_howdy.so",
        "/usr/lib/i386-linux-gnu/security/pam_howdy.so",
        "/usr/lib64/security/pam_howdy.so",
        "/usr/lib/security/pam_howdy.so",
        "/lib/security/pam_howdy.so",
    ];
    CANDIDATES.iter().map(PathBuf::from).find(|p| p.exists())
}

/// Whether the dedicated `pass-howdy` PAM service (see the module doc
/// comment) has been installed — normally done once by the repo's
/// `install.sh`, which needs `sudo` for this one step since PAM service
/// files live under `/etc/pam.d/`.
pub fn is_configured() -> bool {
    Path::new(PAM_SERVICE_FILE).exists()
}

/// Whether "unlock with your face" can be *offered* for `vault_path` right
/// now: howdy installed, the PAM service configured, and a master
/// password already stored for this exact vault (see [`store_password`]).
pub fn is_available_for(vault_path: &Path) -> bool {
    is_installed() && is_configured() && has_stored_password(vault_path)
}

/// Whether enabling face unlock could be *offered* at all (howdy installed
/// and configured) — used right after a normal master-password unlock to
/// decide whether to show an "enable face unlock?" prompt, independent of
/// whether this particular vault has already opted in.
pub fn can_enroll() -> bool {
    is_installed() && is_configured()
}

fn entry_for(vault_path: &Path) -> Result<Entry> {
    Ok(Entry::new(KEYRING_SERVICE, &vault_path.to_string_lossy())?)
}

/// Whether a master password is already stored in the keyring for this
/// exact vault path.
pub fn has_stored_password(vault_path: &Path) -> bool {
    entry_for(vault_path).and_then(|e| Ok(e.get_password()?)).is_ok()
}

/// Stores `master_password` in the OS keyring for `vault_path`, enabling
/// face unlock for it from now on. See the module doc comment for the
/// trade-off this accepts.
pub fn store_password(vault_path: &Path, master_password: &str) -> Result<()> {
    Ok(entry_for(vault_path)?.set_password(master_password)?)
}

/// Removes the stored master password for `vault_path`, disabling face
/// unlock for it.
pub fn forget_password(vault_path: &Path) -> Result<()> {
    Ok(entry_for(vault_path)?.delete_credential()?)
}

/// Authenticates the current user via howdy (PAM service `pass-howdy`,
/// see the module doc comment) and, only on success, returns the master
/// password stored for `vault_path`. Uses PAM's "null" conversation
/// handler deliberately: `pass-howdy` should never need to prompt for
/// anything (it's configured to succeed via face match alone and deny
/// otherwise — see `pass-howdy.pam`), so any unexpected prompt is treated
/// as a failure rather than risking this silently falling back to asking
/// the system password on our behalf.
pub fn unlock_with_face(vault_path: &Path) -> Result<String> {
    let username = std::env::var("USER").map_err(|_| HowdyError::NoUsername)?;
    let mut context = Context::new(PAM_SERVICE, Some(&username), Conversation::new())?;
    context.authenticate(Flag::NONE)?;
    Ok(entry_for(vault_path)?.get_password()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exercises the real OS keyring (secret-service) — there's no
    /// sensible way to mock it for a crate whose entire purpose is
    /// talking to it, so this is a genuine integration check rather than
    /// a unit test. Needs a running secret-service provider (GNOME
    /// Keyring/KWallet), which any normal Linux desktop session has but a
    /// bare headless CI runner might not — acceptable for a crate that's
    /// inherently Linux-desktop-only.
    #[test]
    fn store_get_forget_password_roundtrips_through_the_real_keyring() {
        let vault_path = Path::new("/tmp/pass-howdy-test-vault-does-not-exist.kdbx");

        // Clean slate, in case a previous run of this test panicked before
        // reaching its own cleanup.
        let _ = forget_password(vault_path);
        assert!(!has_stored_password(vault_path));

        store_password(vault_path, "correct horse battery staple").unwrap();
        assert!(has_stored_password(vault_path));

        let entry = entry_for(vault_path).unwrap();
        assert_eq!(entry.get_password().unwrap(), "correct horse battery staple");

        forget_password(vault_path).unwrap();
        assert!(!has_stored_password(vault_path));
    }
}
