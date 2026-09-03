//! Memory hardening for secrets held while the vault is unlocked.
//!
//! `zeroize` alone only guarantees a secret is wiped when it's dropped. It
//! does nothing about the two ways a secret leaves the process while it's
//! still alive: the kernel swapping the page to disk, and the kernel writing
//! the page into a core dump. This module closes both, and adds a third
//! layer on top:
//!
//! - [`SecretBuf`] — a fixed-size heap buffer that is `mlock`ed (so it can't
//!   be swapped out), excluded from core dumps where the platform supports
//!   it (`MADV_DONTDUMP` on Linux), and zeroized on drop.
//! - [`Shielded`] — a secret kept *encrypted in RAM* for its whole lifetime
//!   under a per-process key, decrypted only for the moment it's actually
//!   used. A memory dump taken while the process is idle contains
//!   ciphertext, not the secret.
//!
//! This is the same layering goldwarden gets from `memguard`, done with
//! `memsec` (which wraps the same `mlock`/`VirtualLock`/`madvise` calls)
//! plus a `XChaCha20-Poly1305` shield.
//!
//! ## What this does not do
//!
//! Nothing here defends against an attacker who can read this process's
//! memory *while it is running* — they can read the shield key too, and
//! `ptrace` the moment of decryption. It raises the cost of the offline
//! attacks (swap file, hibernation image, core dump, cold boot) that these
//! primitives are actually designed for. See `SECURITY.md`.

use crate::error::{PassError, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use std::sync::OnceLock;
use zeroize::Zeroize;

/// Size of the per-process shield key, and of an XChaCha20 nonce.
const SHIELD_KEY_LEN: usize = 32;
const SHIELD_NONCE_LEN: usize = 24;

/// A fixed-size heap buffer for secret bytes: locked into RAM (never
/// swapped), excluded from core dumps where supported, and zeroized on drop.
///
/// The buffer is allocated once at its final size and never grows — growing
/// would reallocate and leave a copy of the secret behind in the freed
/// block, which is exactly what this type exists to prevent.
pub struct SecretBuf {
    data: Box<[u8]>,
    /// Whether `mlock` actually succeeded. It can legitimately fail on a
    /// system with a low `RLIMIT_MEMLOCK`; we still zeroize on drop, we just
    /// can't promise the page stayed out of swap. See [`SecretBuf::is_locked`].
    locked: bool,
}

impl SecretBuf {
    /// Allocate a zero-filled locked buffer of `len` bytes.
    pub fn zeroed(len: usize) -> Self {
        let mut data = vec![0u8; len].into_boxed_slice();
        let locked = lock_memory(&mut data);
        Self { data, locked }
    }

    /// Copy `bytes` into a locked buffer.
    ///
    /// Note the source `bytes` are *not* wiped — this can only harden the
    /// copy it owns. Prefer building the secret directly into
    /// [`SecretBuf::zeroed`] where the caller controls the producer.
    pub fn from_slice(bytes: &[u8]) -> Self {
        let mut buf = Self::zeroed(bytes.len());
        buf.data.copy_from_slice(bytes);
        buf
    }

    /// Copy a string's bytes into a locked buffer, wiping the original.
    pub fn from_string(mut s: String) -> Self {
        let buf = Self::from_slice(s.as_bytes());
        s.zeroize();
        buf
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Whether the buffer is actually locked into RAM. False means `mlock`
    /// was refused (typically `RLIMIT_MEMLOCK` too low) and the contents
    /// could in principle reach swap.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Interpret the contents as UTF-8. Used for secrets that are really
    /// text (a master password, an SSH key's PEM body).
    pub fn as_str(&self) -> Result<&str> {
        std::str::from_utf8(&self.data)
            .map_err(|_| PassError::SecureMemory("secret is not valid UTF-8".to_string()))
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        self.data.zeroize();
        if self.locked {
            unlock_memory(&mut self.data);
        }
    }
}

impl std::fmt::Debug for SecretBuf {
    /// Deliberately opaque: a stray `{:?}` on a struct holding one of these
    /// must not be what puts a secret in a log file.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBuf([redacted; {} bytes])", self.data.len())
    }
}

impl Clone for SecretBuf {
    fn clone(&self) -> Self {
        Self::from_slice(&self.data)
    }
}

/// A secret held encrypted in RAM, decrypted only while in use.
///
/// The ciphertext lives in an ordinary allocation (there is nothing secret
/// about it); only the per-process shield key sits in locked memory. Call
/// [`Shielded::expose`] to get the plaintext back in a [`SecretBuf`] that
/// wipes itself as soon as the caller drops it.
pub struct Shielded {
    nonce: [u8; SHIELD_NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl Shielded {
    /// Encrypt `secret` under the process shield key.
    pub fn new(secret: &[u8]) -> Result<Self> {
        let mut nonce = [0u8; SHIELD_NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);

        let ciphertext = cipher()?
            .encrypt(XNonce::from_slice(&nonce), secret)
            .map_err(|_| PassError::SecureMemory("failed to shield secret".to_string()))?;

        Ok(Self { nonce, ciphertext })
    }

    /// Shield a string, wiping the original.
    pub fn from_string(mut s: String) -> Result<Self> {
        let shielded = Self::new(s.as_bytes());
        s.zeroize();
        shielded
    }

    /// Decrypt into a locked buffer. The plaintext exists only for as long
    /// as the returned [`SecretBuf`] is alive.
    pub fn expose(&self) -> Result<SecretBuf> {
        let mut plaintext = cipher()?
            .decrypt(XNonce::from_slice(&self.nonce), self.ciphertext.as_ref())
            .map_err(|_| PassError::SecureMemory("failed to unshield secret".to_string()))?;

        let buf = SecretBuf::from_slice(&plaintext);
        plaintext.zeroize();
        Ok(buf)
    }

    /// Decrypt and hand the plaintext to `f` as a `&str`, wiping it
    /// afterwards. The common shape for "unlock the vault with the master
    /// password we're holding" without ever materialising a `String`.
    pub fn with_str<T>(&self, f: impl FnOnce(&str) -> T) -> Result<T> {
        let buf = self.expose()?;
        Ok(f(buf.as_str()?))
    }
}

impl std::fmt::Debug for Shielded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Shielded([encrypted; {} bytes])", self.ciphertext.len())
    }
}

/// The process-lifetime shield key, generated on first use and held in
/// locked memory for as long as the process lives.
fn shield_key() -> &'static SecretBuf {
    static KEY: OnceLock<SecretBuf> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut key = SecretBuf::zeroed(SHIELD_KEY_LEN);
        rand::thread_rng().fill_bytes(key.as_mut_slice());
        key
    })
}

fn cipher() -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(shield_key().as_slice())
        .map_err(|_| PassError::SecureMemory("invalid shield key length".to_string()))
}

/// `mlock` the buffer (and, on Linux, mark it `MADV_DONTDUMP`). Returns
/// whether the lock succeeded — a failure is not fatal, it just means the
/// weaker guarantee applies.
fn lock_memory(data: &mut [u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    // SAFETY: `data` is a live, uniquely-borrowed allocation of exactly
    // `data.len()` bytes, and we `munlock` the same range in `Drop` before
    // the allocation is freed.
    unsafe { memsec::mlock(data.as_mut_ptr(), data.len()) }
}

fn unlock_memory(data: &mut [u8]) {
    if data.is_empty() {
        return;
    }
    // SAFETY: same range that `lock_memory` locked, still live here since
    // `Drop` runs before the box is deallocated.
    unsafe {
        memsec::munlock(data.as_mut_ptr(), data.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_buf_holds_and_exposes_bytes() {
        let buf = SecretBuf::from_slice(b"correct horse battery staple");
        assert_eq!(buf.as_slice(), b"correct horse battery staple");
        assert_eq!(buf.len(), 28);
        assert!(!buf.is_empty());
    }

    #[test]
    fn secret_buf_from_string_roundtrips_as_str() {
        let buf = SecretBuf::from_string("master-password".to_string());
        assert_eq!(buf.as_str().unwrap(), "master-password");
    }

    #[test]
    fn secret_buf_debug_does_not_leak_contents() {
        let buf = SecretBuf::from_slice(b"topsecret");
        let rendered = format!("{:?}", buf);
        assert!(!rendered.contains("topsecret"), "Debug leaked the secret: {rendered}");
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn zero_length_buffer_is_handled() {
        let buf = SecretBuf::zeroed(0);
        assert!(buf.is_empty());
        assert!(buf.is_locked(), "empty buffer needs no lock, treat as locked");
    }

    #[test]
    fn shielded_roundtrips_the_secret() {
        let shielded = Shielded::new(b"vault-master-key").unwrap();
        assert_eq!(shielded.expose().unwrap().as_slice(), b"vault-master-key");
    }

    #[test]
    fn shielded_ciphertext_does_not_contain_the_plaintext() {
        let secret = b"a-very-recognisable-secret-value";
        let shielded = Shielded::new(secret).unwrap();

        // The whole point: what sits in RAM between uses is not the secret.
        assert!(
            !shielded
                .ciphertext
                .windows(secret.len())
                .any(|w| w == secret),
            "plaintext found in the shielded representation"
        );
    }

    #[test]
    fn shielded_with_str_hands_over_the_plaintext() {
        let shielded = Shielded::from_string("hunter2".to_string()).unwrap();
        let len = shielded.with_str(|s| {
            assert_eq!(s, "hunter2");
            s.len()
        });
        assert_eq!(len.unwrap(), 7);
    }

    #[test]
    fn each_shield_uses_a_fresh_nonce() {
        let a = Shielded::new(b"same-secret").unwrap();
        let b = Shielded::new(b"same-secret").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }
}
