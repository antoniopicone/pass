//! Sharing entries between people, with no server in the middle.
//!
//! Bitwarden-style sharing needs an organisation on a server: the server
//! decides who is in a collection and hands out the wrapped keys. `pass` has
//! no server, so sharing here is a *file* — a self-contained, armored bundle
//! sealed to one recipient's public key, which travels over whatever channel
//! the two people already trust (Signal, email, a USB stick, a shared
//! folder). The channel does not have to be confidential: the bundle is
//! useless to anyone but the recipient.
//!
//! ## Construction
//!
//! Each recipient has a long-lived X25519 [`ShareIdentity`]; its public half
//! is a short string they publish once. Sealing a bundle does two
//! Diffie-Hellman exchanges and mixes both into one key:
//!
//! - `ephemeral × recipient` — a fresh keypair per bundle, so compromising
//!   the sender's identity key later does not decrypt bundles already sent
//! - `sender × recipient` — binds the bundle to the sender's identity, so
//!   the recipient learns *who* shared with them rather than accepting an
//!   anonymous bundle from anybody who knows their public key
//!
//! The payload is then encrypted with XChaCha20-Poly1305, with the bundle
//! header as associated data so none of the public fields can be swapped out
//! without the tag failing.
//!
//! ## What this is not
//!
//! There is no revocation, and there cannot be: once someone holds a
//! password, taking it back means rotating the password, not deleting a
//! file. Bundles are point-in-time copies, not a live shared collection. See
//! `docs/SYNC_STRATEGY.md`.

use crate::entry::PasswordEntry;
use crate::error::{PassError, Result};
use crate::secmem::Shielded;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

const BUNDLE_VERSION: u8 = 1;
const BUNDLE_ALGORITHM: &str = "x25519-xchacha20poly1305";
const KDF_CONTEXT: &[u8] = b"pass-share-v1";
const PUBLIC_KEY_PREFIX: &str = "pass-share-pk1:";
const ARMOR_BEGIN: &str = "-----BEGIN PASS SHARE-----";
const ARMOR_END: &str = "-----END PASS SHARE-----";

/// A long-lived sharing identity: the keypair someone is known by when
/// entries are shared with them.
///
/// The private half is [`Shielded`], like everything else secret in this
/// crate; the public half is a plain 32-byte value meant to be published.
pub struct ShareIdentity {
    /// Human-readable name for this identity ("Antonio's laptop", "Marta").
    pub label: String,
    public: [u8; 32],
    secret: Shielded,
}

impl std::fmt::Debug for ShareIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShareIdentity")
            .field("label", &self.label)
            .field("public_key", &self.public_key_string())
            .field("secret", &"[shielded]")
            .finish()
    }
}

impl ShareIdentity {
    /// Create a new identity with a fresh keypair.
    pub fn generate(label: &str) -> Result<Self> {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        Self::from_secret(label, secret)
    }

    /// Rebuild an identity from its stored 32-byte private key.
    pub fn from_secret_bytes(label: &str, bytes: &[u8]) -> Result<Self> {
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| PassError::Share("a sharing private key must be exactly 32 bytes".to_string()))?;
        Self::from_secret(label, StaticSecret::from(array))
    }

    fn from_secret(label: &str, secret: StaticSecret) -> Result<Self> {
        let public = PublicKey::from(&secret).to_bytes();
        let mut bytes = secret.to_bytes();
        let shielded = Shielded::new(&bytes)?;
        bytes.zeroize();

        Ok(Self {
            label: label.to_string(),
            public,
            secret: shielded,
        })
    }

    /// The raw public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// The public key as the short string to hand to whoever wants to share
    /// with this identity.
    pub fn public_key_string(&self) -> String {
        format!("{PUBLIC_KEY_PREFIX}{}", BASE64.encode(self.public))
    }

    /// The private key, for writing into the vault. Kept out of `Debug` and
    /// returned only on an explicit call.
    pub fn secret_key_bytes(&self) -> Result<[u8; 32]> {
        let exposed = self.secret.expose()?;
        exposed
            .as_slice()
            .try_into()
            .map_err(|_| PassError::Share("stored sharing key has the wrong length".to_string()))
    }

    fn static_secret(&self) -> Result<StaticSecret> {
        Ok(StaticSecret::from(self.secret_key_bytes()?))
    }
}

/// Parse a `pass-share-pk1:…` public key string.
pub fn parse_public_key(text: &str) -> Result<[u8; 32]> {
    let encoded = text
        .trim()
        .strip_prefix(PUBLIC_KEY_PREFIX)
        .ok_or_else(|| PassError::Share(format!("not a sharing public key (expected a {PUBLIC_KEY_PREFIX}… string)")))?;

    let bytes = BASE64
        .decode(encoded)
        .map_err(|_| PassError::Share("sharing public key is not valid base64".to_string()))?;

    bytes
        .try_into()
        .map_err(|_| PassError::Share("sharing public key has the wrong length".to_string()))
}

/// One entry as it travels inside a bundle.
///
/// Deliberately a flat, self-describing copy rather than a `PasswordEntry`:
/// the recipient's vault gives it a new UUID and its own timestamps, because
/// a shared entry is a *copy* landing in someone else's vault, not the same
/// object syncing between two devices.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SharedEntry {
    pub website: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub username: String,
    pub password: String,
    /// `otpauth://` URI, if the entry carried an MFA secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp_uri: Option<String>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub additional_urls: Vec<String>,
}

impl From<&PasswordEntry> for SharedEntry {
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

impl SharedEntry {
    /// Turn a received entry into one ready to add to the recipient's vault.
    pub fn into_password_entry(self) -> Result<PasswordEntry> {
        let mut entry = PasswordEntry::new(self.website, self.url, self.username, self.password);
        entry.notes = self.notes;
        entry.additional_urls = self.additional_urls;
        if let Some(uri) = self.totp_uri {
            entry.totp = Some(crate::totp::parse_otpauth_uri(&uri)?);
        }
        Ok(entry)
    }
}

/// A sealed bundle of shared entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareBundle {
    /// Format version, so a future change can be rejected clearly rather
    /// than misparsed.
    pub v: u8,
    /// Which construction sealed this bundle.
    pub alg: String,
    /// Sender's identity public key (base64).
    pub sender: String,
    /// Per-bundle ephemeral public key (base64).
    pub ephemeral: String,
    /// Recipient's public key (base64) — lets a recipient holding several
    /// identities pick the right one, and lets everyone else see at a glance
    /// that a bundle isn't theirs.
    pub recipient: String,
    /// XChaCha20 nonce (base64).
    pub nonce: String,
    /// Encrypted payload (base64).
    pub ciphertext: String,
}

impl ShareBundle {
    /// Seal `entries` for `recipient_public`, from `sender`.
    pub fn seal(entries: &[SharedEntry], sender: &ShareIdentity, recipient_public: [u8; 32]) -> Result<Self> {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use chacha20poly1305::{XChaCha20Poly1305, XNonce};
        use rand::RngCore;

        let recipient = PublicKey::from(recipient_public);
        let ephemeral_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret).to_bytes();

        let dh_ephemeral = ephemeral_secret.diffie_hellman(&recipient);
        let dh_static = sender.static_secret()?.diffie_hellman(&recipient);

        let mut nonce = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut nonce);

        let mut key = derive_key(
            &ephemeral_public,
            &sender.public,
            &recipient_public,
            dh_ephemeral.as_bytes(),
            dh_static.as_bytes(),
        );

        let mut plaintext = serde_json::to_vec(entries)
            .map_err(|e| PassError::Share(format!("failed to serialise entries: {e}")))?;

        let aad = associated_data(&sender.public, &ephemeral_public, &recipient_public, &nonce);
        let cipher = XChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| PassError::Share("invalid bundle key".to_string()))?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| PassError::Share("failed to seal bundle".to_string()))?;

        key.zeroize();
        plaintext.zeroize();

        Ok(Self {
            v: BUNDLE_VERSION,
            alg: BUNDLE_ALGORITHM.to_string(),
            sender: BASE64.encode(sender.public),
            ephemeral: BASE64.encode(ephemeral_public),
            recipient: BASE64.encode(recipient_public),
            nonce: BASE64.encode(nonce),
            ciphertext: BASE64.encode(&ciphertext),
        })
    }

    /// Open a bundle addressed to `recipient`, returning the sender's public
    /// key alongside the entries so the caller can show *who* this came from.
    pub fn open(&self, recipient: &ShareIdentity) -> Result<(String, Vec<SharedEntry>)> {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use chacha20poly1305::{XChaCha20Poly1305, XNonce};

        if self.v != BUNDLE_VERSION {
            return Err(PassError::Share(format!(
                "bundle format version {} is not supported by this version of pass",
                self.v
            )));
        }
        if self.alg != BUNDLE_ALGORITHM {
            return Err(PassError::Share(format!("unsupported bundle algorithm: {}", self.alg)));
        }

        let sender_public = decode_key(&self.sender, "sender key")?;
        let ephemeral_public = decode_key(&self.ephemeral, "ephemeral key")?;
        let recipient_public = decode_key(&self.recipient, "recipient key")?;
        let nonce: [u8; 24] = BASE64
            .decode(&self.nonce)
            .map_err(|_| PassError::Share("nonce is not valid base64".to_string()))?
            .try_into()
            .map_err(|_| PassError::Share("nonce has the wrong length".to_string()))?;
        let ciphertext = BASE64
            .decode(&self.ciphertext)
            .map_err(|_| PassError::Share("ciphertext is not valid base64".to_string()))?;

        if recipient_public != recipient.public {
            return Err(PassError::Share(format!(
                "this bundle is sealed to a different identity ({})",
                format_args!("{PUBLIC_KEY_PREFIX}{}", self.recipient)
            )));
        }

        let secret = recipient.static_secret()?;
        let dh_ephemeral = secret.diffie_hellman(&PublicKey::from(ephemeral_public));
        let dh_static = secret.diffie_hellman(&PublicKey::from(sender_public));

        let mut key = derive_key(
            &ephemeral_public,
            &sender_public,
            &recipient_public,
            dh_ephemeral.as_bytes(),
            dh_static.as_bytes(),
        );

        let aad = associated_data(&sender_public, &ephemeral_public, &recipient_public, &nonce);
        let cipher = XChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| PassError::Share("invalid bundle key".to_string()))?;
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                PassError::Share(
                    "could not open this bundle: it was not sealed for this identity, or it has been tampered with"
                        .to_string(),
                )
            })?;
        key.zeroize();

        let entries: Vec<SharedEntry> = serde_json::from_slice(&plaintext)
            .map_err(|e| PassError::Share(format!("bundle payload is malformed: {e}")))?;

        Ok((format!("{PUBLIC_KEY_PREFIX}{}", self.sender), entries))
    }

    /// Render as the armored text form that actually gets sent to someone.
    pub fn to_armored(&self) -> Result<String> {
        let json = serde_json::to_vec(self).map_err(|e| PassError::Share(format!("failed to encode bundle: {e}")))?;
        let body = BASE64.encode(&json);

        let mut out = String::from(ARMOR_BEGIN);
        out.push('\n');
        for chunk in body.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
            out.push('\n');
        }
        out.push_str(ARMOR_END);
        out.push('\n');
        Ok(out)
    }

    /// Parse the armored text form, ignoring anything before/after the
    /// markers so a bundle pasted into the middle of an email still works.
    pub fn from_armored(text: &str) -> Result<Self> {
        let start = text
            .find(ARMOR_BEGIN)
            .ok_or_else(|| PassError::Share("no PASS SHARE block found in this text".to_string()))?
            + ARMOR_BEGIN.len();
        let end = text[start..]
            .find(ARMOR_END)
            .ok_or_else(|| PassError::Share("PASS SHARE block is missing its end marker".to_string()))?
            + start;

        let body: String = text[start..end].chars().filter(|c| !c.is_whitespace()).collect();
        let json = BASE64
            .decode(body)
            .map_err(|_| PassError::Share("PASS SHARE block is not valid base64".to_string()))?;

        serde_json::from_slice(&json).map_err(|e| PassError::Share(format!("malformed bundle: {e}")))
    }
}

/// Mix both Diffie-Hellman outputs and all three public keys into one key.
///
/// Binding the public keys in (not just the shared secrets) is what stops an
/// attacker from re-addressing a bundle: change any of them and the derived
/// key changes, so the AEAD tag fails.
fn derive_key(
    ephemeral_public: &[u8; 32],
    sender_public: &[u8; 32],
    recipient_public: &[u8; 32],
    dh_ephemeral: &[u8; 32],
    dh_static: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KDF_CONTEXT);
    hasher.update(ephemeral_public);
    hasher.update(sender_public);
    hasher.update(recipient_public);
    hasher.update(dh_ephemeral);
    hasher.update(dh_static);
    hasher.finalize().into()
}

/// Associated data: the bundle's public header, so it is authenticated even
/// though it is not encrypted.
fn associated_data(
    sender_public: &[u8; 32],
    ephemeral_public: &[u8; 32],
    recipient_public: &[u8; 32],
    nonce: &[u8; 24],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + BUNDLE_ALGORITHM.len() + 32 * 3 + 24);
    aad.push(BUNDLE_VERSION);
    aad.extend_from_slice(BUNDLE_ALGORITHM.as_bytes());
    aad.extend_from_slice(sender_public);
    aad.extend_from_slice(ephemeral_public);
    aad.extend_from_slice(recipient_public);
    aad.extend_from_slice(nonce);
    aad
}

fn decode_key(encoded: &str, what: &str) -> Result<[u8; 32]> {
    BASE64
        .decode(encoded)
        .map_err(|_| PassError::Share(format!("{what} is not valid base64")))?
        .try_into()
        .map_err(|_| PassError::Share(format!("{what} has the wrong length")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entries() -> Vec<SharedEntry> {
        vec![SharedEntry {
            website: "Netflix".to_string(),
            url: "https://netflix.com".to_string(),
            username: "family@example.com".to_string(),
            password: "the-shared-password".to_string(),
            totp_uri: Some("otpauth://totp/Netflix?secret=JBSWY3DPEHPK3PXP&issuer=Netflix".to_string()),
            notes: "profile: guests".to_string(),
            additional_urls: vec!["https://netflix.it".to_string()],
        }]
    }

    #[test]
    fn sealed_bundle_opens_for_the_intended_recipient() {
        let alice = ShareIdentity::generate("alice").unwrap();
        let bob = ShareIdentity::generate("bob").unwrap();

        let bundle = ShareBundle::seal(&sample_entries(), &alice, bob.public_key()).unwrap();
        let (sender, entries) = bundle.open(&bob).unwrap();

        assert_eq!(sender, alice.public_key_string());
        assert_eq!(entries, sample_entries());
    }

    #[test]
    fn a_third_party_cannot_open_the_bundle() {
        let alice = ShareIdentity::generate("alice").unwrap();
        let bob = ShareIdentity::generate("bob").unwrap();
        let eve = ShareIdentity::generate("eve").unwrap();

        let bundle = ShareBundle::seal(&sample_entries(), &alice, bob.public_key()).unwrap();
        assert!(bundle.open(&eve).is_err());
    }

    #[test]
    fn rewriting_the_sender_breaks_the_bundle() {
        // Without the static DH and the AAD binding, an attacker could claim
        // a bundle came from someone else. It must fail to open instead.
        let alice = ShareIdentity::generate("alice").unwrap();
        let bob = ShareIdentity::generate("bob").unwrap();
        let mallory = ShareIdentity::generate("mallory").unwrap();

        let mut bundle = ShareBundle::seal(&sample_entries(), &alice, bob.public_key()).unwrap();
        bundle.sender = BASE64.encode(mallory.public_key());

        assert!(bundle.open(&bob).is_err(), "a forged sender was accepted");
    }

    #[test]
    fn tampering_with_the_ciphertext_is_detected() {
        let alice = ShareIdentity::generate("alice").unwrap();
        let bob = ShareIdentity::generate("bob").unwrap();

        let mut bundle = ShareBundle::seal(&sample_entries(), &alice, bob.public_key()).unwrap();
        let mut raw = BASE64.decode(&bundle.ciphertext).unwrap();
        raw[0] ^= 0x01;
        bundle.ciphertext = BASE64.encode(&raw);

        assert!(bundle.open(&bob).is_err());
    }

    #[test]
    fn armor_roundtrips_through_text() {
        let alice = ShareIdentity::generate("alice").unwrap();
        let bob = ShareIdentity::generate("bob").unwrap();

        let bundle = ShareBundle::seal(&sample_entries(), &alice, bob.public_key()).unwrap();
        let armored = bundle.to_armored().unwrap();

        assert!(armored.starts_with(ARMOR_BEGIN));
        assert!(armored.trim_end().ends_with(ARMOR_END));
        // The secret must not be sitting in the armor in the clear.
        assert!(!armored.contains("the-shared-password"));

        let parsed = ShareBundle::from_armored(&armored).unwrap();
        let (_, entries) = parsed.open(&bob).unwrap();
        assert_eq!(entries, sample_entries());
    }

    #[test]
    fn armor_survives_being_pasted_into_a_message() {
        let alice = ShareIdentity::generate("alice").unwrap();
        let bob = ShareIdentity::generate("bob").unwrap();
        let bundle = ShareBundle::seal(&sample_entries(), &alice, bob.public_key()).unwrap();

        let email = format!(
            "Ciao Bob,\n\nhere's the Netflix login:\n\n{}\n\nCiao!\n",
            bundle.to_armored().unwrap()
        );

        let parsed = ShareBundle::from_armored(&email).unwrap();
        assert!(parsed.open(&bob).is_ok());
    }

    #[test]
    fn every_bundle_uses_a_fresh_ephemeral_key() {
        let alice = ShareIdentity::generate("alice").unwrap();
        let bob = ShareIdentity::generate("bob").unwrap();

        let first = ShareBundle::seal(&sample_entries(), &alice, bob.public_key()).unwrap();
        let second = ShareBundle::seal(&sample_entries(), &alice, bob.public_key()).unwrap();

        assert_ne!(first.ephemeral, second.ephemeral);
        assert_ne!(first.ciphertext, second.ciphertext);
    }

    #[test]
    fn public_key_string_roundtrips() {
        let identity = ShareIdentity::generate("me").unwrap();
        let text = identity.public_key_string();

        assert!(text.starts_with(PUBLIC_KEY_PREFIX));
        assert_eq!(parse_public_key(&text).unwrap(), identity.public_key());
    }

    #[test]
    fn public_key_parsing_rejects_nonsense() {
        assert!(parse_public_key("hello").is_err());
        assert!(parse_public_key("pass-share-pk1:not-base64!!").is_err());
        assert!(parse_public_key("pass-share-pk1:aGk=").is_err(), "wrong length accepted");
    }

    #[test]
    fn identity_survives_a_save_and_reload() {
        let original = ShareIdentity::generate("laptop").unwrap();
        let bytes = original.secret_key_bytes().unwrap();

        let reloaded = ShareIdentity::from_secret_bytes("laptop", &bytes).unwrap();
        assert_eq!(reloaded.public_key(), original.public_key());
    }

    #[test]
    fn debug_does_not_leak_the_private_key() {
        let identity = ShareIdentity::generate("me").unwrap();
        assert!(format!("{:?}", identity).contains("[shielded]"));
    }

    #[test]
    fn future_bundle_versions_are_rejected_clearly() {
        let alice = ShareIdentity::generate("alice").unwrap();
        let bob = ShareIdentity::generate("bob").unwrap();

        let mut bundle = ShareBundle::seal(&sample_entries(), &alice, bob.public_key()).unwrap();
        bundle.v = 99;

        let err = bundle.open(&bob).unwrap_err().to_string();
        assert!(err.contains("version 99"), "unhelpful error: {err}");
    }
}
