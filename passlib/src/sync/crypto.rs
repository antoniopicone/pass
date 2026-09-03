//! Device identity, op signatures, and the sealed payload.
//!
//! The sync layer has two secrets and they do different jobs. Confusing
//! them is the classic way to build something that looks encrypted and
//! authenticates nobody:
//!
//! | secret | question it answers | shared with |
//! |---|---|---|
//! | [`DeviceIdentity`] (Ed25519) | *who wrote this op* | nobody — one per device |
//! | [`SyncKey`] (32 bytes) | *what does the op say* | every device holding this vault |
//!
//! An op therefore travels as ciphertext signed by a named device. A peer
//! on the tailnet that does not hold the vault learns only that a device it
//! may not know changed an entry with some UUID at some time — which is
//! what makes it safe to let an always-on machine relay and store ops
//! without trusting it. And a peer that *does* hold the vault still refuses
//! ops from a device the roster does not list, so possession of the file is
//! not on its own permission to write into someone's replica.
//!
//! ## Why the sync key is not derived from the master password
//!
//! It would be free to do, and it would be a real regression: the master
//! password is protected on disk by Argon2id at 64 MiB × 10 iterations,
//! and hanging a fast KDF off the same secret would hand an eavesdropper a
//! cheap oracle to grind it against. The sync key is instead 32 random
//! bytes stored *in* the vault, so it inherits the vault's protection and
//! reaches a new device the same way everything else does — with the file.

use crate::error::{PassError, Result};
use crate::secmem::{SecretBuf, Shielded};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use super::core::{device_id, DeviceId, Op};

/// Prefix of the printable form of a device's signing key.
pub const DEVICE_KEY_PREFIX: &str = "pass-device-pk1:";
/// Domain separator for the payload AEAD, so a `pass` sync key can never
/// be made to open something sealed by another part of this codebase.
const SEAL_CONTEXT: &[u8] = b"pass-sync-payload-v1";

/// A device's long-lived signing key, plus the epoch that makes its op
/// sequence safe across a restore (see [`super::core::device_id`]).
///
/// One per device, never leaving it — unlike the sharing identity in
/// [`crate::share`], which is per *vault* because it is the name other
/// people know you by. Here the whole point is to distinguish the laptop
/// from the phone, so a key that travelled with the vault would answer the
/// wrong question.
pub struct DeviceIdentity {
    /// Human-readable name, shown by `pass sync devices`.
    pub label: String,
    public: [u8; 32],
    secret: Shielded,
    epoch: u64,
}

impl std::fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("label", &self.label)
            .field("fingerprint", &self.fingerprint())
            .field("epoch", &self.epoch)
            .field("secret", &"[shielded]")
            .finish()
    }
}

impl DeviceIdentity {
    /// A fresh identity for this device, with the current time as its epoch.
    pub fn generate(label: &str) -> Result<Self> {
        use rand::RngCore;

        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let identity = Self::from_secret_bytes(label, &bytes, now_millis());
        bytes.zeroize();
        identity
    }

    /// Rebuild from the 32-byte private key kept in the vault.
    pub fn from_secret_bytes(label: &str, bytes: &[u8], epoch: u64) -> Result<Self> {
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| PassError::Sync("a device signing key must be exactly 32 bytes".to_string()))?;
        let signing = SigningKey::from_bytes(&array);
        let public = signing.verifying_key().to_bytes();

        Ok(Self {
            label: label.to_string(),
            public,
            secret: Shielded::new(&array)?,
            epoch,
        })
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// The printable form to read out when pairing two devices.
    pub fn public_key_string(&self) -> String {
        format!("{DEVICE_KEY_PREFIX}{}", BASE64.encode(self.public))
    }

    /// Short, stable name for this key. Trust is granted to this, not to
    /// the device id, so a restored device stays trusted across epochs.
    pub fn fingerprint(&self) -> String {
        fingerprint_of_key(&self.public)
    }

    /// This device's identity on the wire, for this epoch.
    pub fn device_id(&self) -> DeviceId {
        device_id(&self.fingerprint(), self.epoch)
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Start a new epoch, after detecting that the local op-log rewound.
    ///
    /// Clamped to be strictly increasing: a system clock that is behind the
    /// previous epoch must not hand out an epoch peers have already seen.
    pub fn bump_epoch(&mut self) {
        self.epoch = now_millis().max(self.epoch + 1);
    }

    /// The private key, for writing into the vault. Deliberately an
    /// explicit call and kept out of `Debug`.
    pub fn secret_key_bytes(&self) -> Result<[u8; 32]> {
        let exposed = self.secret.expose()?;
        exposed
            .as_slice()
            .try_into()
            .map_err(|_| PassError::Sync("stored device key has the wrong length".to_string()))
    }

    /// Sign an op. The signature covers [`Op::signing_bytes`], which is
    /// every field except the signature itself.
    pub fn sign_op(&self, op: &Op) -> Result<String> {
        let mut key = self.secret_key_bytes()?;
        let signing = SigningKey::from_bytes(&key);
        key.zeroize();
        Ok(BASE64.encode(signing.sign(&op.signing_bytes()).to_bytes()))
    }
}

/// Whether `op` was signed by the holder of `public_key`.
///
/// Returns `false` for anything malformed rather than an error: to the
/// caller, a signature that cannot be parsed and one that does not verify
/// mean the same thing, and collapsing them removes a branch where an
/// unverified op could slip through.
pub fn verify_op(op: &Op, public_key: &[u8; 32]) -> bool {
    let Ok(verifying) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(raw) = BASE64.decode(&op.sig) else {
        return false;
    };
    let Ok(bytes) = <[u8; 64]>::try_from(raw.as_slice()) else {
        return false;
    };
    verifying.verify(&op.signing_bytes(), &Signature::from_bytes(&bytes)).is_ok()
}

/// The short name a signing key is known by: the first 16 hex characters
/// of its SHA-256. Long enough that finding a collision is not a thing
/// anyone does by accident or on purpose, short enough to read aloud.
pub fn fingerprint_of_key(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    hex_encode(&digest[..8])
}

/// Parse a `pass-device-pk1:…` string.
pub fn parse_public_key(text: &str) -> Result<[u8; 32]> {
    let encoded = text.trim().strip_prefix(DEVICE_KEY_PREFIX).ok_or_else(|| {
        PassError::Sync(format!("not a device key (expected a {DEVICE_KEY_PREFIX}… string)"))
    })?;
    let bytes = BASE64
        .decode(encoded)
        .map_err(|_| PassError::Sync("device key is not valid base64".to_string()))?;
    bytes
        .try_into()
        .map_err(|_| PassError::Sync("device key has the wrong length".to_string()))
}

/// The symmetric key every device holding this vault shares, and which
/// makes an op's payload opaque to everyone else.
pub struct SyncKey(Shielded);

impl std::fmt::Debug for SyncKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SyncKey([shielded])")
    }
}

impl SyncKey {
    /// A fresh key, for the first device to enable sync on a vault.
    pub fn generate() -> Result<Self> {
        use rand::RngCore;

        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let key = Self::from_bytes(&bytes);
        bytes.zeroize();
        key
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(PassError::Sync("a sync key must be exactly 32 bytes".to_string()));
        }
        Ok(Self(Shielded::new(bytes)?))
    }

    /// A short, non-secret name for this key, safe to publish in a
    /// handshake.
    ///
    /// Two vaults that were not copied from one another have different sync
    /// keys, and every op one sends the other is undecryptable. Without
    /// this, the only symptom is a decryption error per op with no hint of
    /// the cause; with it, the two devices notice at the handshake and say
    /// so once. It is a hash of the key, so publishing it reveals nothing:
    /// recovering 32 random bytes from their SHA-256 is not a thing.
    pub fn check_value(&self) -> Result<String> {
        let mut key = self.to_bytes()?;
        let mut hasher = Sha256::new();
        hasher.update(b"pass-sync-keycheck-v1");
        hasher.update(key);
        key.zeroize();
        Ok(hex_encode(&hasher.finalize()[..8]))
    }

    /// The raw key, for storing in the vault.
    pub fn to_bytes(&self) -> Result<[u8; 32]> {
        let exposed = self.0.expose()?;
        exposed
            .as_slice()
            .try_into()
            .map_err(|_| PassError::Sync("stored sync key has the wrong length".to_string()))
    }

    /// Seal `plaintext` for the entity it belongs to.
    ///
    /// The entity id goes in as associated data, so a sealed payload cannot
    /// be lifted onto a different entry even by someone who can forge the
    /// op signature.
    pub fn seal(&self, entity: &str, plaintext: &[u8]) -> Result<String> {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use chacha20poly1305::{XChaCha20Poly1305, XNonce};
        use rand::RngCore;

        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        let mut key = self.to_bytes()?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| PassError::Sync("invalid sync key".to_string()))?;
        key.zeroize();

        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload { msg: plaintext, aad: &associated_data(entity) },
            )
            .map_err(|_| PassError::Sync("failed to seal a sync payload".to_string()))?;

        let mut framed = Vec::with_capacity(24 + ciphertext.len());
        framed.extend_from_slice(&nonce);
        framed.extend_from_slice(&ciphertext);
        Ok(BASE64.encode(&framed))
    }

    /// Open a payload sealed for `entity`.
    ///
    /// The result is a [`SecretBuf`] — locked out of swap and zeroized on
    /// drop — because what comes back is a password.
    pub fn open(&self, entity: &str, sealed: &str) -> Result<SecretBuf> {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use chacha20poly1305::{XChaCha20Poly1305, XNonce};

        let framed = BASE64
            .decode(sealed)
            .map_err(|_| PassError::Sync("sync payload is not valid base64".to_string()))?;
        if framed.len() < 24 {
            return Err(PassError::Sync("sync payload is truncated".to_string()));
        }
        let (nonce, ciphertext) = framed.split_at(24);

        let mut key = self.to_bytes()?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| PassError::Sync("invalid sync key".to_string()))?;
        key.zeroize();

        let mut plaintext = cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload { msg: ciphertext, aad: &associated_data(entity) },
            )
            .map_err(|_| {
                PassError::Sync(
                    "could not open a sync payload: it was sealed by a vault with a different sync key, \
                     or it has been tampered with"
                        .to_string(),
                )
            })?;

        let out = SecretBuf::from_slice(&plaintext);
        plaintext.zeroize();
        Ok(out)
    }
}

fn associated_data(entity: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SEAL_CONTEXT.len() + entity.len() + 1);
    aad.extend_from_slice(SEAL_CONTEXT);
    aad.push(b':');
    aad.extend_from_slice(entity.as_bytes());
    aad
}

pub(super) fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    })
}

pub(super) fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::core::{Hlc, OpKind, Replica, Roster, SERVICE};

    struct OneDevice(String, [u8; 32]);

    impl Roster for OneDevice {
        fn verifying_key(&self, fingerprint: &str) -> Option<[u8; 32]> {
            (fingerprint == self.0).then_some(self.1)
        }
    }

    fn signed_op(identity: &DeviceIdentity, entity: &str, payload: &str) -> Op {
        let mut op = Op {
            device: identity.device_id(),
            seq: 1,
            hlc: Hlc { millis: 1, counter: 0, device: identity.device_id() },
            service: SERVICE.to_string(),
            entity: entity.to_string(),
            kind: OpKind::Upsert,
            payload: payload.to_string(),
            sig: String::new(),
        };
        op.sig = identity.sign_op(&op).unwrap();
        op
    }

    #[test]
    fn a_signed_op_verifies_against_its_own_key() {
        let id = DeviceIdentity::generate("laptop").unwrap();
        let op = signed_op(&id, "e", "payload");
        assert!(verify_op(&op, &id.public_key()));
    }

    #[test]
    fn tampering_with_any_field_invalidates_the_signature() {
        let id = DeviceIdentity::generate("laptop").unwrap();
        let op = signed_op(&id, "e", "payload");

        for tampered in [
            Op { payload: "other".into(), ..op.clone() },
            Op { entity: "other".into(), ..op.clone() },
            Op { seq: 2, ..op.clone() },
            Op { kind: OpKind::Delete, ..op.clone() },
            Op { service: "immich".into(), ..op.clone() },
            Op { hlc: Hlc { millis: 2, ..op.hlc.clone() }, ..op.clone() },
        ] {
            assert!(!verify_op(&tampered, &id.public_key()));
        }
    }

    #[test]
    fn another_devices_key_does_not_verify() {
        let mine = DeviceIdentity::generate("laptop").unwrap();
        let theirs = DeviceIdentity::generate("phone").unwrap();
        let op = signed_op(&mine, "e", "payload");
        assert!(!verify_op(&op, &theirs.public_key()));
    }

    #[test]
    fn a_malformed_signature_is_a_failure_not_a_panic() {
        let id = DeviceIdentity::generate("laptop").unwrap();
        let mut op = signed_op(&id, "e", "payload");

        for bad in ["", "!!!not base64!!!", "c2hvcnQ="] {
            op.sig = bad.to_string();
            assert!(!verify_op(&op, &id.public_key()));
        }
    }

    #[test]
    fn a_replica_refuses_an_op_from_an_unlisted_device() {
        let id = DeviceIdentity::generate("stranger").unwrap();
        let op = signed_op(&id, "e", "payload");

        let mut r = Replica::new("me@1".into());
        assert_eq!(
            r.apply(op, &crate::sync::core::TrustNone),
            Err(crate::sync::core::Rejected::UntrustedDevice(id.fingerprint()))
        );
    }

    #[test]
    fn a_replica_refuses_a_trusted_device_with_a_broken_signature() {
        let id = DeviceIdentity::generate("laptop").unwrap();
        let mut op = signed_op(&id, "e", "payload");
        op.payload = "swapped after signing".into();

        let mut r = Replica::new("me@1".into());
        let roster = OneDevice(id.fingerprint(), id.public_key());
        assert_eq!(r.apply(op, &roster), Err(crate::sync::core::Rejected::BadSignature));
    }

    #[test]
    fn an_op_cannot_borrow_another_devices_clock() {
        let id = DeviceIdentity::generate("laptop").unwrap();
        let mut op = signed_op(&id, "e", "payload");
        // Claiming a clock belonging to "zzz" would win every tie-break.
        op.hlc.device = "zzz@1".into();
        op.sig = id.sign_op(&op).unwrap();

        let mut r = Replica::new("me@1".into());
        let roster = OneDevice(id.fingerprint(), id.public_key());
        assert_eq!(r.apply(op, &roster), Err(crate::sync::core::Rejected::BadSignature));
    }

    #[test]
    fn a_trusted_signed_op_is_accepted() {
        let id = DeviceIdentity::generate("laptop").unwrap();
        let op = signed_op(&id, "e", "payload");

        let mut r = Replica::new("me@1".into());
        let roster = OneDevice(id.fingerprint(), id.public_key());
        assert!(r.apply(op, &roster).is_ok());
        assert_eq!(r.entries().len(), 1);
    }

    #[test]
    fn an_identity_round_trips_through_its_stored_bytes() {
        let id = DeviceIdentity::generate("laptop").unwrap();
        let restored =
            DeviceIdentity::from_secret_bytes("laptop", &id.secret_key_bytes().unwrap(), id.epoch()).unwrap();

        assert_eq!(restored.public_key(), id.public_key());
        assert_eq!(restored.device_id(), id.device_id());
    }

    #[test]
    fn the_public_key_string_round_trips() {
        let id = DeviceIdentity::generate("laptop").unwrap();
        assert_eq!(parse_public_key(&id.public_key_string()).unwrap(), id.public_key());
        assert!(parse_public_key("pass-share-pk1:AAAA").is_err());
        assert!(parse_public_key(&format!("{DEVICE_KEY_PREFIX}not-base64!")).is_err());
    }

    #[test]
    fn bumping_the_epoch_always_moves_forward() {
        let mut id = DeviceIdentity::generate("laptop").unwrap();
        // An epoch from a clock far in the future, as a restored backup or a
        // misconfigured machine could produce.
        let far_future = now_millis() + 10_000_000;
        id.epoch = far_future;
        id.bump_epoch();
        assert!(id.epoch() > far_future);
    }

    #[test]
    fn debug_does_not_leak_the_signing_key() {
        let id = DeviceIdentity::generate("laptop").unwrap();
        let secret = BASE64.encode(id.secret_key_bytes().unwrap());
        assert!(!format!("{id:?}").contains(&secret));
    }

    #[test]
    fn a_sealed_payload_round_trips() {
        let key = SyncKey::generate().unwrap();
        let sealed = key.seal("entity-1", b"hunter2").unwrap();

        assert!(!sealed.contains("hunter2"));
        assert_eq!(key.open("entity-1", &sealed).unwrap().as_slice(), b"hunter2");
    }

    #[test]
    fn sealing_twice_gives_different_ciphertext() {
        let key = SyncKey::generate().unwrap();
        assert_ne!(key.seal("e", b"same").unwrap(), key.seal("e", b"same").unwrap());
    }

    #[test]
    fn a_payload_cannot_be_moved_to_another_entity() {
        let key = SyncKey::generate().unwrap();
        let sealed = key.seal("entity-1", b"hunter2").unwrap();
        assert!(key.open("entity-2", &sealed).is_err());
    }

    #[test]
    fn another_vaults_sync_key_cannot_open_it() {
        let sealed = SyncKey::generate().unwrap().seal("e", b"hunter2").unwrap();
        assert!(SyncKey::generate().unwrap().open("e", &sealed).is_err());
    }

    #[test]
    fn a_truncated_or_corrupted_payload_is_an_error_not_a_panic() {
        let key = SyncKey::generate().unwrap();
        let sealed = key.seal("e", b"hunter2").unwrap();

        assert!(key.open("e", "").is_err());
        assert!(key.open("e", "AAAA").is_err());
        assert!(key.open("e", "not base64!!").is_err());
        assert!(key.open("e", &sealed[..sealed.len() - 4]).is_err());
    }

    #[test]
    fn a_sync_key_round_trips_through_its_stored_bytes() {
        let key = SyncKey::generate().unwrap();
        let restored = SyncKey::from_bytes(&key.to_bytes().unwrap()).unwrap();
        let sealed = key.seal("e", b"hunter2").unwrap();
        assert_eq!(restored.open("e", &sealed).unwrap().as_slice(), b"hunter2");
    }

    #[test]
    fn the_check_value_identifies_a_key_without_revealing_it() {
        let key = SyncKey::generate().unwrap();
        let same = SyncKey::from_bytes(&key.to_bytes().unwrap()).unwrap();
        let other = SyncKey::generate().unwrap();

        assert_eq!(key.check_value().unwrap(), same.check_value().unwrap());
        assert_ne!(key.check_value().unwrap(), other.check_value().unwrap());
        assert_eq!(key.check_value().unwrap().len(), 16);

        let raw = BASE64.encode(key.to_bytes().unwrap());
        assert!(!raw.contains(&key.check_value().unwrap()));
    }

    #[test]
    fn a_sync_key_must_be_the_right_length() {
        assert!(SyncKey::from_bytes(&[0u8; 16]).is_err());
        assert!(SyncKey::from_bytes(&[0u8; 32]).is_ok());
    }

    #[test]
    fn fingerprints_are_stable_and_distinct() {
        let a = DeviceIdentity::generate("a").unwrap();
        let b = DeviceIdentity::generate("b").unwrap();

        assert_eq!(a.fingerprint(), fingerprint_of_key(&a.public_key()));
        assert_eq!(a.fingerprint().len(), 16);
        assert_ne!(a.fingerprint(), b.fingerprint());
    }
}
