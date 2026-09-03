//! SSH keys stored inside the vault, in the format KeePassXC already uses.
//!
//! KeePassXC's own SSH-agent integration doesn't invent a field: it keeps the
//! private key as an ordinary **entry attachment** and describes it in a
//! `KeeAgent.settings` custom string field (an XML blob inherited from the
//! KeeAgent KeePass plugin). Storing keys the same way means an SSH key added
//! by `pass` shows up in KeePassXC's "SSH Agent" tab and can be served by
//! KeePassXC's agent, and vice versa — the same two-way interoperability the
//! rest of the vault already has.
//!
//! This is the piece goldwarden gets from Bitwarden's SSH items; here it maps
//! onto the KDBX4 format instead, so it stays readable by any KeePass tool.
//!
//! Private key material is held [`Shielded`] — encrypted in RAM, decrypted
//! only for the instant a signature is produced (see [`SshKey::sign`]).

use crate::error::{PassError, Result};
use crate::secmem::{SecretBuf, Shielded};
use serde::{Deserialize, Serialize};
use ssh_encoding::Encode;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};

/// The custom string field KeePassXC reads its SSH-agent settings from.
pub const KEEAGENT_SETTINGS_FIELD: &str = "KeeAgent.settings";

/// Signature flags from the SSH agent protocol (draft-miller-ssh-agent §5.3).
/// Only meaningful for RSA keys, which can sign under three different hashes.
pub const SSH_AGENT_RSA_SHA2_256: u32 = 0x02;
pub const SSH_AGENT_RSA_SHA2_512: u32 = 0x04;

/// An SSH key held in the vault.
///
/// Everything public about the key (algorithm, fingerprint, the public key
/// itself) is stored in the clear on this struct — it is public by
/// definition. Only `private_pem` is shielded.
pub struct SshKey {
    /// UUID of the KDBX entry holding this key.
    pub id: String,
    /// Entry title, i.e. the name the key is listed under.
    pub name: String,
    /// Name of the KDBX attachment holding the private key (e.g. `id_ed25519`).
    pub attachment_name: String,
    /// The key's own comment, as embedded in the OpenSSH key file.
    pub comment: String,
    /// SSH algorithm name, e.g. `ssh-ed25519`.
    pub algorithm: String,
    /// `SHA256:…` fingerprint, in the form `ssh-keygen -l` prints.
    pub fingerprint: String,
    /// The public key as one `authorized_keys` line.
    pub public_key: String,
    /// The OpenSSH-format private key, encrypted in RAM.
    private_pem: Shielded,
}

/// Listing view of an SSH key: everything except the private material.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshKeySummary {
    pub id: String,
    pub name: String,
    pub comment: String,
    pub algorithm: String,
    pub fingerprint: String,
    pub public_key: String,
}

impl From<&SshKey> for SshKeySummary {
    fn from(key: &SshKey) -> Self {
        Self {
            id: key.id.clone(),
            name: key.name.clone(),
            comment: key.comment.clone(),
            algorithm: key.algorithm.clone(),
            fingerprint: key.fingerprint.clone(),
            public_key: key.public_key.clone(),
        }
    }
}

impl std::fmt::Debug for SshKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshKey")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("algorithm", &self.algorithm)
            .field("fingerprint", &self.fingerprint)
            .field("private_pem", &"[shielded]")
            .finish()
    }
}

impl SshKey {
    /// Generate a fresh Ed25519 key.
    ///
    /// Ed25519 rather than RSA deliberately: it's what `ssh-keygen` itself
    /// now defaults to, the keys are small enough to be comfortable inside a
    /// KDBX attachment, and it sidesteps the RSA hash-negotiation the agent
    /// protocol otherwise drags in (see [`SshKey::sign`]).
    pub fn generate(name: &str, comment: &str) -> Result<Self> {
        let mut key = PrivateKey::random(&mut rand::thread_rng(), Algorithm::Ed25519)
            .map_err(|e| PassError::SshKey(format!("failed to generate key: {e}")))?;
        key.set_comment(comment);
        Self::from_private_key(String::new(), name, key)
    }

    /// Import an existing OpenSSH private key.
    ///
    /// `passphrase` is required only for a key that is itself encrypted; the
    /// key is stored **decrypted** inside the (already encrypted) vault,
    /// which is the same thing KeePassXC/KeeAgent do — a passphrase on top
    /// of the vault's own encryption would just mean typing two secrets to
    /// use one key.
    pub fn import_openssh(name: &str, pem: &str, passphrase: Option<&str>) -> Result<Self> {
        let key = PrivateKey::from_openssh(pem)
            .map_err(|e| PassError::SshKey(format!("not a valid OpenSSH private key: {e}")))?;

        let key = if key.is_encrypted() {
            let passphrase = passphrase.ok_or_else(|| {
                PassError::SshKey("this key is passphrase-protected; supply its passphrase".to_string())
            })?;
            key.decrypt(passphrase)
                .map_err(|_| PassError::SshKey("wrong passphrase for this SSH key".to_string()))?
        } else {
            key
        };

        Self::from_private_key(String::new(), name, key)
    }

    /// Rebuild a key read back out of the vault.
    pub(crate) fn from_stored(
        id: String,
        name: String,
        attachment_name: String,
        pem: &str,
    ) -> Result<Self> {
        let key = PrivateKey::from_openssh(pem)
            .map_err(|e| PassError::SshKey(format!("stored SSH key is unreadable: {e}")))?;
        if key.is_encrypted() {
            return Err(PassError::SshKey(
                "stored SSH key is passphrase-encrypted; `pass` stores keys decrypted inside the vault".to_string(),
            ));
        }

        let mut built = Self::from_private_key(id, &name, key)?;
        built.attachment_name = attachment_name;
        Ok(built)
    }

    fn from_private_key(id: String, name: &str, key: PrivateKey) -> Result<Self> {
        let public = key.public_key();
        let algorithm = key.algorithm().as_str().to_string();
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        let public_key = public
            .to_openssh()
            .map_err(|e| PassError::SshKey(format!("failed to encode public key: {e}")))?;
        let comment = key.comment().to_string();
        let attachment_name = default_attachment_name(key.algorithm());

        let pem = key
            .to_openssh(LineEnding::LF)
            .map_err(|e| PassError::SshKey(format!("failed to encode private key: {e}")))?;
        // `pem` is a `Zeroizing<String>`; hand its bytes to the shield and let
        // it wipe the original on drop.
        let private_pem = Shielded::new(pem.as_bytes())?;

        Ok(Self {
            id,
            name: name.to_string(),
            attachment_name,
            comment,
            algorithm,
            fingerprint,
            public_key,
            private_pem,
        })
    }

    /// The private key in OpenSSH format, in a locked buffer that wipes
    /// itself when dropped. Used when exporting a key to disk.
    pub fn private_key_pem(&self) -> Result<SecretBuf> {
        self.private_pem.expose()
    }

    /// The public key in SSH wire format — the blob an agent client compares
    /// against when it asks for a signature.
    pub fn public_key_blob(&self) -> Result<Vec<u8>> {
        let key = self.decode_private()?;
        key.public_key()
            .to_bytes()
            .map_err(|e| PassError::SshKey(format!("failed to encode public key blob: {e}")))
    }

    /// Sign `data` for an SSH agent `SIGN_REQUEST`, returning the encoded
    /// signature blob (`string algorithm, string signature`).
    ///
    /// `flags` carries the RSA hash selection. Ed25519 and ECDSA ignore it —
    /// each has exactly one signature algorithm. For RSA we can only produce
    /// `rsa-sha2-512`, so a client that insists on `rsa-sha2-256` gets an
    /// explicit error rather than a signature under the wrong algorithm,
    /// which the server would reject anyway with a far more confusing
    /// message. Use Ed25519 keys.
    pub fn sign(&self, data: &[u8], flags: u32) -> Result<Vec<u8>> {
        use ssh_key::private::KeypairData;
        use signature::Signer;

        let key = self.decode_private()?;

        if matches!(key.key_data(), KeypairData::Rsa(_)) && flags & SSH_AGENT_RSA_SHA2_256 != 0 {
            return Err(PassError::SshKey(
                "client requested rsa-sha2-256, which this agent cannot produce (rsa-sha2-512 only)".to_string(),
            ));
        }

        let signature = key
            .try_sign(data)
            .map_err(|e| PassError::SshKey(format!("signing failed: {e}")))?;

        let mut blob = Vec::new();
        signature
            .encode(&mut blob)
            .map_err(|e| PassError::SshKey(format!("failed to encode signature: {e}")))?;
        Ok(blob)
    }

    /// Decode the shielded PEM back into a usable key. The plaintext lives
    /// only inside this function's `SecretBuf` and the returned `PrivateKey`
    /// (which zeroizes its own key material on drop).
    fn decode_private(&self) -> Result<PrivateKey> {
        let pem = self.private_pem.expose()?;
        PrivateKey::from_openssh(pem.as_slice())
            .map_err(|e| PassError::SshKey(format!("stored SSH key is unreadable: {e}")))
    }

    /// The `KeeAgent.settings` XML describing where this key lives, in the
    /// shape KeePassXC writes and reads.
    pub fn keeagent_settings(&self) -> String {
        keeagent_settings_xml(&self.attachment_name)
    }
}

/// A sensible attachment filename for a key of this algorithm, matching what
/// `ssh-keygen` would have called the file.
fn default_attachment_name(algorithm: Algorithm) -> String {
    match algorithm {
        Algorithm::Ed25519 => "id_ed25519",
        Algorithm::Rsa { .. } => "id_rsa",
        Algorithm::Ecdsa { .. } => "id_ecdsa",
        Algorithm::Dsa => "id_dsa",
        _ => "id_ssh",
    }
    .to_string()
}

/// Render the `KeeAgent.settings` XML for a key stored as `attachment_name`.
///
/// The element names and order are KeeAgent's, which is what KeePassXC
/// parses; `AllowUseOfSshKey` is the flag that actually makes a KDBX entry
/// count as an SSH key rather than an entry that merely has a file attached.
pub fn keeagent_settings_xml(attachment_name: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-16"?>
<EntrySettings xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <AllowUseOfSshKey>true</AllowUseOfSshKey>
  <AddAtDatabaseOpen>true</AddAtDatabaseOpen>
  <RemoveAtDatabaseClose>true</RemoveAtDatabaseClose>
  <UseConfirmConstraintWhenAdding>false</UseConfirmConstraintWhenAdding>
  <UseLifetimeConstraintWhenAdding>false</UseLifetimeConstraintWhenAdding>
  <LifetimeConstraintDuration>600</LifetimeConstraintDuration>
  <Location>
    <SelectedType>attachment</SelectedType>
    <AttachmentName>{}</AttachmentName>
    <SaveAttachmentToTempFile>false</SaveAttachmentToTempFile>
    <FileName />
  </Location>
</EntrySettings>"#,
        xml_escape(attachment_name)
    )
}

/// Whether this `KeeAgent.settings` blob marks the entry as an SSH key that
/// may be served by an agent.
pub fn keeagent_allows_ssh_key(xml: &str) -> bool {
    xml_tag_value(xml, "AllowUseOfSshKey")
        .map(|v| v.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// The attachment a `KeeAgent.settings` blob points at, if it stores the key
/// as an attachment (the only location `pass` supports — the alternative,
/// KeeAgent's "external file" mode, points outside the vault entirely and so
/// isn't a vault-held key at all).
pub fn keeagent_attachment_name(xml: &str) -> Option<String> {
    let selected = xml_tag_value(xml, "SelectedType")?;
    if !selected.trim().eq_ignore_ascii_case("attachment") {
        return None;
    }
    xml_tag_value(xml, "AttachmentName").map(|v| xml_unescape(v.trim()))
}

/// Extract the text of the first `<tag>…</tag>` pair.
///
/// A full XML parser would be overkill for a fixed-shape settings blob whose
/// only variable part is a filename, and would pull a parsing dependency into
/// the crypto-carrying crate for it.
fn xml_tag_value<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(&xml[start..end])
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::PublicKey;

    #[test]
    fn generate_produces_a_usable_ed25519_key() {
        let key = SshKey::generate("work laptop", "antonio@laptop").unwrap();

        assert_eq!(key.algorithm, "ssh-ed25519");
        assert_eq!(key.comment, "antonio@laptop");
        assert_eq!(key.attachment_name, "id_ed25519");
        assert!(key.fingerprint.starts_with("SHA256:"));
        assert!(key.public_key.starts_with("ssh-ed25519 AAAA"));
        assert!(key.public_key.ends_with("antonio@laptop"));
    }

    #[test]
    fn private_key_pem_is_a_real_openssh_key() {
        let key = SshKey::generate("k", "c").unwrap();
        let pem = key.private_key_pem().unwrap();
        let text = pem.as_str().unwrap();

        assert!(text.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        // Round-trips through the parser, i.e. `ssh-keygen` would read it too.
        let reparsed = PrivateKey::from_openssh(text).unwrap();
        assert_eq!(reparsed.fingerprint(HashAlg::Sha256).to_string(), key.fingerprint);
    }

    #[test]
    fn signature_verifies_against_the_public_key() {
        use signature::Verifier;

        let key = SshKey::generate("k", "c").unwrap();
        let message = b"ssh agent sign request payload";
        let blob = key.sign(message, 0).unwrap();

        // Decode the agent-format blob back into a signature and check it
        // against the advertised public key — the exact thing an SSH server
        // does with what this agent returns.
        let signature = ssh_key::Signature::try_from(&blob[..]).unwrap();
        let public = PublicKey::from_openssh(&key.public_key).unwrap();
        // Fully qualified: `PublicKey` also has an inherent `verify` for
        // sshsig-namespaced signatures, which is not what an agent produces.
        Verifier::verify(&public, message, &signature).unwrap();
    }

    #[test]
    fn public_key_blob_matches_the_openssh_public_key() {
        let key = SshKey::generate("k", "c").unwrap();
        let blob = key.public_key_blob().unwrap();
        let from_blob = PublicKey::from_bytes(&blob).unwrap();
        let from_text = PublicKey::from_openssh(&key.public_key).unwrap();

        assert_eq!(from_blob.key_data(), from_text.key_data());
    }

    #[test]
    fn import_accepts_a_key_generated_elsewhere() {
        let generated = SshKey::generate("original", "someone@host").unwrap();
        let pem = generated.private_key_pem().unwrap();

        let imported = SshKey::import_openssh("imported", pem.as_str().unwrap(), None).unwrap();
        assert_eq!(imported.fingerprint, generated.fingerprint);
        assert_eq!(imported.name, "imported");
    }

    #[test]
    fn import_rejects_garbage() {
        let err = SshKey::import_openssh("bad", "not a key at all", None).unwrap_err();
        assert!(matches!(err, PassError::SshKey(_)));
    }

    #[test]
    fn keeagent_settings_roundtrip() {
        let xml = keeagent_settings_xml("id_ed25519");
        assert!(keeagent_allows_ssh_key(&xml));
        assert_eq!(keeagent_attachment_name(&xml).as_deref(), Some("id_ed25519"));
    }

    #[test]
    fn keeagent_settings_ignores_non_attachment_locations() {
        // KeeAgent can also point at a file on disk; that's not a key held
        // in the vault, so we must not claim it as one.
        let xml = keeagent_settings_xml("id_ed25519").replace("attachment", "file");
        assert_eq!(keeagent_attachment_name(&xml), None);
    }

    #[test]
    fn keeagent_settings_honours_a_disabled_key() {
        let xml = keeagent_settings_xml("id_ed25519").replace(
            "<AllowUseOfSshKey>true</AllowUseOfSshKey>",
            "<AllowUseOfSshKey>false</AllowUseOfSshKey>",
        );
        assert!(!keeagent_allows_ssh_key(&xml));
    }

    #[test]
    fn attachment_names_with_xml_metacharacters_survive() {
        let xml = keeagent_settings_xml("weird & <name>");
        assert!(xml.contains("weird &amp; &lt;name&gt;"));
        assert_eq!(keeagent_attachment_name(&xml).as_deref(), Some("weird & <name>"));
    }

    #[test]
    fn debug_does_not_leak_private_material() {
        let key = SshKey::generate("k", "c").unwrap();
        let rendered = format!("{:?}", key);
        assert!(rendered.contains("[shielded]"));
        assert!(!rendered.contains("BEGIN OPENSSH"));
    }
}
