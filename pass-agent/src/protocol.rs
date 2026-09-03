//! The control protocol between the `pass` CLI (and the browser host, and
//! the GUIs) and the agent.
//!
//! One JSON object per line, request then response. Newline-delimited JSON
//! rather than a binary framing because the transport is a local socket with
//! no throughput problem to solve, and being able to `socat` the socket and
//! read what is going over it is worth more here than a few saved bytes.
//!
//! Secrets do travel over this socket — that is its purpose — which is why
//! the socket itself is `0600` in a `0700` directory (see [`crate::paths`]).

use passlib::{PasswordEntrySummary, SshKeySummary};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A request from a client to the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum Request {
    /// Is a vault unlocked, and for how much longer?
    Status,
    /// Unlock a vault and start (or replace) the session.
    Unlock {
        vault: PathBuf,
        master_password: String,
        /// Idle timeout in seconds; `0` means never auto-lock.
        #[serde(default)]
        idle_timeout_secs: Option<u64>,
    },
    /// Drop the session, wiping the master password and cached SSH keys.
    Lock,
    /// Entry summaries, without passwords.
    ListEntries,
    /// One entry, with its password and current TOTP code.
    GetEntry { query: String },
    /// The SSH keys the agent is serving.
    ListSshKeys,
    /// Re-read SSH keys from the vault (after `pass ssh add`, say).
    ReloadSshKeys,
    /// What the peer-to-peer sync node is doing, if one is running.
    SyncStatus,
    /// Reconcile with every known peer now, instead of waiting for the next
    /// anti-entropy round.
    SyncNow,
    /// Stop the agent entirely.
    Shutdown,
}

/// The agent's answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum Response {
    Ok,
    Status(Status),
    /// Struct variants, not newtypes: serde's internally-tagged
    /// representation (`tag = "status"`) cannot serialize a newtype variant
    /// wrapping a sequence, and fails at runtime rather than at compile time
    /// if you try.
    Entries { entries: Vec<PasswordEntrySummary> },
    Entry(Box<Entry>),
    SshKeys { keys: Vec<SshKeySummary> },
    Sync(Box<SyncStatus>),
    Error { message: String },
}

impl Response {
    pub fn error(message: impl Into<String>) -> Self {
        Response::Error {
            message: message.into(),
        }
    }

    /// Turn an error response back into a `Result`, for clients that just
    /// want the happy path.
    pub fn into_result(self) -> Result<Self, String> {
        match self {
            Response::Error { message } => Err(message),
            other => Ok(other),
        }
    }
}

/// Session state, as reported by [`Request::Status`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub unlocked: bool,
    /// Path of the unlocked vault, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault: Option<PathBuf>,
    /// Seconds until the session auto-locks; `None` when locked, `Some(0)`
    /// when auto-locking is disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locks_in_secs: Option<u64>,
    pub ssh_keys: usize,
    /// Where `SSH_AUTH_SOCK` should point to use this agent.
    pub ssh_auth_sock: PathBuf,
}

/// What the sync node reports about itself.
///
/// Lives here rather than with the node so that it stays portable: the node
/// is Unix-only (its transport is), but a client asking an agent for its
/// sync status is not.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatus {
    /// This replica's wire id. Empty until the vault has been unlocked once
    /// with sync enabled.
    pub device: String,
    pub hostname: String,
    /// What peers are told to call this node at; empty when it cannot
    /// accept connections.
    pub advertise: String,
    pub listening_on: String,
    pub ops: usize,
    pub entries: usize,
    pub trusted_devices: usize,
    /// The merge fingerprint. Two devices that have converged print the
    /// same one — the fastest way to tell a network problem from a merge
    /// problem.
    pub fingerprint: String,
    pub peers: Vec<SyncPeer>,
    /// Changes from peers are waiting to be written into the vault (which
    /// needs it unlocked).
    pub pending_vault_write: bool,
    /// Recent activity, newest first.
    pub log: Vec<String>,
}

/// One peer, as reported to a client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncPeer {
    pub hostname: String,
    pub addr: String,
    pub device_id: String,
}

/// One entry, including the secrets a client asked for by name.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub id: String,
    pub website: String,
    pub url: String,
    pub username: String,
    pub password: String,
    pub notes: String,
    pub additional_urls: Vec<String>,
    /// Current TOTP code, when the entry has an MFA secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp_code: Option<String>,
    /// Seconds until that code rolls over.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp_expires_in: Option<u64>,
}

impl From<&passlib::PasswordEntry> for Entry {
    fn from(entry: &passlib::PasswordEntry) -> Self {
        let now = chrono::Utc::now();
        // A TOTP secret that fails to generate is reported as "no code"
        // rather than failing the whole entry lookup — the password is still
        // what the caller mostly wanted.
        let (totp_code, totp_expires_in) = match &entry.totp {
            Some(totp) => match passlib::totp::generate_code(totp, now) {
                Ok(code) => (Some(code), Some(passlib::totp::seconds_remaining(totp, now))),
                Err(_) => (None, None),
            },
            None => (None, None),
        };

        Self {
            id: entry.id.clone(),
            website: entry.website.clone(),
            url: entry.url.clone(),
            username: entry.username.clone(),
            password: entry.password().to_string(),
            notes: entry.notes.clone(),
            additional_urls: entry.additional_urls.clone(),
            totp_code,
            totp_expires_in,
        }
    }
}

/// Encode a request/response as one protocol line (trailing newline included).
pub fn encode_line<T: Serialize>(value: &T) -> serde_json::Result<String> {
    let mut line = serde_json::to_string(value)?;
    line.push('\n');
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_request(request: &Request) -> Request {
        let line = encode_line(request).unwrap();
        assert!(line.ends_with('\n'), "protocol lines must be newline-terminated");
        serde_json::from_str(&line).unwrap()
    }

    #[test]
    fn requests_roundtrip_through_json() {
        let unlock = Request::Unlock {
            vault: PathBuf::from("/home/me/passwords.kdbx"),
            master_password: "hunter2".to_string(),
            idle_timeout_secs: Some(900),
        };
        match roundtrip_request(&unlock) {
            Request::Unlock {
                vault,
                master_password,
                idle_timeout_secs,
            } => {
                assert_eq!(vault, PathBuf::from("/home/me/passwords.kdbx"));
                assert_eq!(master_password, "hunter2");
                assert_eq!(idle_timeout_secs, Some(900));
            }
            other => panic!("decoded as {other:?}"),
        }

        assert!(matches!(roundtrip_request(&Request::Status), Request::Status));
        assert!(matches!(roundtrip_request(&Request::Lock), Request::Lock));
        assert!(matches!(roundtrip_request(&Request::Shutdown), Request::Shutdown));
    }

    #[test]
    fn the_idle_timeout_is_optional_on_the_wire() {
        // Older clients omit it; that must mean "use the default", not a
        // parse failure.
        let request: Request =
            serde_json::from_str(r#"{"op":"unlock","vault":"/v.kdbx","master_password":"x"}"#).unwrap();
        match request {
            Request::Unlock { idle_timeout_secs, .. } => assert_eq!(idle_timeout_secs, None),
            other => panic!("decoded as {other:?}"),
        }
    }

    #[test]
    fn responses_roundtrip_through_json() {
        let status = Response::Status(Status {
            unlocked: true,
            vault: Some(PathBuf::from("/v.kdbx")),
            locks_in_secs: Some(300),
            ssh_keys: 2,
            ssh_auth_sock: PathBuf::from("/run/user/1000/pass/ssh-agent.sock"),
        });

        let line = encode_line(&status).unwrap();
        match serde_json::from_str::<Response>(&line).unwrap() {
            Response::Status(s) => {
                assert!(s.unlocked);
                assert_eq!(s.ssh_keys, 2);
                assert_eq!(s.locks_in_secs, Some(300));
            }
            other => panic!("decoded as {other:?}"),
        }
    }

    #[test]
    fn errors_convert_into_results() {
        assert_eq!(
            Response::error("vault is locked").into_result().unwrap_err(),
            "vault is locked"
        );
        assert!(Response::Ok.into_result().is_ok());
    }

    #[test]
    fn a_protocol_line_never_contains_an_embedded_newline() {
        // The framing is line-based, so a secret containing a newline must
        // still encode to exactly one line.
        let request = Request::Unlock {
            vault: PathBuf::from("/v.kdbx"),
            master_password: "two\nlines".to_string(),
            idle_timeout_secs: None,
        };

        let line = encode_line(&request).unwrap();
        assert_eq!(line.matches('\n').count(), 1);

        match serde_json::from_str::<Request>(&line).unwrap() {
            Request::Unlock { master_password, .. } => assert_eq!(master_password, "two\nlines"),
            other => panic!("decoded as {other:?}"),
        }
    }

    #[test]
    fn entry_carries_a_live_totp_code() {
        let mut entry = passlib::PasswordEntry::new(
            "GitHub".to_string(),
            "https://github.com".to_string(),
            "me".to_string(),
            "secret".to_string(),
        );
        entry.totp = Some(
            passlib::totp::parse_otpauth_uri("otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP&issuer=GitHub").unwrap(),
        );

        let payload = Entry::from(&entry);
        assert_eq!(payload.password, "secret");
        assert_eq!(payload.totp_code.as_ref().unwrap().len(), 6);
        assert!(payload.totp_expires_in.unwrap() <= 30);
    }

    #[test]
    fn an_entry_without_totp_reports_no_code() {
        let entry = passlib::PasswordEntry::new("A".into(), "u".into(), "n".into(), "p".into());
        let payload = Entry::from(&entry);
        assert!(payload.totp_code.is_none());
        assert!(payload.totp_expires_in.is_none());
    }
}
