//! Talking to a running agent.
//!
//! One connection per request: the protocol is request/response with no
//! server-initiated messages, connections are cheap on a Unix socket, and a
//! stateless client means a CLI invocation can't leave a half-read socket
//! behind for the next one to trip over.

use crate::paths;
use crate::protocol::{encode_line, Entry, Request, Response, Status, SyncStatus};
use passlib::{PasswordEntrySummary, SshKeySummary};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How long to wait for the agent to answer. Generous, because an `unlock`
/// runs Argon2id at 64 MiB, which is deliberately slow and slower still on a
/// loaded machine.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("no agent is running at {path} — start one with `pass agent run`")]
    NotRunning { path: PathBuf },

    #[error("agent communication failed: {0}")]
    Io(#[from] io::Error),

    #[error("agent sent a malformed reply: {0}")]
    Malformed(#[from] serde_json::Error),

    #[error("the agent closed the connection without replying")]
    NoReply,

    #[error("{0}")]
    Refused(String),

    #[error("agent replied with an unexpected message: {0}")]
    Unexpected(String),
}

pub type Result<T> = std::result::Result<T, AgentError>;

/// A handle to the agent's control socket.
#[derive(Debug, Clone)]
pub struct Client {
    path: PathBuf,
}

impl Client {
    /// A client for the default socket path.
    pub fn with_default_path() -> io::Result<Self> {
        Ok(Self::new(paths::ipc_socket_path()?))
    }

    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether an agent is actually listening. Used to decide between
    /// talking to the agent and falling back to prompting for the master
    /// password directly.
    pub fn is_running(&self) -> bool {
        UnixStream::connect(&self.path).is_ok()
    }

    /// Send one request and read the reply.
    pub fn send(&self, request: Request) -> Result<Response> {
        let mut stream = UnixStream::connect(&self.path).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => AgentError::NotRunning {
                path: self.path.clone(),
            },
            _ => AgentError::Io(e),
        })?;

        stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
        stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;

        stream.write_all(encode_line(&request)?.as_bytes())?;
        stream.flush()?;

        let mut line = String::new();
        if BufReader::new(&stream).read_line(&mut line)? == 0 {
            return Err(AgentError::NoReply);
        }

        serde_json::from_str::<Response>(&line)?
            .into_result()
            .map_err(AgentError::Refused)
    }

    pub fn status(&self) -> Result<Status> {
        match self.send(Request::Status)? {
            Response::Status(status) => Ok(status),
            other => Err(unexpected(&other)),
        }
    }

    pub fn unlock(&self, vault: &Path, master_password: &str, idle_timeout: Option<Duration>) -> Result<()> {
        self.expect_ok(Request::Unlock {
            vault: vault.to_path_buf(),
            master_password: master_password.to_string(),
            idle_timeout_secs: idle_timeout.map(|d| d.as_secs()),
        })
    }

    pub fn lock(&self) -> Result<()> {
        self.expect_ok(Request::Lock)
    }

    pub fn shutdown(&self) -> Result<()> {
        self.expect_ok(Request::Shutdown)
    }

    pub fn reload_ssh_keys(&self) -> Result<()> {
        self.expect_ok(Request::ReloadSshKeys)
    }

    pub fn list_entries(&self) -> Result<Vec<PasswordEntrySummary>> {
        match self.send(Request::ListEntries)? {
            Response::Entries { entries } => Ok(entries),
            other => Err(unexpected(&other)),
        }
    }

    pub fn get_entry(&self, query: &str) -> Result<Entry> {
        match self.send(Request::GetEntry {
            query: query.to_string(),
        })? {
            Response::Entry(entry) => Ok(*entry),
            other => Err(unexpected(&other)),
        }
    }

    pub fn list_ssh_keys(&self) -> Result<Vec<SshKeySummary>> {
        match self.send(Request::ListSshKeys)? {
            Response::SshKeys { keys } => Ok(keys),
            other => Err(unexpected(&other)),
        }
    }

    /// What the agent's sync node is doing, if it has one.
    pub fn sync_status(&self) -> Result<SyncStatus> {
        match self.send(Request::SyncStatus)? {
            Response::Sync(status) => Ok(*status),
            other => Err(unexpected(&other)),
        }
    }

    /// Ask for a round now rather than at the next interval. Returns as soon
    /// as the round is scheduled: it runs on the agent's own thread, so a
    /// sleeping peer cannot hold this call open for its whole timeout.
    pub fn sync_now(&self) -> Result<()> {
        self.expect_ok(Request::SyncNow)
    }

    fn expect_ok(&self, request: Request) -> Result<()> {
        match self.send(request)? {
            Response::Ok => Ok(()),
            other => Err(unexpected(&other)),
        }
    }
}

fn unexpected(response: &Response) -> AgentError {
    AgentError::Unexpected(
        serde_json::to_string(response).unwrap_or_else(|_| "<unserialisable response>".to_string()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_pointed_at_nothing_reports_not_running() {
        let dir = tempfile::tempdir().unwrap();
        let client = Client::new(dir.path().join("absent.sock"));

        assert!(!client.is_running());
        assert!(matches!(
            client.status().unwrap_err(),
            AgentError::NotRunning { .. }
        ));
    }

    #[test]
    fn the_not_running_error_tells_the_user_what_to_do() {
        let error = AgentError::NotRunning {
            path: PathBuf::from("/run/user/1000/pass/agent.sock"),
        };
        let message = error.to_string();
        assert!(message.contains("pass agent run"), "unhelpful message: {message}");
    }
}
