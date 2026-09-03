//! The agent process: two Unix sockets and a session shared between them.
//!
//! - the **control socket** speaks [`crate::protocol`] to the `pass` CLI and
//!   the other clients;
//! - the **SSH socket** speaks the OpenSSH agent protocol
//!   ([`crate::sshagent`]) to `ssh`, `git`, and anything else honouring
//!   `SSH_AUTH_SOCK`.
//!
//! Both hand out secrets, so both are `0600` in a `0700` directory, and the
//! agent refuses to start on a socket it cannot protect.

use crate::paths;
use crate::protocol::{self, Request, Response, Status};
use crate::session::{Session, DEFAULT_IDLE_TIMEOUT};
use crate::sshagent::{self, AgentRequest};
use crate::sync::{SyncConfig, SyncNode};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How often the accept loops wake up to notice a shutdown, and how often the
/// reaper checks whether the session has gone idle.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const REAP_INTERVAL: Duration = Duration::from_secs(1);

type SharedSession = Arc<Mutex<Option<Session>>>;

/// A running (or runnable) agent.
pub struct Agent {
    session: SharedSession,
    ipc_path: PathBuf,
    ssh_path: PathBuf,
    shutdown: Arc<AtomicBool>,
    /// Peer-to-peer sync, when the user asked for it. `None` is the
    /// default: an agent that only holds the vault open and serves SSH
    /// opens no network port at all.
    sync: Option<SyncNode>,
}

impl Agent {
    /// Build an agent bound to the default socket paths.
    pub fn with_default_paths() -> io::Result<Self> {
        Ok(Self::new(paths::ipc_socket_path()?, paths::ssh_agent_socket_path()?))
    }

    pub fn new(ipc_path: PathBuf, ssh_path: PathBuf) -> Self {
        Self {
            session: Arc::new(Mutex::new(None)),
            ipc_path,
            ssh_path,
            shutdown: Arc::new(AtomicBool::new(false)),
            sync: None,
        }
    }

    /// Also replicate this vault to the user's other devices.
    ///
    /// Loads the persisted op-log so a restart does not make every peer
    /// re-send its history. The node is built here but stays inert until a
    /// vault is unlocked: it cannot sign or seal anything without one.
    ///
    /// Takes `&mut self` rather than consuming the agent so that a caller
    /// can report a failure and carry on without sync. Losing the op-log is
    /// a problem; losing the SSH agent because of it would be a worse one.
    pub fn enable_sync(&mut self, config: SyncConfig) -> io::Result<()> {
        self.sync = Some(SyncNode::load(config)?);
        Ok(())
    }

    pub fn ipc_path(&self) -> &Path {
        &self.ipc_path
    }

    pub fn ssh_path(&self) -> &Path {
        &self.ssh_path
    }

    /// A handle that makes [`Agent::run`] return. Mainly for tests and for a
    /// signal handler.
    pub fn shutdown_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown)
    }

    /// Bind both sockets and serve until shutdown.
    ///
    /// Returns once a `Shutdown` request arrives or the shutdown handle is
    /// set; the sockets are removed on the way out so the next start doesn't
    /// have to reason about a stale one.
    pub fn run(&self) -> io::Result<()> {
        let ipc = bind(&self.ipc_path)?;
        let ssh = bind(&self.ssh_path)?;

        let ipc_thread = {
            let session = Arc::clone(&self.session);
            let shutdown = Arc::clone(&self.shutdown);
            let ssh_path = self.ssh_path.clone();
            let sync = self.sync.clone();
            std::thread::spawn(move || {
                accept_loop(ipc, Arc::clone(&shutdown), move |stream| {
                    let session = Arc::clone(&session);
                    let shutdown = Arc::clone(&shutdown);
                    let ssh_path = ssh_path.clone();
                    let sync = sync.clone();
                    let _ = handle_control_connection(stream, session, shutdown, ssh_path, sync);
                })
            })
        };

        let ssh_thread = {
            let session = Arc::clone(&self.session);
            let shutdown = Arc::clone(&self.shutdown);
            std::thread::spawn(move || {
                accept_loop(ssh, shutdown, move |stream| {
                    let session = Arc::clone(&session);
                    let _ = handle_ssh_connection(stream, session);
                })
            })
        };

        let reaper = {
            let session = Arc::clone(&self.session);
            let shutdown = Arc::clone(&self.shutdown);
            std::thread::spawn(move || reap_expired_sessions(session, shutdown))
        };

        // Sync gets two threads: one serving peers, one reconciling with
        // them. A failure to bind the port is reported and then ignored —
        // the agent's job of holding the vault open and answering `ssh`
        // must not depend on a network feature being able to start.
        let sync_threads = self.sync.as_ref().map(|node| {
            let serve = match node.bind() {
                Ok(listener) => {
                    let node = node.clone();
                    let shutdown = Arc::clone(&self.shutdown);
                    Some(std::thread::spawn(move || node.serve(listener, shutdown)))
                }
                Err(e) => {
                    node.note(format!("not serving peers: {e}"));
                    None
                }
            };

            let node = node.clone();
            let session = Arc::clone(&self.session);
            let shutdown = Arc::clone(&self.shutdown);
            let reconcile = std::thread::spawn(move || node.run_antientropy(session, shutdown));
            (serve, reconcile)
        });

        let _ = ipc_thread.join();
        let _ = ssh_thread.join();
        let _ = reaper.join();
        if let Some((serve, reconcile)) = sync_threads {
            if let Some(serve) = serve {
                let _ = serve.join();
            }
            let _ = reconcile.join();
        }

        // Persist the op-log on the way out, so a restart does not make
        // every peer re-send everything it already delivered.
        if let Some(node) = &self.sync {
            node.persist();
        }

        // Locking on the way out is belt and braces — the process is about to
        // exit and take the memory with it — but it means a `run()` that
        // returns inside a longer-lived process (a test, an embedded agent)
        // doesn't leave an unlocked session behind.
        if let Ok(mut guard) = self.session.lock() {
            *guard = None;
        }

        let _ = std::fs::remove_file(&self.ipc_path);
        let _ = std::fs::remove_file(&self.ssh_path);
        Ok(())
    }
}

/// Bind a Unix socket, clearing a stale one left by a crashed agent.
fn bind(path: &Path) -> io::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        paths::restrict_to_owner(parent, 0o700)?;
    }

    if path.exists() {
        // A socket that still has an agent behind it must not be stolen; one
        // that refuses connections is debris from a crash and can go.
        match UnixStream::connect(path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("an agent is already listening on {}", path.display()),
                ))
            }
            Err(_) => std::fs::remove_file(path)?,
        }
    }

    let listener = UnixListener::bind(path)?;
    paths::restrict_to_owner(path, 0o600)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Accept connections until shutdown, handing each to `handler` on its own
/// thread.
///
/// Non-blocking accept plus a short sleep, rather than a blocking accept:
/// there is no portable way to interrupt a blocked `accept`, and polling
/// every 100 ms costs nothing measurable for a process that spends its life
/// idle.
fn accept_loop<F>(listener: UnixListener, shutdown: Arc<AtomicBool>, handler: F)
where
    F: Fn(UnixStream) + Send + Sync + Clone + 'static,
{
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                // Connections are long-lived (an `ssh` session holds one open
                // for its whole life), so each gets a thread.
                let handler = handler.clone();
                std::thread::spawn(move || {
                    let _ = stream.set_nonblocking(false);
                    handler(stream);
                });
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(POLL_INTERVAL),
            Err(_) => std::thread::sleep(POLL_INTERVAL),
        }
    }
}

/// Drop the session once it has been idle for its timeout.
fn reap_expired_sessions(session: SharedSession, shutdown: Arc<AtomicBool>) {
    while !shutdown.load(Ordering::SeqCst) {
        if let Ok(mut guard) = session.lock() {
            if guard.as_ref().is_some_and(Session::is_expired) {
                *guard = None;
            }
        }
        std::thread::sleep(REAP_INTERVAL);
    }
}

// ---------------------------------------------------------------------------
// Control socket
// ---------------------------------------------------------------------------

fn handle_control_connection(
    stream: UnixStream,
    session: SharedSession,
    shutdown: Arc<AtomicBool>,
    ssh_path: PathBuf,
    sync: Option<SyncNode>,
) -> io::Result<()> {
    let mut writer = stream.try_clone()?;
    let reader = BufReader::new(stream);

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<Request>(&line) {
            Ok(request) => handle_request(request, &session, &shutdown, &ssh_path, sync.as_ref()),
            Err(e) => Response::error(format!("malformed request: {e}")),
        };

        let encoded = protocol::encode_line(&response)
            .unwrap_or_else(|e| format!("{{\"status\":\"error\",\"message\":\"{e}\"}}\n"));
        writer.write_all(encoded.as_bytes())?;
        writer.flush()?;
    }

    Ok(())
}

fn handle_request(
    request: Request,
    session: &SharedSession,
    shutdown: &Arc<AtomicBool>,
    ssh_path: &Path,
    sync: Option<&SyncNode>,
) -> Response {
    let Ok(mut guard) = session.lock() else {
        // A poisoned mutex means a handler panicked while holding the
        // session. Refusing is the only safe answer: we cannot know what
        // state it left behind.
        return Response::error("agent session is in an inconsistent state; restart the agent");
    };

    match request {
        Request::Status => {
            // Report an expired-but-not-yet-reaped session as locked, so
            // status never claims an unlock the next request won't honour.
            let expired = guard.as_ref().is_some_and(Session::is_expired);
            if expired {
                *guard = None;
            }

            Response::Status(match guard.as_ref() {
                Some(session) => Status {
                    unlocked: true,
                    vault: Some(session.vault_path().to_path_buf()),
                    locks_in_secs: Some(session.time_to_lock().as_secs()),
                    ssh_keys: session.ssh_keys().len(),
                    ssh_auth_sock: ssh_path.to_path_buf(),
                },
                None => Status {
                    unlocked: false,
                    vault: None,
                    locks_in_secs: None,
                    ssh_keys: 0,
                    ssh_auth_sock: ssh_path.to_path_buf(),
                },
            })
        }

        Request::Unlock {
            vault,
            master_password,
            idle_timeout_secs,
        } => {
            let timeout = idle_timeout_secs.map_or(DEFAULT_IDLE_TIMEOUT, Duration::from_secs);
            match Session::unlock(&vault, &master_password, timeout) {
                Ok(mut session) => {
                    // Arming needs the vault open, so it happens here rather
                    // than in the sync loop. A failure is reported in the
                    // sync log and does not fail the unlock: the user asked
                    // for their vault, not for their mesh.
                    if let Some(node) = sync {
                        if let Err(e) = arm_sync(node, &mut session) {
                            node.note(format!("could not start syncing this vault: {e}"));
                        }
                    }
                    *guard = Some(session);
                    Response::Ok
                }
                Err(e) => Response::error(e.to_string()),
            }
        }

        Request::Lock => {
            *guard = None;
            Response::Ok
        }

        Request::ListEntries => with_session(&mut guard, |session| {
            session
                .with_vault(|vault, _| vault.list_entries())
                .map(|entries| Response::Entries { entries })
        }),

        Request::GetEntry { query } => with_session(&mut guard, |session| {
            session
                .with_vault(|vault, _| find_entry(vault, &query))
                .map(|entry| Response::Entry(Box::new(protocol::Entry::from(&entry))))
        }),

        Request::ListSshKeys => with_session(&mut guard, |session| {
            Ok(Response::SshKeys {
                keys: session.ssh_keys().iter().map(passlib::SshKeySummary::from).collect(),
            })
        }),

        Request::ReloadSshKeys => with_session(&mut guard, |session| {
            session.reload_ssh_keys().map(|()| Response::Ok)
        }),

        Request::SyncStatus => match sync {
            Some(node) => Response::Sync(Box::new(node.status())),
            None => Response::error(
                "this agent is not syncing; start it with `pass agent run --sync`",
            ),
        },

        Request::SyncNow => match sync {
            Some(node) => {
                // The round is run on its own thread so a slow or
                // unreachable peer cannot hold the control socket — and the
                // session lock — for the length of a network timeout.
                let node = node.clone();
                let session = Arc::clone(session);
                std::thread::spawn(move || node.sync_once(&session));
                Response::Ok
            }
            None => Response::error(
                "this agent is not syncing; start it with `pass agent run --sync`",
            ),
        },

        Request::Shutdown => {
            *guard = None;
            shutdown.store(true, Ordering::SeqCst);
            Response::Ok
        }
    }
}

/// Bring the sync node up against a freshly unlocked vault: create the sync
/// key and this device's identity if needed, repair a rewound op-log, and
/// refresh the roster.
fn arm_sync(node: &SyncNode, session: &mut Session) -> passlib::Result<()> {
    session.with_vault(|vault, password| {
        let armed = node.arm(vault)?;
        let repaired = node.repair_epoch_if_rewound(vault)?;
        if armed || repaired {
            vault.save(password)?;
        }
        Ok(())
    })
}

/// Run `f` against the unlocked session, or report that there isn't one.
fn with_session(
    guard: &mut Option<Session>,
    f: impl FnOnce(&mut Session) -> passlib::Result<Response>,
) -> Response {
    match guard.as_mut() {
        Some(session) if !session.is_expired() => match f(session) {
            Ok(response) => response,
            Err(e) => Response::error(e.to_string()),
        },
        Some(_) => {
            *guard = None;
            Response::error("the vault locked itself after being idle; unlock it again")
        }
        None => Response::error("no vault is unlocked; run `pass unlock` first"),
    }
}

/// Resolve an entry by id first, then by a case-insensitive website match —
/// the same rule the CLI uses, kept here so every client gets it.
fn find_entry(vault: &passlib::Vault, query: &str) -> passlib::Result<passlib::PasswordEntry> {
    if let Ok(entry) = vault.get_entry(query) {
        return Ok(entry);
    }

    let needle = query.to_lowercase();
    let found = vault
        .list_entries()?
        .into_iter()
        .find(|e| e.website.to_lowercase().contains(&needle))
        .ok_or_else(|| passlib::PassError::EntryNotFound(query.to_string()))?;

    vault.get_entry(&found.id)
}

// ---------------------------------------------------------------------------
// SSH agent socket
// ---------------------------------------------------------------------------

fn handle_ssh_connection(stream: UnixStream, session: SharedSession) -> io::Result<()> {
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);

    while let Some(payload) = sshagent::read_message(&mut reader)? {
        let response = match sshagent::parse_request(&payload) {
            Ok(request) => answer_ssh_request(request, &session),
            // A malformed message is the client's problem; answer FAILURE and
            // keep the connection, rather than dropping a session's agent
            // because one frame was bad.
            Err(_) => sshagent::failure(),
        };
        sshagent::write_message(&mut writer, &response)?;
    }

    Ok(())
}

fn answer_ssh_request(request: AgentRequest, session: &SharedSession) -> Vec<u8> {
    let Ok(mut guard) = session.lock() else {
        return sshagent::failure();
    };

    // A session that has timed out serves nothing, and takes the opportunity
    // to drop itself rather than waiting for the reaper.
    if guard.as_ref().is_some_and(Session::is_expired) {
        *guard = None;
    }

    match request {
        AgentRequest::RequestIdentities => {
            // A locked agent answers "no identities" rather than FAILURE:
            // that is what an empty agent looks like, so `ssh` moves on to
            // its next authentication method instead of erroring out.
            let identities = guard
                .as_mut()
                .map(|session| {
                    session.touch();
                    session
                        .ssh_keys()
                        .iter()
                        .filter_map(|key| {
                            let blob = key.public_key_blob().ok()?;
                            let comment = if key.comment.is_empty() {
                                key.name.clone()
                            } else {
                                key.comment.clone()
                            };
                            Some((blob, comment))
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            sshagent::identities_answer(&identities)
        }

        AgentRequest::Sign { key_blob, data, flags } => {
            let Some(session) = guard.as_mut() else {
                return sshagent::failure();
            };
            session.touch();

            match session.ssh_key_for_blob(&key_blob) {
                Some(key) => match key.sign(&data, flags) {
                    Ok(signature) => sshagent::sign_response(&signature),
                    Err(_) => sshagent::failure(),
                },
                None => sshagent::failure(),
            }
        }

        // Read-only agent: adding, removing and locking are all refused. See
        // the module docs on `sshagent` for why.
        AgentRequest::Unsupported(_) => sshagent::failure(),
    }
}
