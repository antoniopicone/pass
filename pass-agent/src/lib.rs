//! # pass-agent — the background process that holds the vault unlocked
//!
//! Without an agent, every `pass` command has to ask for the master password
//! and run Argon2id again, and features that must answer *without* a prompt —
//! an SSH agent, autotype, injecting a secret into a command's environment —
//! are simply impossible. This crate is the piece that makes them possible.
//!
//! It listens on two Unix sockets:
//!
//! | socket | protocol | who talks to it |
//! |---|---|---|
//! | `agent.sock` | [`protocol`], newline-delimited JSON | the `pass` CLI, the GUIs, the browser host |
//! | `ssh-agent.sock` | [`sshagent`], the OpenSSH agent protocol | `ssh`, `git`, anything reading `SSH_AUTH_SOCK` |
//!
//! ## Security posture
//!
//! - Between requests the process holds **no decrypted vault**: only the
//!   master password and the SSH keys, each encrypted in RAM
//!   ([`passlib::Shielded`]) and locked out of swap. See [`session`].
//! - The session auto-locks after an idle timeout, wiping both.
//! - Both sockets are `0600` inside a `0700` directory — OpenSSH's own model
//!   for `ssh-agent`. See [`paths`].
//! - The SSH agent is read-only: `ssh-add` cannot add, remove, or overwrite
//!   keys, because keys belong in the vault and nowhere else.
//!
//! ## Platform support
//!
//! Unix only. The transport is Unix domain sockets; the Windows equivalent is
//! named pipes plus a different SSH agent convention (Pageant or the OpenSSH
//! named pipe), which is a separate piece of work rather than a recompile.
//! [`protocol`] and [`sshagent`] are portable, so that work is confined to the
//! transport.

pub mod paths;
pub mod protocol;
pub mod session;
pub mod sshagent;

#[cfg(unix)]
pub mod sync;

#[cfg(unix)]
pub mod client;
#[cfg(unix)]
pub mod server;

#[cfg(unix)]
pub use client::{AgentError, Client};
#[cfg(unix)]
pub use server::Agent;

pub use protocol::{Request, Response, Status};
#[cfg(unix)]
pub use sync::{SyncConfig, SyncNode, SyncStatus};
pub use session::{Session, DEFAULT_IDLE_TIMEOUT};
