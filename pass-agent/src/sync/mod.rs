//! Peer-to-peer sync between a person's own devices.
//!
//! The replicated data type lives in [`passlib::sync`] — deliberately, so
//! that the CLI, the GUIs and (through `passlib_ffi`) the Apple clients all
//! merge with the same code rather than with four implementations of the
//! same rule. What is here is everything that touches the outside world:
//!
//! | module | job |
//! |---|---|
//! | [`discovery`] | finding peers: tailnet, peer exchange, bootstrap |
//! | [`http`] | the wire: five JSON endpoints over HTTP/1.1 |
//! | [`bridge`] | vault ⇄ op-log, in both directions |
//! | [`state`] | what survives a restart, and the roster |
//! | [`node`] | the endpoints, a round of anti-entropy, the loop |
//!
//! ## Security in one paragraph
//!
//! An op is sealed with a key that exists only inside the vault and signed
//! by a device listed in that vault's roster. A peer therefore cannot read
//! what it relays, cannot write into a replica unless the user paired it,
//! and cannot influence the merge. The transport is plain HTTP on a port
//! bound to the tailnet address, and that is not an oversight: confidentiality
//! and authenticity are properties of the op, not of the connection, which
//! is what allows an untrusted always-on machine to be useful as a relay.

pub mod bridge;
pub mod discovery;
pub mod http;
pub mod node;
pub mod state;

pub use discovery::{Peer, AGENT_PORT};
pub use crate::protocol::SyncStatus;
pub use node::{SyncConfig, SyncNode};
