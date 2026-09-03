//! Finding the other devices.
//!
//! ## Why not mDNS
//!
//! `docs/SYNC_STRATEGY.md` proposed mDNS/DNS-SD, which is the right answer
//! for two machines on one LAN and the wrong one the moment they are not:
//! multicast does not cross a router, and a tailnet does not carry it at
//! all. Since the interesting case — laptop at a café, desktop at home — is
//! exactly the one mDNS cannot serve, discovery here is built on three
//! sources that do work across networks, in increasing order of
//! independence:
//!
//! 1. **A bootstrap address** the user configures once. Always available,
//!    including for clients that can see nothing else (an App Store iOS app
//!    cannot talk to `tailscaled`'s socket, so it cannot enumerate anything).
//! 2. **The tailnet**, via `tailscale status --json`. Zero configuration
//!    where Tailscale is running.
//! 3. **Peer exchange**, and this is the one that matters: after a single
//!    contact with any peer, a device knows the whole mesh, and keeps
//!    knowing it if Tailscale is uninstalled tomorrow.
//!
//! ## One port per device, not one per service
//!
//! The obvious design is a conventional port per service. It does work, and
//! it costs N×M connection attempts per discovery round — 6 devices × 8
//! services is 48 probes, nearly all of them timing out — while a port also
//! collides: `2283` identifies "something that speaks Immich", not *your*
//! Immich, so a stray container on a shared tailnet answers too.
//!
//! Here there is one port per device ([`AGENT_PORT`]), and asking it once
//! returns every service that device replicates ([`NodeInfo::services`]).
//! N probes instead of N×M, and adding a service does not touch discovery.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// The one conventional port a `pass` sync agent listens on.
///
/// Deliberately not the control socket and not an application port: the
/// sync layer should not inherit another service's lifecycle, permissions
/// or bugs.
pub const AGENT_PORT: u16 = 47100;

/// Wire protocol version. Bumped when the endpoints change shape, so an
/// old peer is told plainly instead of being misparsed.
pub const PROTO: u32 = 1;

/// What a device answers on `/v1/node` — the handshake, and the index of
/// everything it replicates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub proto: u32,
    /// The replica's wire id, `<fingerprint>@<epoch>`.
    pub device_id: String,
    pub hostname: String,
    /// Service name to the port it runs on. One probe per peer lists them
    /// all; today that is just `pass`.
    pub services: BTreeMap<String, u16>,
    /// A hash of the vault's sync key (see
    /// [`passlib::sync::SyncKey::check_value`]), so two devices holding
    /// unrelated vaults find out at the handshake instead of exchanging ops
    /// neither can open. Empty on a node that has never been unlocked, and
    /// on one speaking an older build.
    #[serde(default)]
    pub key_check: String,
}

/// A device this one knows how to reach.
///
/// The same type a client sees in [`crate::protocol::SyncStatus`]: a peer
/// list is a peer list, and two structs that must stay in step are one
/// struct that has not been noticed yet.
///
/// `addr` is `host:port`, and empty for a peer that cannot accept
/// connections — an iPhone in the background holds no listener, and saying
/// so is better than every other device retrying it forever.
pub use crate::protocol::SyncPeer as Peer;

/// Peers learned from handshakes, independent of how they were first found.
///
/// This is what makes discovery survive its own source: once a peer is in
/// here, finding it again does not need `tailscaled`, a bootstrap address,
/// or the network it was first seen on.
#[derive(Clone, Default)]
pub struct PexCache(Arc<Mutex<BTreeMap<String, Peer>>>);

impl PexCache {
    /// Absorb peers learned from a handshake, ignoring unreachable ones,
    /// anything claiming to be us, and anything that has not said who it is.
    ///
    /// The last of those is not hypothetical: a node whose vault has never
    /// been unlocked has no identity yet, and recording it under the empty
    /// id means that when it finally gets one, the same machine sits in
    /// every peer's cache twice.
    pub fn merge(&self, peers: Vec<Peer>, me: &str) {
        let Ok(mut cache) = self.0.lock() else {
            return;
        };
        for peer in peers {
            if peer.addr.is_empty() || peer.device_id.is_empty() || peer.device_id == me {
                continue;
            }
            cache.insert(peer.device_id.clone(), peer);
        }
    }

    pub fn list(&self) -> Vec<Peer> {
        self.0.lock().map(|c| c.values().cloned().collect()).unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.0.lock().map(|c| c.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Restore a cache persisted across restarts.
    pub fn load(peers: Vec<Peer>) -> Self {
        let cache = Self::default();
        cache.merge(peers, "");
        cache
    }
}

/// Online peers in the local tailnet, as `(hostname, ip)`.
///
/// Empty — never an error — when Tailscale is not installed, not running,
/// or not readable by this user. Discovery has three sources and losing one
/// is not a failure worth propagating; on Linux, making this one work needs
/// `tailscale set --operator=$USER`, since otherwise `tailscaled`'s socket
/// is root-only.
pub fn tailnet_candidates() -> Vec<(String, String)> {
    let Some(status) = tailscale_status() else {
        return Vec::new();
    };
    let Some(peers) = status.get("Peer").and_then(|p| p.as_object()) else {
        return Vec::new();
    };

    peers
        .values()
        .filter(|node| node.get("Online").and_then(serde_json::Value::as_bool).unwrap_or(false))
        .filter_map(|node| {
            let host = node.get("HostName").and_then(|h| h.as_str()).unwrap_or("?").to_string();
            let ip = node
                .get("TailscaleIPs")
                .and_then(|i| i.as_array())
                .and_then(|a| a.first())
                .and_then(|i| i.as_str())?;
            Some((host, ip.to_string()))
        })
        .collect()
}

/// This node's own tailnet address, for announcing itself in peer exchange.
///
/// Announcing `127.0.0.1` would propagate an address nobody else can use,
/// and the peer that believed it would keep trying it.
pub fn my_tailnet_ip() -> Option<String> {
    tailscale_status()?
        .get("Self")?
        .get("TailscaleIPs")?
        .as_array()?
        .first()?
        .as_str()
        .map(String::from)
}

fn tailscale_status() -> Option<serde_json::Value> {
    let output = std::process::Command::new("tailscale")
        .args(["status", "--json"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    serde_json::from_slice(&output.stdout).ok()
}

/// This machine's name, for showing peers something readable.
pub fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: &str, addr: &str) -> Peer {
        Peer {
            hostname: id.to_string(),
            addr: addr.to_string(),
            device_id: id.to_string(),
        }
    }

    #[test]
    fn the_cache_keeps_one_entry_per_device() {
        let cache = PexCache::default();
        cache.merge(vec![peer("a@1", "10.0.0.1:47100")], "me@1");
        cache.merge(vec![peer("a@1", "10.0.0.2:47100")], "me@1");

        assert_eq!(cache.len(), 1);
        assert_eq!(cache.list()[0].addr, "10.0.0.2:47100", "a peer that moved was not updated");
    }

    #[test]
    fn the_cache_ignores_ourselves() {
        let cache = PexCache::default();
        cache.merge(vec![peer("me@1", "10.0.0.1:47100"), peer("a@1", "10.0.0.2:47100")], "me@1");

        assert_eq!(cache.len(), 1);
        assert_eq!(cache.list()[0].device_id, "a@1");
    }

    #[test]
    fn the_cache_ignores_peers_that_cannot_be_reached() {
        let cache = PexCache::default();
        cache.merge(vec![peer("phone@1", "")], "me@1");
        assert!(cache.is_empty(), "an unreachable peer would be retried forever");
    }

    #[test]
    fn the_cache_ignores_a_peer_that_has_no_identity_yet() {
        let cache = PexCache::default();
        cache.merge(vec![peer("", "10.0.0.1:47100")], "me@1");
        assert!(
            cache.is_empty(),
            "an unarmed peer recorded under the empty id shows up twice once it has a real one"
        );
    }

    #[test]
    fn a_cache_survives_a_restart() {
        let cache = PexCache::default();
        cache.merge(vec![peer("a@1", "10.0.0.1:47100")], "me@1");

        let restored = PexCache::load(cache.list());
        assert_eq!(restored.list(), cache.list());
    }

    #[test]
    fn a_missing_tailscale_is_not_an_error() {
        // Whether Tailscale is installed on the machine running the tests is
        // not something to assert on; that this returns rather than failing
        // is.
        let _ = tailnet_candidates();
        let _ = my_tailnet_ip();
    }

    #[test]
    fn node_info_round_trips_as_json() {
        let info = NodeInfo {
            proto: PROTO,
            device_id: "abc@1".into(),
            hostname: "laptop".into(),
            services: BTreeMap::from([("pass".to_string(), AGENT_PORT)]),
            key_check: "abcdef0123456789".into(),
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: NodeInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(back.device_id, info.device_id);
        assert_eq!(back.services["pass"], AGENT_PORT);
        assert_eq!(back.key_check, info.key_check);
    }
}
