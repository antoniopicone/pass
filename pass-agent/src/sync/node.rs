//! The sync node: five endpoints, a round of anti-entropy, and the bridge
//! to the vault.
//!
//! Every node is identical and none is authoritative. That is not a slogan:
//! it is what makes the thing work with no server, and it costs one
//! specific piece of discipline — **correctness lives in the periodic
//! anti-entropy round, never in a notification**. A push that gets lost, a
//! peer that was asleep, a network that came back after twenty minutes: the
//! next round reconciles it anyway, because a round is a full comparison of
//! version vectors rather than an incremental update anyone has to receive.
//!
//! ## A round
//!
//! ```text
//!   probe    GET  /v1/node        who are you, what do you replicate
//!   pull     POST /v1/ops/since   here is my version vector, send what I lack
//!   push     GET  /v1/vv          … and here is what you lack
//!            POST /v1/ops
//!   exchange POST /v1/peers       here is the mesh as I know it
//! ```
//!
//! Symmetric, stateless, and identical on every platform — including the
//! clients that can never be *called*: an iPhone in the background holds no
//! listener, so it drives its own rounds and pushes what its peers lack.
//! Nothing in this design requires anyone to be reachable.
//!
//! ## Peer exchange goes both ways
//!
//! The caller sends its list and receives the union. One direction is not
//! enough: if A never calls B, A never learns B exists, and a device
//! bootstrapped from A stays blind to B forever — discovery would depend on
//! the order things happened to start in.
//!
//! ## What a peer is not, and what it still sees
//!
//! It is not trusted. It cannot inject an op (they are signed by devices in
//! the vault's roster), cannot read one (payloads are sealed), and cannot
//! decide anything about the merge. The worst a hostile peer can do to
//! correctness is withhold ops, which the next round with any other peer
//! repairs.
//!
//! What it *does* see is the metadata: requests are not themselves
//! authenticated, so anything that can reach this port can pull the op-log
//! and read which entry UUIDs changed, on which device, and when. That is
//! the reason [`SyncConfig::bind_address`] does not default to every
//! interface, and it is stated plainly in `SECURITY.md` rather than papered
//! over — authenticating requests would need a challenge-response handshake
//! that this does not have.

use super::bridge::{self, Marks};
use super::discovery::{self, NodeInfo, Peer, PexCache, AGENT_PORT, PROTO};
use super::http::{self, HttpError, HttpResult, Request, Response};
use super::state::{self, SyncState, TrustedDevices};
use crate::protocol::SyncStatus;
use crate::session::Session;
use passlib::sync::{fingerprint_of, Op, Rejected, Replica, VersionVector};
use passlib::{PassError, Result, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

/// How long a peer has to answer one request before the round moves on.
const PEER_TIMEOUT: Duration = Duration::from_secs(5);
/// How many lines of recent activity `pass sync status` can show.
const LOG_LINES: usize = 40;

/// Environment overrides, so a two-node test can run on one machine
/// without a config file.
pub const BIND_ENV: &str = "PASS_SYNC_BIND";
pub const ADVERTISE_ENV: &str = "PASS_SYNC_ADVERTISE";

/// How the node listens and who it talks to.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    pub port: u16,
    /// Address to bind. Defaults to this node's tailnet address, falling
    /// back to loopback — see [`SyncConfig::bind_address`].
    pub bind: Option<String>,
    /// `host:port` this node announces in peer exchange. Defaults to the
    /// tailnet address; empty means "cannot be called, I will call you".
    pub advertise: Option<String>,
    /// Addresses to try before anything has been discovered.
    pub bootstrap: Vec<String>,
    pub interval: Duration,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            port: AGENT_PORT,
            bind: None,
            advertise: None,
            bootstrap: Vec::new(),
            interval: Duration::from_secs(30),
        }
    }
}

impl SyncConfig {
    /// Where to bind, and why the default is not `0.0.0.0`.
    ///
    /// Binding every interface would put this port on whatever café Wi-Fi
    /// the laptop joins next. Everything it serves is signed and sealed, so
    /// that is not a disclosure — but an open port is an open port, and a
    /// password manager should not add one to a hostile network by default.
    /// The tailnet address is already private to the tailnet; loopback is
    /// the safe fallback when there is no tailnet.
    pub fn bind_address(&self) -> String {
        if let Some(bind) = self.bind.clone().or_else(|| std::env::var(BIND_ENV).ok()) {
            return bind;
        }
        discovery::my_tailnet_ip().unwrap_or_else(|| "127.0.0.1".to_string())
    }

    /// What to tell peers to call this node at.
    pub fn advertise_address(&self) -> String {
        if let Some(advertise) = self.advertise.clone().or_else(|| std::env::var(ADVERTISE_ENV).ok()) {
            return advertise;
        }
        discovery::my_tailnet_ip().map_or_else(String::new, |ip| format!("{ip}:{}", self.port))
    }
}

/// A running sync node. Cheap to clone: every clone shares one replica.
#[derive(Clone)]
pub struct SyncNode {
    config: SyncConfig,
    inner: Arc<Inner>,
}

struct Inner {
    replica: Mutex<Replica>,
    marks: Mutex<Marks>,
    trusted: Mutex<TrustedDevices>,
    pex: PexCache,
    hostname: String,
    advertise: String,
    state_path: PathBuf,
    high_water: Mutex<u64>,
    /// Remote ops have been accepted and not yet written to the vault.
    dirty: AtomicBool,
    /// Vault modification time as of the last ingest, so a vault the user
    /// has not touched costs nothing to check.
    seen_vault_mtime: Mutex<Option<SystemTime>>,
    log: Mutex<Vec<String>>,
    /// Devices that asked to sync and are not on the roster, so the user is
    /// told once rather than on every round.
    reported_strangers: Mutex<Vec<String>>,
    /// Hash of this vault's sync key, published in the handshake. Not a
    /// secret — see [`passlib::sync::SyncKey::check_value`].
    key_check: Mutex<String>,
    /// Peers whose vault holds a different sync key, reported once each.
    reported_key_mismatch: Mutex<Vec<String>>,
}

impl SyncNode {
    /// Load persisted state and build a node.
    ///
    /// Works before the vault has ever been unlocked: with no device
    /// identity it serves nothing, but it starts, which means a misconfigured
    /// sync cannot stop the agent from running as an SSH agent.
    pub fn load(config: SyncConfig) -> std::io::Result<Self> {
        let state_path = SyncState::path()?;
        let state = SyncState::load(&state_path)?;
        let (replica, rejected) = state.replica();

        let advertise = config.advertise_address();
        let node = Self {
            config,
            inner: Arc::new(Inner {
                replica: Mutex::new(replica),
                marks: Mutex::new(state.marks),
                trusted: Mutex::new(state.trusted),
                pex: PexCache::load(state.peers),
                hostname: discovery::hostname(),
                advertise,
                state_path,
                high_water: Mutex::new(state.high_water),
                dirty: AtomicBool::new(false),
                seen_vault_mtime: Mutex::new(None),
                log: Mutex::new(Vec::new()),
                reported_strangers: Mutex::new(Vec::new()),
                key_check: Mutex::new(String::new()),
                reported_key_mismatch: Mutex::new(Vec::new()),
            }),
        };

        if rejected > 0 {
            node.note(format!(
                "{rejected} stored op(s) failed verification and were dropped — the state file was \
                 edited, or a device was removed from the roster"
            ));
        }
        Ok(node)
    }

    /// Bring the node up against an unlocked vault: create the sync key and
    /// this device's identity if they do not exist, and refresh the roster.
    ///
    /// Called on every unlock rather than once, because the roster changes
    /// in the vault (a device paired on another machine arrives with the
    /// file) and a stale roster refuses ops it should accept.
    pub fn arm(&self, vault: &mut Vault) -> Result<bool> {
        let mut changed = false;

        let key = match vault.sync_key()? {
            Some(key) => key,
            None => {
                changed = true;
                self.note("created this vault's sync key");
                vault.ensure_sync_key()?
            }
        };
        if let Ok(mut check) = self.inner.key_check.lock() {
            *check = key.check_value()?;
        }

        let mut replica = self.lock_replica()?;
        let fingerprint = fingerprint_of(&replica.device().to_string()).to_string();

        // Identify this device: the one whose key we already hold, or a new
        // one. Matching on the persisted fingerprint rather than on the
        // hostname is what stops two machines with the same hostname from
        // sharing an identity — which would give them one sequence counter
        // between them and lose ops.
        let identity = match vault.sync_device_identity(&fingerprint)? {
            Some(existing) => existing,
            None => {
                let fresh = passlib::sync::DeviceIdentity::generate(&self.inner.hostname)?;
                vault.add_sync_device(&fresh)?;
                changed = true;
                self.note(format!("registered this device as {} ({})", fresh.label, fresh.fingerprint()));
                fresh
            }
        };

        // The roster is refreshed *before* any replay below: replaying ops
        // against a stale roster would silently drop every op signed by a
        // device this vault has learned about since the last run.
        *self.lock_trusted()? = TrustedDevices::from_vault(&vault.sync_devices());

        if replica.device() != identity.device_id() {
            // First arming, or a new epoch: start a replica under the right
            // id and replay what we already hold into it.
            *replica = self.replay_under(identity.device_id(), replica.export_log())?;
        }
        drop(replica);

        self.inner.dirty.store(true, Ordering::SeqCst);
        Ok(changed)
    }

    /// Rebuild a replica under a new device id, keeping the history.
    ///
    /// Ops that no longer verify are reported rather than dropped in
    /// silence: the only ways to get here are a roster that shrank or a
    /// state file that was edited, and both are worth saying out loud.
    fn replay_under(&self, device: passlib::sync::DeviceId, ops: Vec<Op>) -> Result<Replica> {
        let mut fresh = Replica::new(device);
        let trusted = self.lock_trusted()?;
        let dropped = ops.into_iter().filter(|op| fresh.apply(op.clone(), &*trusted).is_err()).count();
        drop(trusted);

        if dropped > 0 {
            self.note(format!("{dropped} stored op(s) no longer verify and were dropped"));
        }
        Ok(fresh)
    }

    /// Detect and repair a rewound op-log, which otherwise breaks sync
    /// silently and permanently. See [`state::log_rewound`].
    pub fn repair_epoch_if_rewound(&self, vault: &mut Vault) -> Result<bool> {
        let replica = self.lock_replica()?;
        let published = replica.next_seq().saturating_sub(1);
        let high_water = *self.lock_high_water()?;
        let device = replica.device().to_string();
        drop(replica);

        if !state::log_rewound(&device, published, high_water) {
            return Ok(false);
        }

        let fingerprint = fingerprint_of(&device).to_string();
        let Some(mut identity) = vault.sync_device_identity(&fingerprint)? else {
            return Ok(false);
        };

        identity.bump_epoch();
        vault.set_sync_device_epoch(&fingerprint, identity.epoch())?;

        let ops = self.lock_replica()?.export_log();
        *self.lock_replica()? = self.replay_under(identity.device_id(), ops)?;
        *self.lock_high_water()? = 0;

        self.note(format!(
            "op-log rewound ({published} < {high_water}): started epoch {} so peers do not discard \
             this device's future changes",
            identity.epoch()
        ));
        Ok(true)
    }

    // -----------------------------------------------------------------
    // Endpoints
    // -----------------------------------------------------------------

    /// Answer one request from a peer.
    pub fn handle(&self, request: Request) -> Response {
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/v1/node") => Response::json(&self.node_info()),
            ("GET", "/v1/vv") => match self.lock_replica() {
                Ok(replica) => Response::json(&replica.version_vector()),
                Err(e) => Response::error(503, &e.to_string()),
            },
            ("POST", "/v1/ops/since") => self.ops_since(&request.body),
            ("POST", "/v1/ops") => self.ops_push(&request.body),
            ("POST", "/v1/peers") => self.peers(&request.body),
            ("GET" | "POST", _) => Response::error(404, "no such endpoint"),
            _ => Response::error(400, "unsupported method"),
        }
    }

    fn node_info(&self) -> NodeInfo {
        NodeInfo {
            proto: PROTO,
            device_id: self.device_id(),
            hostname: self.inner.hostname.clone(),
            services: BTreeMap::from([(passlib::sync::SERVICE.to_string(), self.config.port)]),
            key_check: self.inner.key_check.lock().map(|k| k.clone()).unwrap_or_default(),
        }
    }

    fn ops_since(&self, body: &[u8]) -> Response {
        #[derive(Deserialize)]
        struct Req {
            vv: VersionVector,
        }

        let Ok(req) = serde_json::from_slice::<Req>(body) else {
            return Response::error(400, "expected {\"vv\": {...}}");
        };
        match self.lock_replica() {
            Ok(replica) => Response::json(&OpsBody { ops: replica.ops_since(&req.vv) }),
            Err(e) => Response::error(503, &e.to_string()),
        }
    }

    fn ops_push(&self, body: &[u8]) -> Response {
        let Ok(req) = serde_json::from_slice::<OpsBody>(body) else {
            return Response::error(400, "expected {\"ops\": [...]}");
        };

        let (applied, refused) = self.apply_all(req.ops);
        match self.lock_replica() {
            Ok(replica) => Response::json(&serde_json::json!({
                "applied": applied,
                "refused": refused,
                "vv": replica.version_vector(),
            })),
            Err(e) => Response::error(503, &e.to_string()),
        }
    }

    fn peers(&self, body: &[u8]) -> Response {
        #[derive(Deserialize, Default)]
        struct Req {
            #[serde(default)]
            peers: Vec<Peer>,
        }

        let req = serde_json::from_slice::<Req>(body).unwrap_or_default();
        let me = self.device_id();
        self.inner.pex.merge(req.peers, &me);

        let mut out: Vec<Peer> = self.inner.pex.list();
        if let Some(me) = self.me_as_peer() {
            out.push(me);
        }
        Response::json(&out)
    }

    // -----------------------------------------------------------------
    // Client side of a round
    // -----------------------------------------------------------------

    /// One round with one peer. Returns `(pulled, pushed)`.
    pub fn sync_round(&self, addr: &str) -> HttpResult<(usize, usize)> {
        let info: NodeInfo = http::get_json(addr, "/v1/node", PEER_TIMEOUT)?;
        if info.proto != PROTO {
            return Err(HttpError::Status {
                code: 400,
                message: format!("peer speaks sync protocol {}, this agent speaks {PROTO}", info.proto),
            });
        }
        let me = self.device_id();
        if !me.is_empty() && info.device_id == me {
            return Ok((0, 0)); // ourselves, reached by another address
        }
        self.check_sync_key(&info);

        // 1. Pull: what does it have that we lack.
        let my_vv = self.lock_replica().map_err(state_error)?.version_vector();
        let pulled: OpsBody = http::post_json(
            addr,
            "/v1/ops/since",
            &serde_json::json!({ "vv": my_vv }),
            PEER_TIMEOUT,
        )?;
        let (applied, _) = self.apply_all(pulled.ops);

        // 2. Push: what do we have that it lacks. Asked *after* the pull so
        //    that anything just learned goes out in the same round.
        let their_vv: VersionVector = http::get_json(addr, "/v1/vv", PEER_TIMEOUT)?;
        let mine = self.lock_replica().map_err(state_error)?.ops_since(&their_vv);
        let pushed = if mine.is_empty() {
            0
        } else {
            #[derive(Deserialize)]
            struct PushResp {
                applied: usize,
            }
            let resp: PushResp = http::post_json(addr, "/v1/ops", &OpsBody { ops: mine }, PEER_TIMEOUT)?;
            resp.applied
        };

        // 3. Peer exchange, both ways.
        let mut known = self.inner.pex.list();
        known.extend(self.me_as_peer());
        if let Ok(list) = http::post_json::<_, Vec<Peer>>(
            addr,
            "/v1/peers",
            &serde_json::json!({ "peers": known }),
            PEER_TIMEOUT,
        ) {
            self.inner.pex.merge(list, &self.device_id());
        }

        // The peer that answered is worth remembering by the address that
        // actually worked, whatever it advertises.
        self.inner.pex.merge(
            vec![Peer { hostname: info.hostname, addr: addr.to_string(), device_id: info.device_id }],
            &self.device_id(),
        );

        Ok((applied, pushed))
    }

    /// Apply a batch of ops, returning `(applied, refused)`.
    ///
    /// Duplicates and causal gaps are silent: both are normal on a healthy
    /// round. An op from a device the vault has not been told to trust is
    /// *not* silent — that is a user telling this device to pair, and it
    /// needs to be visible or pairing looks broken.
    fn apply_all(&self, ops: Vec<Op>) -> (usize, usize) {
        let Ok(mut replica) = self.inner.replica.lock() else {
            return (0, 0);
        };
        let Ok(trusted) = self.inner.trusted.lock() else {
            return (0, 0);
        };

        let mut ops = ops;
        ops.sort_by(|a, b| (&a.device, a.seq).cmp(&(&b.device, b.seq)));

        let mut applied = 0;
        let mut refused = 0;
        let mut strangers = Vec::new();

        for op in ops {
            match replica.apply(op, &*trusted) {
                Ok(()) => applied += 1,
                Err(Rejected::UntrustedDevice(fingerprint)) => {
                    refused += 1;
                    if !strangers.contains(&fingerprint) {
                        strangers.push(fingerprint);
                    }
                }
                Err(Rejected::BadSignature) => refused += 1,
                Err(_) => {}
            }
        }
        drop(trusted);
        drop(replica);

        for fingerprint in strangers {
            self.report_stranger(&fingerprint);
        }
        if applied > 0 {
            self.inner.dirty.store(true, Ordering::SeqCst);
        }
        (applied, refused)
    }

    /// Warn, once per peer, when its vault holds a different sync key.
    ///
    /// The two devices will still exchange ops — everything else about them
    /// is valid — but neither can open the other's payloads. Diagnosed here
    /// rather than left to surface as a decryption error per op, because
    /// the cause ("these two vaults are not copies of each other") is not
    /// something anyone would infer from "could not open a sync payload".
    fn check_sync_key(&self, info: &NodeInfo) {
        let mine = self.inner.key_check.lock().map(|k| k.clone()).unwrap_or_default();
        if mine.is_empty() || info.key_check.is_empty() || info.key_check == mine {
            return;
        }

        let Ok(mut reported) = self.inner.reported_key_mismatch.lock() else {
            return;
        };
        if reported.contains(&info.device_id) {
            return;
        }
        reported.push(info.device_id.clone());
        drop(reported);

        self.note(format!(
            "{} holds a different vault: its sync key is {} and this one's is {mine}. Two vaults              that were created separately cannot sync — copy this vault's file to that device once,              then unlock it there.",
            info.hostname, info.key_check
        ));
    }

    /// Tell the user, once, about a device that wants to sync and is not
    /// trusted. Repeating it every round would bury the message it matters.
    fn report_stranger(&self, fingerprint: &str) {
        let Ok(mut reported) = self.inner.reported_strangers.lock() else {
            return;
        };
        if reported.iter().any(|f| f == fingerprint) {
            return;
        }
        reported.push(fingerprint.to_string());
        drop(reported);

        self.note(format!(
            "refused changes from unknown device {fingerprint} — if it is yours, run \
             `pass sync trust {fingerprint}`"
        ));
    }

    // -----------------------------------------------------------------
    // The loop
    // -----------------------------------------------------------------

    /// Serve and reconcile until `shutdown` is set.
    ///
    /// Returns the bound address so a caller (a test, or the CLI's startup
    /// banner) can report where the node actually landed when the port was
    /// left to the OS.
    pub fn bind(&self) -> std::io::Result<TcpListener> {
        let address = self.config.bind_address();
        TcpListener::bind((address.as_str(), self.config.port))
    }

    /// Serve peers on `listener` until shutdown.
    pub fn serve(&self, listener: TcpListener, shutdown: Arc<AtomicBool>) {
        let node = self.clone();
        http::serve(listener, shutdown, move |request| node.handle(request));
    }

    /// Reconcile with every known peer, then with the vault, forever.
    pub fn run_antientropy(&self, session: Arc<Mutex<Option<Session>>>, shutdown: Arc<AtomicBool>) {
        while !shutdown.load(Ordering::SeqCst) {
            self.round(&session, Some(shutdown.as_ref()));
            sleep_until(shutdown.as_ref(), self.config.interval);
        }
    }

    /// One full round, on demand — what `pass sync now` triggers rather
    /// than waiting out the interval.
    pub fn sync_once(&self, session: &Arc<Mutex<Option<Session>>>) {
        self.round(session, None);
    }

    /// Publish, exchange, apply, persist.
    ///
    /// The vault pass happens on both sides of the exchange on purpose: the
    /// one before publishes an edit made a second ago in *this* round rather
    /// than the next, and the one after writes down what just arrived.
    fn round(&self, session: &Arc<Mutex<Option<Session>>>, shutdown: Option<&AtomicBool>) {
        let stopping = || shutdown.is_some_and(|s| s.load(Ordering::SeqCst));

        self.vault_pass(session);

        for target in self.targets() {
            if stopping() {
                return;
            }
            match self.sync_round(&target) {
                Ok((0, 0)) => {}
                Ok((pulled, pushed)) => {
                    self.note(format!("{target}: +{pulled} received, +{pushed} sent"))
                }
                // Unreachable peers are the normal state of a mesh of
                // laptops and phones, and logging each one every round would
                // drown everything worth reading.
                Err(HttpError::Unreachable(_)) => {}
                Err(e) => self.note(format!("{target}: {e}")),
            }
        }

        self.vault_pass(session);
        self.persist();
    }

    /// Everything worth trying this round, deduplicated.
    fn targets(&self) -> Vec<String> {
        let mut targets: Vec<String> = self.config.bootstrap.clone();
        targets.extend(
            discovery::tailnet_candidates()
                .into_iter()
                .map(|(_, ip)| format!("{ip}:{AGENT_PORT}")),
        );
        targets.extend(self.inner.pex.list().into_iter().map(|p| p.addr));

        targets.sort();
        targets.dedup();
        targets.retain(|t| !t.is_empty() && *t != self.inner.advertise);
        targets
    }

    /// Move changes between the vault and the op-log, in whichever
    /// direction has something to say.
    ///
    /// Opening the vault means Argon2id at 64 MiB — hundreds of milliseconds
    /// by design — so this does nothing at all unless the vault's
    /// modification time moved (a local edit) or an op arrived from a peer.
    /// In the steady state a round costs no vault work.
    pub fn vault_pass(&self, session: &Arc<Mutex<Option<Session>>>) {
        let Ok(mut guard) = session.lock() else {
            return;
        };
        let Some(active) = guard.as_mut().filter(|s| !s.is_expired()) else {
            return;
        };

        // Stat *before* the vault is opened, and remember this value rather
        // than a fresh one at the end.
        //
        // Taking it afterwards loses writes: `pass add` running while this
        // pass is working leaves a modification time the pass then records
        // as "seen", even though what it read predates that write. The entry
        // is then never published — not late, never — until something else
        // happens to touch the file. Recording the pre-open time can instead
        // only cause a redundant re-read, and ingest mints nothing when the
        // content hashes still match.
        let observed = modified_at(active.vault_path());
        let ingest_needed = self
            .inner
            .seen_vault_mtime
            .lock()
            .map(|seen| *seen != observed)
            .unwrap_or(false);
        let materialise_needed = self.inner.dirty.load(Ordering::SeqCst);

        if !ingest_needed && !materialise_needed {
            return;
        }

        // Deliberately does not touch the session: a background round must
        // not keep an idle vault unlocked forever. Auto-lock is a security
        // property, and sync is not a reason to suspend it.
        let outcome = active.with_vault_untouched(|vault, password| {
            self.reconcile(vault, password, ingest_needed, materialise_needed)
        });

        match outcome {
            Ok(pass) => {
                if let Ok(mut seen) = self.inner.seen_vault_mtime.lock() {
                    // Our own write is the one case where the *current* time
                    // is the right one to record — the pass verified nothing
                    // else had written before saving, so this modification is
                    // known to be ours and is not a local edit to publish.
                    *seen = if pass.wrote_vault {
                        modified_at(active.vault_path())
                    } else {
                        observed
                    };
                }
                // Only when the pass actually finished. A pass that backed
                // off because the file changed under it must stay pending,
                // or the changes it did not write would never be retried.
                if pass.completed {
                    self.inner.dirty.store(false, Ordering::SeqCst);
                }
            }
            Err(e) => self.note(format!("vault pass failed: {e}")),
        }
    }

    /// Move changes in both directions against an open vault.
    fn reconcile(
        &self,
        vault: &mut Vault,
        password: &str,
        ingest: bool,
        materialise: bool,
    ) -> Result<VaultPass> {
        let Some(key) = vault.sync_key()? else {
            // Sync was never set up on this vault, or the key entry was
            // deleted. Either way there is nothing to seal payloads with.
            return Ok(VaultPass::done());
        };

        // The vault is open anyway, so this is the cheapest moment to pick
        // up a device the user just trusted — and it means `pass sync trust`
        // takes effect at the next round rather than at the next unlock.
        *self.lock_trusted()? = TrustedDevices::from_vault(&vault.sync_devices());
        if let Ok(mut check) = self.inner.key_check.lock() {
            *check = key.check_value()?;
        }

        let mut replica = self.lock_replica()?;
        let fingerprint = fingerprint_of(&replica.device().to_string()).to_string();
        let Some(identity) = vault.sync_device_identity(&fingerprint)? else {
            return Ok(VaultPass::done());
        };
        let mut marks = self.lock_marks()?;

        // Publishing reads the vault and writes only the op-log, so it is
        // committed unconditionally: the ops describe what was on disk when
        // it was read, which stays true whatever happens next.
        if ingest {
            let minted = bridge::ingest(vault, &mut replica, &mut marks, &key, &identity)?;
            if !minted.is_empty() {
                self.note(format!("published {} local change(s)", minted.len()));
            }
            if let Ok(mut high_water) = self.inner.high_water.lock() {
                *high_water = (*high_water).max(replica.next_seq().saturating_sub(1));
            }
        }

        if !materialise {
            return Ok(VaultPass::done());
        }

        // Writing back is the risky half. `Vault::save` rewrites the whole
        // file from what was read at the start of this call, so anything
        // another process wrote in between — `pass add`, `pass sync trust`,
        // a merge from the file-sync transport — would be erased. The marks
        // are therefore staged and only committed once the file has actually
        // been written, so a round that backs off leaves nothing claiming to
        // be reconciled that is not.
        let opened_at = modified_at(vault.path());
        let mut staged = marks.clone();
        let applied = bridge::materialise(vault, &replica, &mut staged, &key)?;
        let mut wrote_vault = false;

        if applied.changed() {
            if modified_at(vault.path()) != opened_at {
                self.note("the vault changed while syncing; leaving it alone until the next round");
                return Ok(VaultPass { completed: false, wrote_vault: false });
            }
            vault.save(password)?;
            wrote_vault = true;
            self.note(format!("applied from peers: {applied}"));
        }
        if applied.unreadable > 0 {
            // The handshake usually reports this first and by name; this is
            // the backstop for ops relayed by a third device.
            self.note(format!(
                "{} op(s) could not be opened with this vault's sync key and were left alone",
                applied.unreadable
            ));
        }
        if applied.failed > 0 {
            self.note(format!(
                "{} change(s) from peers could not be written into the vault; they will be retried",
                applied.failed
            ));
        }

        *marks = staged;
        Ok(VaultPass { completed: true, wrote_vault })
    }

    // -----------------------------------------------------------------
    // Reporting
    // -----------------------------------------------------------------

    pub fn status(&self) -> SyncStatus {
        let (device, ops, entries, fingerprint) = match self.lock_replica() {
            Ok(replica) => (
                replica.device().to_string(),
                replica.op_count(),
                replica.entries().len(),
                replica.fingerprint(),
            ),
            Err(_) => (String::new(), 0, 0, String::new()),
        };

        SyncStatus {
            device,
            hostname: self.inner.hostname.clone(),
            advertise: self.inner.advertise.clone(),
            listening_on: format!("{}:{}", self.config.bind_address(), self.config.port),
            ops,
            entries,
            trusted_devices: self.lock_trusted().map(|t| t.len()).unwrap_or(0),
            fingerprint,
            peers: self.inner.pex.list(),
            pending_vault_write: self.inner.dirty.load(Ordering::SeqCst),
            log: self.inner.log.lock().map(|l| l.clone()).unwrap_or_default(),
        }
    }

    /// Persist the op-log, marks, roster and peer cache.
    pub fn persist(&self) {
        let Ok(replica) = self.inner.replica.lock() else {
            return;
        };
        let state = SyncState {
            device: replica.device().to_string(),
            high_water: self
                .inner
                .high_water
                .lock()
                .map(|h| (*h).max(replica.next_seq().saturating_sub(1)))
                .unwrap_or(0),
            ops: replica.export_log(),
            marks: self.inner.marks.lock().map(|m| m.clone()).unwrap_or_default(),
            peers: self.inner.pex.list(),
            trusted: self.inner.trusted.lock().map(|t| t.clone()).unwrap_or_default(),
        };
        drop(replica);

        if let Err(e) = state.save(&self.inner.state_path) {
            self.note(format!("could not save sync state: {e}"));
        }
    }

    /// Record a line for `pass sync status`, newest first.
    pub fn note(&self, line: impl Into<String>) {
        let line = line.into();
        if let Ok(mut log) = self.inner.log.lock() {
            log.insert(0, line.clone());
            log.truncate(LOG_LINES);
        }
        eprintln!("[sync] {line}");
    }

    pub fn device_id(&self) -> String {
        self.lock_replica().map(|r| r.device().to_string()).unwrap_or_default()
    }

    /// How to introduce this node in peer exchange — `None` until it has an
    /// identity, so an unarmed node does not get cached under the empty id.
    fn me_as_peer(&self) -> Option<Peer> {
        let device_id = self.device_id();
        (!device_id.is_empty()).then(|| Peer {
            hostname: self.inner.hostname.clone(),
            addr: self.inner.advertise.clone(),
            device_id,
        })
    }

    // A poisoned lock means a thread panicked mid-update; refusing is the
    // only safe answer, since the replica's invariants may not hold.
    fn lock_replica(&self) -> Result<std::sync::MutexGuard<'_, Replica>> {
        self.inner.replica.lock().map_err(|_| poisoned("replica"))
    }

    fn lock_marks(&self) -> Result<std::sync::MutexGuard<'_, Marks>> {
        self.inner.marks.lock().map_err(|_| poisoned("marks"))
    }

    fn lock_trusted(&self) -> Result<std::sync::MutexGuard<'_, TrustedDevices>> {
        self.inner.trusted.lock().map_err(|_| poisoned("roster"))
    }

    fn lock_high_water(&self) -> Result<std::sync::MutexGuard<'_, u64>> {
        self.inner.high_water.lock().map_err(|_| poisoned("sequence counter"))
    }
}

/// What one pass over the vault did.
struct VaultPass {
    /// The pass ran to the end; `false` means it backed off because
    /// something else wrote the vault while it worked.
    completed: bool,
    /// The pass itself saved the vault, so its new modification time is
    /// this agent's own doing rather than an edit to publish.
    wrote_vault: bool,
}

impl VaultPass {
    /// Finished, with nothing written.
    fn done() -> Self {
        Self { completed: true, wrote_vault: false }
    }
}

#[derive(Serialize, Deserialize)]
struct OpsBody {
    ops: Vec<Op>,
}

fn poisoned(what: &str) -> PassError {
    PassError::Sync(format!("the sync {what} is in an inconsistent state; restart the agent"))
}

fn state_error(e: PassError) -> HttpError {
    HttpError::Malformed(e.to_string())
}

fn modified_at(path: &std::path::Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}

/// Sleep in short steps so shutdown is noticed promptly even with a long
/// sync interval.
fn sleep_until(shutdown: &AtomicBool, total: Duration) {
    const STEP: Duration = Duration::from_millis(200);
    let mut slept = Duration::ZERO;
    while slept < total && !shutdown.load(Ordering::SeqCst) {
        std::thread::sleep(STEP);
        slept += STEP;
    }
}
