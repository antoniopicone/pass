//! pass-syncd — the embedded, single-purpose sync daemon behind `pass`'s
//! real-time cross-device sync.
//!
//! Design lineage: this is a sibling fork of
//! karakeep-browser-extension's `reading-list-syncd`, which is itself a
//! scoped-down fork of github.com/antoniopicone/serverless-sync's `syncd`
//! (see core.rs and discovery.rs, copied over near-verbatim from
//! reading-list-syncd — main.rs/persist.rs are adapted here, same as they
//! were there). Same reasoning as reading-list-syncd: this binary hosts
//! exactly one dataset (one `pass` vault's entries) with no registry, no
//! per-app secret, and — unlike reading-list-syncd — no Native Messaging
//! bridge mode either, since none of `pass`'s clients (the CLI, the
//! Chromium extension's native host, the GNOME app, the Apple app) are
//! spawned per-call by a browser the way reading-list-syncd's bridge mode
//! is; they can all just be plain HTTP clients of the loopback API below.
//! So there is exactly one run mode:
//!
//!   pass-syncd serve [--device NAME] [--port N] [--data PATH]
//!                     [--bootstrap host:port,...] [--advertise ADDR]
//!                     [--peer-prefix PREFIX] [--no-lan-discovery]
//!       The long-running background daemon (installed as a systemd/
//!       launchd/Task Scheduler service — see service/): owns the CSV
//!       ledger, runs the peer-to-peer anti-entropy loop against other
//!       devices, and exposes a small loopback-only HTTP control API on
//!       `--port` (default 47210).
//!
//! # Encryption
//!
//! This daemon never sees a password in the clear. Every `value` it stores
//! or relays — in the CSV ledger, over the local loopback API, and over
//! the peer-to-peer wire — is already an opaque, encrypted-and-base64
//! blob by the time it reaches here: `passlib::sync` (the client-side
//! module every `pass` frontend calls into) derives a key from the vault's
//! own master password and a per-vault salt stored in the KDBX file, and
//! encrypts each entry's payload with AES-256-GCM before ever calling
//! `POST /write`. This daemon's job is purely to replicate opaque blobs by
//! `entity` (a password entry's UUID) with last-writer-wins semantics — see
//! core.rs — exactly as content-agnostic as reading-list-syncd's own
//! design, just with sensitive content this time.
//!
//! Peer-to-peer *transport* is unencrypted at this layer, same as
//! reading-list-syncd (see its README's "Known limitation" section): the
//! primary transport (Tailscale) already runs inside its own WireGuard
//! tunnel, and the LAN-broadcast fallback is opt-in and intended for a
//! trusted home network. What travels over that transport is still only
//! ciphertext, so a passive observer on an untrusted LAN learns nothing
//! about entry contents even without this layer's own encryption — only
//! traffic metadata (which entities changed, when, from which device).

mod core;
mod discovery;
mod persist;

use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use core::{Op, OpKind, Replica, VersionVector};
use discovery::{Peer, PexCache};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const PROTO: u32 = 1;
const DEFAULT_PORT: u16 = 47210;

fn arg(args: &[String], k: &str) -> Option<String> {
    let eq_prefix = format!("{k}=");
    args.iter().find_map(|a| a.strip_prefix(&eq_prefix).map(String::from)).or_else(|| {
        args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).cloned()
    })
}

fn generate_device_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let pid = std::process::id();
    format!("device-{nanos:x}-{pid:x}")
}

/// Resolves this daemon's device id: `--device` always wins; otherwise a
/// persisted one from a previous run at this `--data` dir; otherwise a
/// freshly generated one, persisted for next time. Unlike
/// reading-list-syncd (which defaults to the fixed string "device-1" and
/// relies on the operator remembering to pass a unique `--device` per
/// machine), this auto-generates a unique id by default — `pass-syncd` is
/// meant to be installed as a service with no manual flags at all, so
/// silently colliding on "device-1" across every one of a user's machines
/// would be an easy, damaging mistake (two devices sharing one identity in
/// the version vector makes the CRDT under-count their divergent writes).
fn resolve_device_id(args: &[String], data_dir: &std::path::Path) -> String {
    if let Some(explicit) = arg(args, "--device") {
        return explicit;
    }
    if let Some(persisted) = persist::read_device_id(data_dir) {
        return persisted;
    }
    let generated = generate_device_id();
    if let Err(e) = persist::write_device_id(data_dir, &generated) {
        eprintln!("[persist] could not persist generated device id: {e}");
    }
    generated
}

#[derive(Clone)]
struct App {
    replica: Arc<Mutex<Replica>>,
    log: Arc<persist::OpLog>,
    device: String,
    hostname: String,
    port: u16,
    advertise: String,
    peer_prefix: String,
    pex: PexCache,
}

fn apply_and_persist(app: &App, op: Op) -> bool {
    let applied = app.replica.lock().unwrap().apply(op.clone());
    if applied {
        if let Err(e) = app.log.append(&op) {
            eprintln!("[persist] failed to append op ({} seq {}): {e}", op.device, op.seq);
        }
    }
    applied
}

// ---------------------------------------------------------- local control
// (loopback-only: this is what passcli/pass-native-host/pass-gnome/the
// Apple app — all running on this same machine on the user's own behalf —
// actually call)

async fn require_loopback(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if addr.ip().is_loopback() {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

#[derive(Deserialize)]
struct WriteReq {
    entity: String,
    value: Option<String>,
}

#[derive(Serialize)]
struct WriteResp {
    seq: u64,
    vv: VersionVector,
}

async fn local_write(State(app): State<App>, Json(req): Json<WriteReq>) -> Json<WriteResp> {
    let op = {
        let mut replica = app.replica.lock().unwrap();
        match req.value {
            Some(v) => replica.local_change(&req.entity, OpKind::Upsert, &v),
            None => replica.local_change(&req.entity, OpKind::Delete, ""),
        }
    };
    if let Err(e) = app.log.append(&op) {
        eprintln!("[persist] failed to append local op (seq {}): {e}", op.seq);
    }
    let vv = app.replica.lock().unwrap().version_vector();
    Json(WriteResp { seq: op.seq, vv })
}

#[derive(Serialize)]
struct StateResp {
    device: String,
    entries: Vec<serde_json::Value>,
    vv: VersionVector,
    fingerprint: String,
}

async fn local_state(State(app): State<App>) -> Json<StateResp> {
    let replica = app.replica.lock().unwrap();
    Json(StateResp {
        device: app.device.clone(),
        entries: replica.entries(),
        vv: replica.version_vector(),
        fingerprint: format!("{:x}", replica.state_fingerprint()),
    })
}

// ------------------------------------------------------------ peer-to-peer
// (reachable from the LAN/tailnet — same shapes as serverless-sync's
// per-application endpoints, minus the (name, token) path segment and the
// encryption envelope; see the module doc comment for why the envelope
// isn't needed at this layer.)

#[derive(Serialize)]
struct NodeInfo {
    proto: u32,
    device_id: String,
    hostname: String,
    port: u16,
    entries: usize,
    fingerprint: String,
}

async fn node(State(app): State<App>) -> Json<NodeInfo> {
    let replica = app.replica.lock().unwrap();
    Json(NodeInfo {
        proto: PROTO,
        device_id: app.device.clone(),
        hostname: app.hostname.clone(),
        port: app.port,
        entries: replica.entries().len(),
        fingerprint: format!("{:x}", replica.state_fingerprint()),
    })
}

#[derive(Serialize, Deserialize, Default)]
struct PexReq {
    #[serde(default)]
    peers: Vec<Peer>,
}

async fn peers(State(app): State<App>, Json(req): Json<PexReq>) -> Json<Vec<Peer>> {
    app.pex.merge(req.peers);
    let me = app.device.clone();
    let mut out: Vec<Peer> = app.pex.list().into_iter().filter(|p| p.device_id != me).collect();
    out.push(Peer { hostname: app.hostname.clone(), addr: app.advertise.clone(), device_id: me });
    Json(out)
}

async fn vv(State(app): State<App>) -> Json<VersionVector> {
    Json(app.replica.lock().unwrap().version_vector())
}

#[derive(Serialize, Deserialize)]
struct SinceReq {
    vv: VersionVector,
}

#[derive(Serialize, Deserialize)]
struct OpsResp {
    ops: Vec<Op>,
}

async fn ops_since(State(app): State<App>, Json(req): Json<SinceReq>) -> Json<OpsResp> {
    let ops = app.replica.lock().unwrap().ops_since(&req.vv);
    Json(OpsResp { ops })
}

#[derive(Serialize, Deserialize)]
struct PushReq {
    ops: Vec<Op>,
}

#[derive(Serialize, Deserialize)]
struct PushResp {
    applied: usize,
    vv: VersionVector,
}

async fn ops_push(State(app): State<App>, Json(req): Json<PushReq>) -> Json<PushResp> {
    let mut ops = req.ops;
    ops.sort_by_key(|o| (o.device.clone(), o.seq));
    let applied = ops.into_iter().filter(|o| apply_and_persist(&app, o.clone())).count();
    let vv = app.replica.lock().unwrap().version_vector();
    Json(PushResp { applied, vv })
}

// ------------------------------------------------------------ sync client

async fn sync_round(app: &App, addr: &str) -> Result<(usize, usize), String> {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .map_err(|e| e.to_string())?;

    let my_vv = app.replica.lock().unwrap().version_vector();
    let pulled: OpsResp = http
        .post(format!("http://{addr}/v1/ops/since"))
        .json(&SinceReq { vv: my_vv })
        .send().await.map_err(|e| e.to_string())?
        .json().await.map_err(|e| e.to_string())?;

    let mut ops = pulled.ops;
    ops.sort_by_key(|o| (o.device.clone(), o.seq));
    let n_pull = ops.into_iter().filter(|o| apply_and_persist(app, o.clone())).count();

    let their_vv: VersionVector = http
        .post(format!("http://{addr}/v1/vv"))
        .send().await.map_err(|e| e.to_string())?
        .json().await.map_err(|e| e.to_string())?;

    let mine = app.replica.lock().unwrap().ops_since(&their_vv);
    let n_push = if mine.is_empty() {
        0
    } else {
        let resp: PushResp = http
            .post(format!("http://{addr}/v1/ops"))
            .json(&PushReq { ops: mine })
            .send().await.map_err(|e| e.to_string())?
            .json().await.map_err(|e| e.to_string())?;
        resp.applied
    };

    Ok((n_pull, n_push))
}

async fn exchange_peers(app: &App, addr: &str) {
    let Ok(http) = reqwest::Client::builder().timeout(std::time::Duration::from_secs(2)).build() else { return };
    let mut mine_peers = app.pex.list();
    mine_peers.push(Peer { hostname: app.hostname.clone(), addr: app.advertise.clone(), device_id: app.device.clone() });
    if let Ok(resp) = http.post(format!("http://{addr}/v1/peers")).json(&PexReq { peers: mine_peers }).send().await {
        if let Ok(list) = resp.json::<Vec<Peer>>().await {
            app.pex.merge(list);
        }
    }
}

async fn antientropy_loop(app: App, bootstrap: Vec<String>, interval_secs: u64) {
    loop {
        let mut targets: Vec<String> = bootstrap.clone();
        for (_host, ip) in discovery::tailnet_candidates(&app.peer_prefix) {
            targets.push(format!("{ip}:{}", app.port));
        }
        for p in app.pex.list() {
            targets.push(p.addr);
        }
        targets.sort();
        targets.dedup();

        for t in targets.into_iter().filter(|t| *t != app.advertise) {
            exchange_peers(&app, &t).await;
            match sync_round(&app, &t).await {
                Ok((pulled, pushed)) => {
                    if pulled + pushed > 0 {
                        println!("[sync] <-> {t}: +{pulled} received, +{pushed} sent");
                    }
                }
                Err(e) => eprintln!("[sync] <-> {t}: unreachable ({e})"),
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
    }
}

// -------------------------------------------------------------- serve mode

async fn run_serve(args: Vec<String>) {
    let data_path: PathBuf = arg(&args, "--data").map(PathBuf::from).unwrap_or_else(persist::default_ledger_path);
    let data_dir = data_path.parent().map(PathBuf::from).unwrap_or_else(persist::default_data_dir);

    let device = resolve_device_id(&args, &data_dir);
    let port: u16 = arg(&args, "--port").and_then(|p| p.parse().ok()).unwrap_or(DEFAULT_PORT);
    let bootstrap: Vec<String> = arg(&args, "--bootstrap")
        .map(|b| b.split(',').map(String::from).collect())
        .unwrap_or_default();
    let peer_prefix = arg(&args, "--peer-prefix").unwrap_or_default();
    let lan_discovery_enabled = !args.iter().any(|a| a == "--no-lan-discovery");

    let hostname = std::process::Command::new("hostname")
        .output().ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| device.clone());

    let lan_ip = discovery::local_lan_ip();
    let advertise = arg(&args, "--advertise")
        .or_else(|| std::env::var("PASS_SYNCD_ADVERTISE").ok())
        .or_else(|| discovery::my_tailnet_ip().map(|ip| format!("{ip}:{port}")))
        .or_else(|| lan_ip.map(|ip| format!("{ip}:{port}")))
        .unwrap_or_else(|| format!("127.0.0.1:{port}"));

    let mut replica = Replica::new(device.clone());
    match persist::load(&data_path) {
        Ok(ops) => {
            let n = ops.len();
            for op in ops {
                replica.apply(op);
            }
            if n > 0 {
                println!("[persist] replayed {n} ops from {}", data_path.display());
            }
        }
        Err(e) => eprintln!("[persist] failed to read {}: {e} (starting empty)", data_path.display()),
    }
    let log = persist::OpLog::open(&data_path)
        .unwrap_or_else(|e| panic!("[persist] cannot open {}: {e}", data_path.display()));

    if let Err(e) = persist::write_port_file(&data_dir, port) {
        eprintln!("[persist] could not write port file next to {}: {e} (clients may not find this daemon)", data_path.display());
    }

    let app = App {
        replica: Arc::new(Mutex::new(replica)),
        log: Arc::new(log),
        device: device.clone(),
        hostname,
        port,
        advertise: advertise.clone(),
        peer_prefix,
        pex: PexCache::default(),
    };

    println!("pass-syncd serve: device={device} port={port} advertise={advertise} data={}", data_path.display());

    let mut local_api = Router::new()
        .route("/write", post(local_write))
        .route("/state", get(local_state))
        .route("/ops/since", post(ops_since));
    local_api = local_api.layer(middleware::from_fn(require_loopback));

    let sync_api = Router::new()
        .route("/v1/node", get(node))
        .route("/v1/peers", post(peers))
        .route("/v1/vv", post(vv))
        .route("/v1/ops/since", post(ops_since))
        .route("/v1/ops", post(ops_push));

    let router = local_api.merge(sync_api).with_state(app.clone());

    tokio::spawn(antientropy_loop(app.clone(), bootstrap, 10));
    if lan_discovery_enabled {
        let me = Peer { hostname: app.hostname.clone(), addr: app.advertise.clone(), device_id: app.device.clone() };
        tokio::spawn(discovery::lan_discovery_loop(me, app.peer_prefix.clone(), app.pex.clone(), std::time::Duration::from_secs(5)));
    }

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await
        .unwrap_or_else(|e| panic!("cannot bind port {port}: {e}"));
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) != Some("serve") {
        eprintln!("Usage: pass-syncd serve [--device NAME] [--port N] [--data PATH] [--bootstrap host:port,...] [--advertise ADDR] [--peer-prefix PREFIX] [--no-lan-discovery]");
        std::process::exit(2);
    }
    run_serve(args).await;
}
