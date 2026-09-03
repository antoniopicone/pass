//! Two nodes, one loopback, no server.
//!
//! These tests run the real thing: real sockets, the real HTTP endpoints,
//! real signatures, real KDBX vaults on disk. The unit tests in
//! `passlib::sync` prove the merge rule; what is proved here is that two
//! independently-built replicas holding two separate vault files actually
//! converge — which is the claim that matters and the one a mocked
//! transport cannot make.
//!
//! Each test costs a few Argon2id derivations at 64 MiB, so they are slow
//! by construction. That is the price of testing the real vault rather than
//! a stand-in for it.

#![cfg(unix)]

use pass_agent::sync::node::{SyncConfig, SyncNode};
use pass_agent::session::{Session, DEFAULT_IDLE_TIMEOUT};
use passlib::{PasswordEntry, Vault};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const PASSWORD: &str = "correct horse battery staple";

/// One device: its own vault file, its own state directory, its own node.
struct Device {
    _dir: tempfile::TempDir,
    vault_path: std::path::PathBuf,
    node: SyncNode,
    session: Arc<Mutex<Option<Session>>>,
    addr: String,
    shutdown: Arc<AtomicBool>,
}

impl Drop for Device {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }
}

impl Device {
    /// Build a device serving on an ephemeral loopback port.
    ///
    /// A second device is set up the way a real one is: by copying the vault
    /// file across once. That is what carries the sync key, and it is why
    /// there is no key exchange in this protocol to get wrong.
    fn new(label: &str, vault_from: Option<&Device>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join(format!("{label}.kdbx"));

        match vault_from {
            Some(other) => {
                std::fs::copy(&other.vault_path, &vault_path).unwrap();
            }
            None => {
                let mut vault = Vault::init(&vault_path, PASSWORD).unwrap();
                vault.ensure_sync_key().unwrap();
                vault.save(PASSWORD).unwrap();
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let config = SyncConfig {
            port: listener.local_addr().unwrap().port(),
            bind: Some("127.0.0.1".to_string()),
            advertise: Some(addr.clone()),
            bootstrap: Vec::new(),
            interval: Duration::from_millis(200),
        };

        let node = {
            let _guard = StateDirGuard::new(dir.path().join("state"));
            SyncNode::load(config).unwrap()
        };

        let shutdown = Arc::new(AtomicBool::new(false));
        {
            let node = node.clone();
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || node.serve(listener, shutdown));
        }

        let device = Self {
            _dir: dir,
            vault_path,
            node,
            session: Arc::new(Mutex::new(None)),
            addr,
            shutdown,
        };
        device.unlock();
        device
    }

    fn unlock(&self) {
        let mut session = Session::unlock(&self.vault_path, PASSWORD, DEFAULT_IDLE_TIMEOUT).unwrap();
        session
            .with_vault(|vault, password| {
                self.node.arm(vault)?;
                vault.save(password)
            })
            .unwrap();
        *self.session.lock().unwrap() = Some(session);
    }

    fn lock(&self) {
        *self.session.lock().unwrap() = None;
    }

    /// Accept ops signed by `other` — what `pass sync trust` does, with the
    /// fingerprint read off the other device's screen instead of typed.
    fn trust(&self, other: &Device) {
        let their_devices = Vault::unlock(&other.vault_path, PASSWORD).unwrap().sync_devices();
        let mut vault = Vault::unlock(&self.vault_path, PASSWORD).unwrap();
        for device in their_devices {
            vault.trust_sync_device(&device.label, device.public_key).unwrap();
        }
        vault.save(PASSWORD).unwrap();
        self.unlock(); // re-arm, so the node picks the new roster up
    }

    fn edit(&self, f: impl FnOnce(&mut Vault) -> passlib::Result<()>) {
        let mut vault = Vault::unlock(&self.vault_path, PASSWORD).unwrap();
        f(&mut vault).unwrap();
        vault.save(PASSWORD).unwrap();
    }

    fn entries(&self) -> Vec<(String, String)> {
        let vault = Vault::unlock(&self.vault_path, PASSWORD).unwrap();
        let mut out: Vec<(String, String)> = vault
            .list_entries()
            .unwrap()
            .into_iter()
            .map(|e| {
                let full = vault.get_entry(&e.id).unwrap();
                (full.website.clone(), full.password().to_string())
            })
            .collect();
        out.sort();
        out
    }

    /// A full round against `peer`: publish, exchange, apply.
    fn sync_with(&self, peer: &Device) {
        self.node.vault_pass(&self.session);
        self.node.sync_round(&peer.addr).unwrap();
        self.node.vault_pass(&self.session);
    }
}

/// Points `PASS_STATE_DIR` at one directory for as long as it lives.
///
/// Environment variables are process-global and `cargo test` runs tests in
/// parallel threads, so this also takes a lock: without it, two devices
/// being built at the same time would be handed each other's op-log.
// The guard is held for its lifetime, not read.
struct StateDirGuard(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);

static STATE_DIR_LOCK: Mutex<()> = Mutex::new(());

impl StateDirGuard {
    fn new(path: std::path::PathBuf) -> Self {
        let guard = STATE_DIR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(pass_agent::paths::STATE_DIR_ENV, path);
        Self(guard)
    }
}

impl Drop for StateDirGuard {
    fn drop(&mut self) {
        std::env::remove_var(pass_agent::paths::STATE_DIR_ENV);
    }
}

fn add(vault: &mut Vault, website: &str, password: &str) -> passlib::Result<()> {
    vault.add_entry(PasswordEntry::new(
        website.to_string(),
        format!("https://{website}"),
        "me".to_string(),
        password.to_string(),
    ))?;
    Ok(())
}

/// Two paired devices, ready to sync.
fn pair() -> (Device, Device) {
    let a = Device::new("a", None);
    let b = Device::new("b", Some(&a));
    a.trust(&b);
    b.trust(&a);
    (a, b)
}

#[test]
fn an_entry_written_on_one_device_arrives_on_the_other() {
    let (a, b) = pair();
    a.edit(|v| add(v, "github.com", "hunter2"));

    a.sync_with(&b);
    b.sync_with(&a);

    assert_eq!(b.entries(), vec![("github.com".to_string(), "hunter2".to_string())]);
}

#[test]
fn both_devices_end_up_with_the_same_state_fingerprint() {
    let (a, b) = pair();
    a.edit(|v| add(v, "github.com", "hunter2"));
    b.edit(|v| add(v, "gitlab.com", "hunter3"));

    // Two rounds each way: the first exchanges, the second confirms.
    for _ in 0..2 {
        a.sync_with(&b);
        b.sync_with(&a);
    }

    assert_eq!(a.entries(), b.entries());
    assert_eq!(
        a.node.status().fingerprint,
        b.node.status().fingerprint,
        "the two replicas merged differently"
    );
}

#[test]
fn an_edit_propagates_and_keeps_the_old_password_in_history() {
    let (a, b) = pair();
    a.edit(|v| add(v, "github.com", "old"));
    a.sync_with(&b);
    b.sync_with(&a);

    let id = Vault::unlock(&a.vault_path, PASSWORD).unwrap().list_entries().unwrap()[0]
        .id
        .clone();
    a.edit(|v| v.update_entry(&id, None, None, None, Some("new".into()), None, None));

    a.sync_with(&b);
    b.sync_with(&a);

    assert_eq!(b.entries(), vec![("github.com".to_string(), "new".to_string())]);

    let entry = Vault::unlock(&b.vault_path, PASSWORD).unwrap().get_entry(&id).unwrap();
    assert!(
        entry.history.iter().any(|h| h.password == "old"),
        "the replaced password should still be recoverable from KDBX history"
    );
}

#[test]
fn a_deletion_propagates() {
    let (a, b) = pair();
    a.edit(|v| add(v, "github.com", "hunter2"));
    a.sync_with(&b);
    b.sync_with(&a);
    assert_eq!(b.entries().len(), 1);

    let id = Vault::unlock(&a.vault_path, PASSWORD).unwrap().list_entries().unwrap()[0]
        .id
        .clone();
    a.edit(|v| v.delete_entry(&id));

    a.sync_with(&b);
    b.sync_with(&a);

    assert!(b.entries().is_empty(), "a deletion did not reach the peer");
    assert_eq!(a.node.status().fingerprint, b.node.status().fingerprint);
}

#[test]
fn nothing_ping_pongs_once_the_two_are_in_step() {
    let (a, b) = pair();
    a.edit(|v| add(v, "github.com", "hunter2"));

    for _ in 0..3 {
        a.sync_with(&b);
        b.sync_with(&a);
    }
    let ops_after_settling = a.node.status().ops;

    // Several more rounds with nobody editing anything must mint no ops.
    // Getting this wrong is not cosmetic: writing a peer's change into the
    // vault bumps its modification time, which a naive implementation reads
    // as a fresh local edit and republishes, forever.
    for _ in 0..3 {
        a.sync_with(&b);
        b.sync_with(&a);
    }

    assert_eq!(a.node.status().ops, ops_after_settling, "the two devices are echoing each other");
    assert_eq!(b.node.status().ops, ops_after_settling);
}

#[test]
fn an_edit_made_while_a_pass_is_running_is_still_published() {
    let (a, b) = pair();
    a.sync_with(&b);
    b.sync_with(&a);

    // Two writes. The first exists only to guarantee the pass below really
    // runs rather than returning early with nothing to do; the second lands
    // *during* that pass — which is what happens whenever `pass add` is
    // typed while the agent happens to be reconciling.
    a.edit(|v| add(v, "before-the-pass.com", "hunter2"));

    // The second write is built ahead of time and delivered as a file copy,
    // so the moment it lands is exact. Doing the edit inline instead would
    // make the writer pay for two Argon2id derivations — around two seconds
    // — and land *after* the pass rather than inside it, which is precisely
    // the interleaving this test must not accidentally produce.
    let staged = a._dir.path().join("staged.kdbx");
    std::fs::copy(&a.vault_path, &staged).unwrap();
    {
        let mut vault = Vault::unlock(&staged, PASSWORD).unwrap();
        add(&mut vault, "during-the-pass.com", "hunter3").unwrap();
        vault.save(PASSWORD).unwrap();
    }

    let vault_path = a.vault_path.clone();
    let writer = std::thread::spawn(move || {
        // Comfortably after the pass has read the file (that happens in the
        // first milliseconds) and comfortably before it finishes (opening a
        // vault is Argon2id at 64 MiB).
        std::thread::sleep(Duration::from_millis(200));
        std::fs::copy(&staged, &vault_path).unwrap();
    });

    a.node.vault_pass(&a.session);
    writer.join().unwrap();

    // Getting this wrong does not delay the second entry, it loses it: the
    // pass records a modification time reflecting a write it never read, so
    // from then on the change looks already-seen and is never published.
    for _ in 0..2 {
        a.sync_with(&b);
        b.sync_with(&a);
    }

    let seen: Vec<String> = b.entries().into_iter().map(|(site, _)| site).collect();
    assert!(
        seen.iter().any(|s| s == "during-the-pass.com"),
        "an entry written while the agent was reconciling never reached the peer: {seen:?}"
    );
}

#[test]
fn a_concurrent_edit_to_one_entry_converges_on_one_winner() {
    let (a, b) = pair();
    a.edit(|v| add(v, "github.com", "original"));
    a.sync_with(&b);
    b.sync_with(&a);

    let id = Vault::unlock(&a.vault_path, PASSWORD).unwrap().list_entries().unwrap()[0]
        .id
        .clone();

    // Both edit the same entry while out of contact.
    a.edit(|v| v.update_entry(&id, None, None, None, Some("from-a".into()), None, None));
    b.edit(|v| v.update_entry(&id, None, None, None, Some("from-b".into()), None, None));

    for _ in 0..2 {
        a.sync_with(&b);
        b.sync_with(&a);
    }

    let winner = a.entries();
    assert_eq!(winner, b.entries(), "the two devices disagree about the winner");
    assert!(
        winner[0].1 == "from-a" || winner[0].1 == "from-b",
        "the winner should be one of the two edits, got {winner:?}"
    );
    assert_eq!(a.node.status().fingerprint, b.node.status().fingerprint);
}

#[test]
fn an_untrusted_device_is_refused_and_reported() {
    let a = Device::new("a", None);
    let stranger = Device::new("stranger", Some(&a));
    // Deliberately no pairing in either direction.

    stranger.edit(|v| add(v, "evil.example", "injected"));
    stranger.node.vault_pass(&stranger.session);
    stranger.node.sync_round(&a.addr).unwrap();
    a.node.vault_pass(&a.session);

    assert!(a.entries().is_empty(), "an unpaired device wrote into the vault");
    assert!(
        a.node.status().log.iter().any(|line| line.contains("unknown device")),
        "the user was not told a device is asking to pair: {:?}",
        a.node.status().log
    );
}

#[test]
fn a_locked_device_still_relays_but_does_not_write_to_its_vault() {
    let (a, b) = pair();
    a.edit(|v| add(v, "github.com", "hunter2"));

    b.lock();
    a.sync_with(&b);
    b.node.sync_round(&a.addr).unwrap();

    // B holds the op — it can verify signatures without the vault — but has
    // nowhere to put it until the user unlocks.
    assert!(b.node.status().ops > 0, "a locked device should still accept and relay ops");
    assert!(b.entries().is_empty());
    assert!(b.node.status().pending_vault_write);

    b.unlock();
    b.node.vault_pass(&b.session);
    assert_eq!(b.entries(), vec![("github.com".to_string(), "hunter2".to_string())]);
}

#[test]
fn a_third_device_learns_the_mesh_from_one_contact() {
    let (a, b) = pair();
    a.sync_with(&b);
    b.sync_with(&a);

    let c = Device::new("c", Some(&a));
    c.trust(&a);
    a.trust(&c);

    // C only ever talks to A, and must come away knowing about B.
    c.node.sync_round(&a.addr).unwrap();

    let known: Vec<String> = c.node.status().peers.into_iter().map(|p| p.addr).collect();
    assert!(known.contains(&b.addr), "peer exchange did not propagate B to C: {known:?}");
}

#[test]
fn the_op_log_survives_a_restart() {
    let (a, b) = pair();
    a.edit(|v| add(v, "github.com", "hunter2"));
    a.sync_with(&b);
    let before = a.node.status();
    a.node.persist();

    // Same state directory, fresh node — as if the agent had restarted.
    let restarted = {
        let _guard = StateDirGuard::new(a._dir.path().join("state"));
        SyncNode::load(SyncConfig {
            port: 0,
            bind: Some("127.0.0.1".into()),
            advertise: Some(a.addr.clone()),
            bootstrap: Vec::new(),
            interval: Duration::from_millis(200),
        })
        .unwrap()
    };

    let after = restarted.status();
    assert_eq!(after.ops, before.ops, "the op-log was lost across a restart");
    assert_eq!(after.device, before.device, "the device changed identity across a restart");
    assert_eq!(after.fingerprint, before.fingerprint);
}
