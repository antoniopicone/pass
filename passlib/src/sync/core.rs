//! The replicated data type: HLC, op-log, version vector, LWW state.
//!
//! This module knows nothing about sockets, Tailscale, or KDBX. It is the
//! piece every peer must agree on *exactly*: two devices converge only if
//! they apply the same merge rule to the same ops. Keeping it here — in
//! `passlib`, reachable from the CLI, the GUIs and (through `passlib_ffi`)
//! from the Apple clients — is deliberate: a second implementation in
//! another language is a second merge rule waiting to drift, and a merge
//! rule that drifts in a password manager loses credentials silently.
//!
//! ## The three properties everything else leans on
//!
//! - **Idempotent**: applying the same op twice changes nothing.
//! - **Commutative**: order of arrival does not matter (within a device's
//!   own causal chain, which `seq` enforces).
//! - **Convergent**: replicas that have seen the same set of ops hold the
//!   same state, and say so via [`Replica::fingerprint`].
//!
//! Together they let the network layer be stupid: no deduplication, no
//! ordered delivery, no exactly-once. Anti-entropy re-sends whatever was
//! lost and applying it again is free.
//!
//! ## Why the payload is opaque here
//!
//! [`Op::payload`] is ciphertext (see [`super::crypto`]). This module never
//! looks inside it, which is what allows an always-on peer — a home server,
//! someone else's laptop on the tailnet — to relay and store ops without
//! being trusted with their contents.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A replica's identity on the wire: `<key-fingerprint>@<epoch>`.
///
/// The fingerprint half names the device's signing key (see
/// [`super::crypto::DeviceIdentity`]); the epoch half is what makes a
/// restored backup safe. See [`DeviceId::new`].
pub type DeviceId = String;

/// What each device's `seq` has reached, as far as this replica knows.
pub type VersionVector = BTreeMap<DeviceId, u64>;

/// The service whose state is being replicated. A device runs one sync
/// agent for all of them (see the agent's `NodeInfo.services`), so ops
/// carry the name and a replica drops anything not addressed to it.
pub const SERVICE: &str = "pass";

/// Build the wire device id from a key fingerprint and an epoch.
///
/// **Why the epoch.** `seq` is monotonic per device and peers ignore any op
/// whose `seq` they have already seen. Restore a device from a backup and
/// its counter rewinds: every op it writes from then on carries a `seq` its
/// peers consider ancient, so they discard it — silently, forever, and the
/// symptom ("my new passwords never reach the laptop") shows up weeks
/// later with nothing in the logs. Changing the epoch makes the restored
/// device a *new* replica to everyone else, which costs one extra entry in
/// each version vector and nothing else.
pub fn device_id(fingerprint: &str, epoch: u64) -> DeviceId {
    format!("{fingerprint}@{epoch}")
}

/// The key-fingerprint half of a device id — what the roster grants trust
/// to, since trust follows the key and not the epoch.
pub fn fingerprint_of(device: &DeviceId) -> &str {
    device.split_once('@').map_or(device.as_str(), |(fp, _)| fp)
}

/// Hybrid Logical Clock: wall-clock time that cannot go backwards.
///
/// Ordering is `(millis, counter, device)`. The device id in last place is
/// not decoration: without a deterministic tie-break, two devices writing
/// in the same millisecond would each pick themselves as the winner and
/// never converge.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Hlc {
    pub millis: u64,
    pub counter: u32,
    pub device: DeviceId,
}

impl Hlc {
    /// Milliseconds since the Unix epoch, as this clock reads them.
    pub fn as_datetime(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        chrono::DateTime::from_timestamp_millis(self.millis as i64)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OpKind {
    Upsert,
    Delete,
}

/// One immutable change. `(device, seq)` is its identity.
///
/// `seq` is gapless and monotonic per device, which is exactly what makes
/// delta-sync by version vector possible: "everything after 7" is a
/// complete answer, not an approximation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Op {
    pub device: DeviceId,
    pub seq: u64,
    pub hlc: Hlc,
    pub service: String,
    /// The vault entry's UUID. Stays in the clear: it is a random
    /// identifier that reveals nothing, and the merge needs it.
    pub entity: String,
    pub kind: OpKind,
    /// Sealed [`super::SyncEntry`], base64. Empty for a delete — a
    /// tombstone carries no secret.
    #[serde(default)]
    pub payload: String,
    /// Ed25519 signature over [`Op::signing_bytes`], base64.
    pub sig: String,
}

impl Op {
    /// The exact bytes that get signed and verified.
    ///
    /// Every field is length-prefixed rather than concatenated with a
    /// separator: without that, an attacker could shift a byte from the end
    /// of one field to the start of the next and produce a different op
    /// with the same signature.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160 + self.payload.len());
        out.extend_from_slice(b"pass-sync-op-v1");
        for field in [
            self.device.as_bytes(),
            &self.seq.to_be_bytes(),
            &self.hlc.millis.to_be_bytes(),
            &self.hlc.counter.to_be_bytes(),
            self.hlc.device.as_bytes(),
            self.service.as_bytes(),
            self.entity.as_bytes(),
            match self.kind {
                OpKind::Upsert => b"upsert",
                OpKind::Delete => b"delete",
            },
            self.payload.as_bytes(),
        ] {
            out.extend_from_slice(&(field.len() as u64).to_be_bytes());
            out.extend_from_slice(field);
        }
        out
    }
}

/// One entity's current value, after the merge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateEntry {
    pub entity: String,
    /// Sealed payload of the winning op; empty when `deleted`.
    pub payload: String,
    pub deleted: bool,
    pub hlc: Hlc,
}

/// Why an op was not accepted. Rejections are routine (a duplicate arrives
/// on every anti-entropy round) *except* [`Rejected::UntrustedDevice`] and
/// [`Rejected::BadSignature`], which the agent surfaces to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejected {
    /// Addressed to a different service.
    WrongService,
    /// Already applied.
    Duplicate,
    /// Arrived before an op it depends on; a later round will fill the gap.
    CausalGap { expected: u64, got: u64 },
    /// Signed by a key this vault has not been told to trust.
    UntrustedDevice(String),
    /// Signed by a trusted key, but the signature does not check out.
    BadSignature,
}

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rejected::WrongService => write!(f, "op belongs to another service"),
            Rejected::Duplicate => write!(f, "already seen"),
            Rejected::CausalGap { expected, got } => {
                write!(f, "causal gap: expected seq {expected}, got {got}")
            }
            Rejected::UntrustedDevice(fp) => {
                write!(f, "device {fp} is not trusted by this vault")
            }
            Rejected::BadSignature => write!(f, "signature does not verify"),
        }
    }
}

/// Decides whether an op's author may write to this replica.
///
/// The agent backs this with the device roster stored in the vault; tests
/// use [`TrustAll`]. It is a trait rather than a concrete roster so that
/// `core` keeps no dependency on where trust is persisted.
pub trait Roster {
    /// The signing public key registered for `fingerprint`, if any.
    fn verifying_key(&self, fingerprint: &str) -> Option<[u8; 32]>;
}

/// A roster that accepts nothing — the safe default before pairing.
pub struct TrustNone;

impl Roster for TrustNone {
    fn verifying_key(&self, _fingerprint: &str) -> Option<[u8; 32]> {
        None
    }
}

/// One replica of the replicated state.
pub struct Replica {
    device: DeviceId,
    service: String,
    /// Append-only op-log, per device, ordered by `seq`.
    log: BTreeMap<DeviceId, Vec<Op>>,
    state: BTreeMap<String, StateEntry>,
    counter: u32,
    last_millis: u64,
}

impl Replica {
    pub fn new(device: DeviceId) -> Self {
        Self {
            device,
            service: SERVICE.to_string(),
            log: BTreeMap::new(),
            state: BTreeMap::new(),
            counter: 0,
            last_millis: 0,
        }
    }

    pub fn device(&self) -> &str {
        &self.device
    }

    pub fn service(&self) -> &str {
        &self.service
    }

    /// What this replica has seen, per device. The whole delta-sync
    /// protocol is this one value travelling between peers.
    pub fn version_vector(&self) -> VersionVector {
        self.log
            .iter()
            .map(|(d, ops)| (d.clone(), ops.last().map_or(0, |o| o.seq)))
            .collect()
    }

    /// The `seq` the next locally-written op will carry.
    pub fn next_seq(&self) -> u64 {
        self.log.get(&self.device).and_then(|ops| ops.last()).map_or(1, |o| o.seq + 1)
    }

    /// Every op held, ordered — for persisting the log.
    pub fn export_log(&self) -> Vec<Op> {
        let mut out: Vec<Op> = self.log.values().flatten().cloned().collect();
        out.sort_by(|a, b| (&a.device, a.seq).cmp(&(&b.device, b.seq)));
        out
    }

    fn now_millis() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64)
    }

    /// The local half of the hybrid clock: monotonic even if the system
    /// clock is dragged backwards by NTP or a user.
    fn tick(&mut self) -> Hlc {
        let now = Self::now_millis();
        if now > self.last_millis {
            self.last_millis = now;
            self.counter = 0;
        } else {
            self.counter = self.counter.saturating_add(1);
        }
        Hlc {
            millis: self.last_millis,
            counter: self.counter,
            device: self.device.clone(),
        }
    }

    /// The hybrid half: absorb a remote clock so this replica never falls
    /// behind the causal past it has already observed.
    fn observe(&mut self, remote: &Hlc) {
        if remote.millis > self.last_millis {
            self.last_millis = remote.millis;
            self.counter = remote.counter.saturating_add(1);
        }
    }

    /// Mint a local op. `sign` receives the finished op minus its
    /// signature and returns one; keeping the key outside this module is
    /// what lets the signing half stay shielded in the agent.
    pub fn local_change<E>(
        &mut self,
        entity: &str,
        kind: OpKind,
        payload: String,
        sign: impl FnOnce(&Op) -> std::result::Result<String, E>,
    ) -> std::result::Result<Op, E> {
        let hlc = self.tick();
        let mut op = Op {
            device: self.device.clone(),
            seq: self.next_seq(),
            hlc,
            service: self.service.clone(),
            entity: entity.to_string(),
            kind,
            payload,
            sig: String::new(),
        };
        op.sig = sign(&op)?;

        // A locally-minted op is trusted by construction, so it goes in
        // through the same path but without a roster check.
        self.insert(op.clone());
        Ok(op)
    }

    /// Apply a remote op, verifying it first.
    ///
    /// Verification happens *before* the causal-gap check on purpose: an
    /// unsigned op should be reported as untrusted whatever its `seq`, so a
    /// peer flooding gap-filling garbage cannot hide behind "wait for the
    /// missing op".
    pub fn apply(&mut self, op: Op, roster: &dyn Roster) -> std::result::Result<(), Rejected> {
        if op.service != self.service {
            return Err(Rejected::WrongService);
        }

        let fingerprint = fingerprint_of(&op.device);
        let key = roster
            .verifying_key(fingerprint)
            .ok_or_else(|| Rejected::UntrustedDevice(fingerprint.to_string()))?;
        if !super::crypto::verify_op(&op, &key) {
            return Err(Rejected::BadSignature);
        }

        // The HLC's device must be the op's device: otherwise a trusted but
        // misbehaving peer could mint ops that claim another device's clock
        // and win every LWW comparison by tie-break.
        if op.hlc.device != op.device {
            return Err(Rejected::BadSignature);
        }

        let expected = self.log.get(&op.device).and_then(|ops| ops.last()).map_or(1, |o| o.seq + 1);
        if op.seq < expected {
            return Err(Rejected::Duplicate);
        }
        if op.seq > expected {
            return Err(Rejected::CausalGap { expected, got: op.seq });
        }

        self.insert(op);
        Ok(())
    }

    /// Append to the log and fold into the materialised state.
    fn insert(&mut self, op: Op) {
        self.observe(&op.hlc);

        let win = match self.state.get(&op.entity) {
            None => true,
            Some(current) => op.hlc > current.hlc,
        };
        if win {
            self.state.insert(
                op.entity.clone(),
                StateEntry {
                    entity: op.entity.clone(),
                    payload: op.payload.clone(),
                    deleted: op.kind == OpKind::Delete,
                    hlc: op.hlc.clone(),
                },
            );
        }

        self.log.entry(op.device.clone()).or_default().push(op);
    }

    /// Ops the caller — identified by the version vector they sent — has
    /// not seen. Sorted so the receiver can apply them without gaps.
    pub fn ops_since(&self, vv: &VersionVector) -> Vec<Op> {
        let mut out = Vec::new();
        for (device, ops) in &self.log {
            let have = vv.get(device).copied().unwrap_or(0);
            out.extend(ops.iter().filter(|o| o.seq > have).cloned());
        }
        out.sort_by(|a, b| (&a.device, a.seq).cmp(&(&b.device, b.seq)));
        out
    }

    /// Live entities, ordered — the merged view, still sealed.
    pub fn entries(&self) -> Vec<&StateEntry> {
        let mut v: Vec<&StateEntry> = self.state.values().filter(|e| !e.deleted).collect();
        v.sort_by(|a, b| a.entity.cmp(&b.entity));
        v
    }

    /// Entities whose winning op is a delete. Kept separate from
    /// [`Replica::entries`] because a tombstone is not a value the user has
    /// — but it is something a peer still has to be told about.
    pub fn tombstones(&self) -> Vec<&StateEntry> {
        let mut v: Vec<&StateEntry> = self.state.values().filter(|e| e.deleted).collect();
        v.sort_by(|a, b| a.entity.cmp(&b.entity));
        v
    }

    /// The winning state for one entity, tombstones included.
    pub fn get(&self, entity: &str) -> Option<&StateEntry> {
        self.state.get(entity)
    }

    pub fn op_count(&self) -> usize {
        self.log.values().map(Vec::len).sum()
    }

    /// A hash of the merge outcome. Two replicas that have converged print
    /// the same value; two that have not, do not — which is the fastest way
    /// to tell a network problem from a merge problem.
    ///
    /// It hashes the *decision* (which HLC won, deleted or not) rather than
    /// the payload. The ciphertext would converge too — it is replicated
    /// verbatim — but hashing the decision is what actually answers "did we
    /// merge the same way".
    pub fn fingerprint(&self) -> String {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for e in self.state.values() {
            let line = format!(
                "{}={}.{}.{}:{}",
                e.entity, e.hlc.millis, e.hlc.counter, e.hlc.device, e.deleted
            );
            for b in line.bytes() {
                h ^= b as u64;
                h = h.wrapping_mul(0x1000_0000_01b3);
            }
        }
        format!("{h:016x}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests exercise the merge rule, not the signature check; the roster
    /// and signing tests live in `crypto`.
    struct NoCrypto;

    impl Roster for NoCrypto {
        fn verifying_key(&self, _fingerprint: &str) -> Option<[u8; 32]> {
            Some([0u8; 32])
        }
    }

    /// Applies without verifying, so the merge rule can be tested on its
    /// own. Mirrors `Replica::apply` minus the crypto.
    fn apply_unchecked(r: &mut Replica, op: Op) -> std::result::Result<(), Rejected> {
        let expected = r.log.get(&op.device).and_then(|o| o.last()).map_or(1, |o| o.seq + 1);
        if op.seq < expected {
            return Err(Rejected::Duplicate);
        }
        if op.seq > expected {
            return Err(Rejected::CausalGap { expected, got: op.seq });
        }
        r.insert(op);
        Ok(())
    }

    fn change(r: &mut Replica, entity: &str, payload: &str) -> Op {
        r.local_change::<std::convert::Infallible>(entity, OpKind::Upsert, payload.into(), |_| {
            Ok(String::new())
        })
        .unwrap()
    }

    fn delete(r: &mut Replica, entity: &str) -> Op {
        r.local_change::<std::convert::Infallible>(entity, OpKind::Delete, String::new(), |_| {
            Ok(String::new())
        })
        .unwrap()
    }

    #[test]
    fn a_local_change_is_visible_immediately() {
        let mut r = Replica::new("a@1".into());
        change(&mut r, "github", "sealed");

        assert_eq!(r.entries().len(), 1);
        assert_eq!(r.version_vector().get("a@1"), Some(&1));
    }

    #[test]
    fn seq_is_gapless_per_device() {
        let mut r = Replica::new("a@1".into());
        for i in 1..=3 {
            assert_eq!(change(&mut r, "e", "v").seq, i);
        }
    }

    #[test]
    fn applying_the_same_op_twice_is_a_no_op() {
        let mut a = Replica::new("a@1".into());
        let op = change(&mut a, "github", "sealed");

        let mut b = Replica::new("b@1".into());
        assert!(apply_unchecked(&mut b, op.clone()).is_ok());
        assert_eq!(apply_unchecked(&mut b, op), Err(Rejected::Duplicate));
        assert_eq!(b.op_count(), 1);
    }

    #[test]
    fn an_op_arriving_early_is_held_back_not_dropped_silently() {
        let mut a = Replica::new("a@1".into());
        let _first = change(&mut a, "e", "1");
        let second = change(&mut a, "e", "2");

        let mut b = Replica::new("b@1".into());
        assert_eq!(
            apply_unchecked(&mut b, second),
            Err(Rejected::CausalGap { expected: 1, got: 2 })
        );
        // ops_since on A still offers both, so the next round fills the gap.
        assert_eq!(a.ops_since(&b.version_vector()).len(), 2);
    }

    #[test]
    fn ops_since_returns_only_what_the_caller_lacks() {
        let mut a = Replica::new("a@1".into());
        change(&mut a, "e1", "1");
        change(&mut a, "e2", "2");

        let mut vv = VersionVector::new();
        vv.insert("a@1".into(), 1);
        assert_eq!(a.ops_since(&vv).len(), 1);
        assert_eq!(a.ops_since(&a.version_vector()).len(), 0);
    }

    #[test]
    fn a_wrong_service_op_is_refused() {
        let mut a = Replica::new("a@1".into());
        let mut op = change(&mut a, "e", "v");
        op.service = "immich".into();

        let mut b = Replica::new("b@1".into());
        assert_eq!(b.apply(op, &NoCrypto), Err(Rejected::WrongService));
    }

    #[test]
    fn concurrent_writes_to_one_entity_converge_on_the_same_winner() {
        let mut a = Replica::new("a@1".into());
        let mut b = Replica::new("b@1".into());

        // Both write the same entity without having seen each other.
        let from_a = change(&mut a, "github", "from-a");
        let from_b = change(&mut b, "github", "from-b");

        apply_unchecked(&mut a, from_b).unwrap();
        apply_unchecked(&mut b, from_a).unwrap();

        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_eq!(a.get("github").unwrap().payload, b.get("github").unwrap().payload);
    }

    #[test]
    fn order_of_arrival_does_not_change_the_outcome() {
        let mut a = Replica::new("a@1".into());
        let mut b = Replica::new("b@1".into());
        let mut c = Replica::new("c@1".into());

        let a1 = change(&mut a, "e1", "a1");
        let a2 = change(&mut a, "e2", "a2");
        let b1 = change(&mut b, "e1", "b1");

        // C hears A then B; a fourth replica hears B then A.
        for op in [a1.clone(), a2.clone(), b1.clone()] {
            apply_unchecked(&mut c, op).unwrap();
        }
        let mut d = Replica::new("d@1".into());
        for op in [b1, a1, a2] {
            apply_unchecked(&mut d, op).unwrap();
        }

        assert_eq!(c.fingerprint(), d.fingerprint());
    }

    #[test]
    fn a_delete_is_a_tombstone_that_a_later_write_can_overturn() {
        let mut a = Replica::new("a@1".into());
        change(&mut a, "github", "v1");
        delete(&mut a, "github");
        assert!(a.entries().is_empty());
        assert!(a.get("github").unwrap().deleted);

        // Re-adding wins, because its HLC is later: deletes take part in the
        // same LWW as everything else rather than being final.
        change(&mut a, "github", "v2");
        assert_eq!(a.entries().len(), 1);
    }

    #[test]
    fn a_delete_propagates_to_a_peer_that_never_saw_the_original() {
        let mut a = Replica::new("a@1".into());
        let add = change(&mut a, "github", "v1");
        let del = delete(&mut a, "github");

        let mut b = Replica::new("b@1".into());
        apply_unchecked(&mut b, add).unwrap();
        apply_unchecked(&mut b, del).unwrap();
        assert!(b.entries().is_empty());
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn the_clock_survives_the_system_clock_going_backwards() {
        let mut r = Replica::new("a@1".into());
        let first = change(&mut r, "e", "1");

        // Simulate the wall clock jumping into the past.
        r.last_millis = first.hlc.millis + 10_000;
        let second = change(&mut r, "e", "2");
        assert!(second.hlc > first.hlc, "HLC went backwards");
    }

    #[test]
    fn observing_a_remote_clock_keeps_a_later_local_write_ahead() {
        let mut a = Replica::new("a@1".into());
        let mut b = Replica::new("b@1".into());

        // B's clock is an hour ahead.
        b.last_millis = Replica::now_millis() + 3_600_000;
        let from_b = change(&mut b, "e", "b");

        apply_unchecked(&mut a, from_b.clone()).unwrap();
        let from_a = change(&mut a, "e", "a");
        assert!(from_a.hlc > from_b.hlc, "a later write lost to a fast peer's clock");
        assert_eq!(a.get("e").unwrap().payload, "a");
    }

    #[test]
    fn the_hlc_tie_break_is_deterministic_across_replicas() {
        let hlc = |device: &str| Hlc { millis: 7, counter: 0, device: device.into() };
        assert!(hlc("b@1") > hlc("a@1"));
        assert!(hlc("a@2") > hlc("a@1"));
    }

    #[test]
    fn a_restored_backup_gets_a_new_epoch_and_is_not_ignored() {
        let mut peer = Replica::new("peer@1".into());

        // The device wrote three ops, then was restored from a backup that
        // only had one: its counter rewound.
        let mut before = Replica::new(device_id("dev", 100));
        for _ in 0..3 {
            let op = change(&mut before, "e", "v");
            apply_unchecked(&mut peer, op).unwrap();
        }

        let mut rewound = Replica::new(device_id("dev", 100));
        let stale = change(&mut rewound, "e", "after-restore");
        assert_eq!(
            apply_unchecked(&mut peer, stale),
            Err(Rejected::Duplicate),
            "the rewind should be exactly the failure the epoch exists to prevent"
        );

        // Same key, new epoch: the peer treats it as a fresh replica.
        let mut restored = Replica::new(device_id("dev", 200));
        // It syncs before writing, as the anti-entropy loop always does, so
        // its hybrid clock is not behind the history it just inherited.
        for op in peer.ops_since(&restored.version_vector()) {
            apply_unchecked(&mut restored, op).unwrap();
        }
        let op = change(&mut restored, "e", "after-restore");
        assert!(apply_unchecked(&mut peer, op).is_ok());
        assert_eq!(peer.get("e").unwrap().payload, "after-restore");
    }

    #[test]
    fn trust_follows_the_key_not_the_epoch() {
        assert_eq!(fingerprint_of(&device_id("abc", 42)), "abc");
        assert_eq!(fingerprint_of(&"no-epoch".to_string()), "no-epoch");
    }

    #[test]
    fn signing_bytes_cannot_be_confused_by_shifting_a_field_boundary() {
        let base = Op {
            device: "a@1".into(),
            seq: 1,
            hlc: Hlc { millis: 1, counter: 0, device: "a@1".into() },
            service: SERVICE.into(),
            entity: "ab".into(),
            kind: OpKind::Upsert,
            payload: "c".into(),
            sig: String::new(),
        };
        let shifted = Op { entity: "a".into(), payload: "bc".into(), ..base.clone() };
        assert_ne!(base.signing_bytes(), shifted.signing_bytes());
    }

    #[test]
    fn the_fingerprint_ignores_the_order_ops_arrived_in() {
        let mut a = Replica::new("a@1".into());
        let mut b = Replica::new("b@1".into());
        let o1 = change(&mut a, "z", "1");
        let o2 = change(&mut a, "a", "2");

        apply_unchecked(&mut b, o1).unwrap();
        apply_unchecked(&mut b, o2).unwrap();
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn diverged_replicas_have_different_fingerprints() {
        let mut a = Replica::new("a@1".into());
        let mut b = Replica::new("b@1".into());
        change(&mut a, "e", "v");
        change(&mut b, "e", "v");
        assert_ne!(a.fingerprint(), b.fingerprint());
    }
}
