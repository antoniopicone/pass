//! The two directions between the KDBX vault and the replicated op-log.
//!
//! - **ingest** — an entry the user changed locally becomes a signed,
//!   sealed op;
//! - **materialise** — an op that won the merge is written back into the
//!   vault.
//!
//! ## The trap this module exists to avoid
//!
//! Both directions trigger on the same observation: "the vault and the
//! op-log disagree about this entry". Run them naively and two devices
//! bounce one entry between them forever — A writes B's change into its
//! vault, which bumps the KDBX modification time, which looks like a fresh
//! local edit, which A publishes back to B, and so on. It is not a
//! hypothetical: it is what a timestamp comparison gets you, because
//! writing a remote change *is* a local write as far as KDBX is concerned.
//!
//! The fix is [`EntityMark`]: per entity, the content hash and the winning
//! clock at the moment the two last agreed. Ingest fires when the vault's
//! content moved away from the mark; materialise fires when the winning op
//! moved away from it. After either, the mark is updated, and the other
//! direction sees nothing to do.
//!
//! Marks are local bookkeeping and are never replicated — they say what
//! *this* device has reconciled, which is a different question from what
//! the replicas agree on.

use passlib::sync::{DeviceIdentity, EntityMark, Op, OpKind, Replica, SyncEntry, SyncKey};
use passlib::{PassError, Result, Vault};
use std::collections::BTreeMap;

/// Mark content standing for "this entity is deleted here". A hash is 64
/// hex characters, so this can never collide with one.
const TOMBSTONE: &str = "deleted";

/// Per-entity reconciliation marks, keyed by vault entry id.
pub type Marks = BTreeMap<String, EntityMark>;

/// What a materialise pass did to the vault.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Applied {
    pub created: usize,
    pub updated: usize,
    pub deleted: usize,
    /// Ops whose payload this vault's sync key cannot open — almost always
    /// a peer whose vault was created separately rather than copied from
    /// this one.
    pub unreadable: usize,
    /// Ops that could be read but not written into the vault.
    pub failed: usize,
}

impl Applied {
    pub fn changed(&self) -> bool {
        self.created + self.updated + self.deleted > 0
    }
}

impl std::fmt::Display for Applied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} created, {} updated, {} deleted",
            self.created, self.updated, self.deleted
        )?;
        if self.unreadable > 0 {
            write!(f, ", {} unreadable", self.unreadable)?;
        }
        if self.failed > 0 {
            write!(f, ", {} failed", self.failed)?;
        }
        Ok(())
    }
}

/// Turn local vault changes into ops, appending them to `replica`.
///
/// Returns the ops minted, so the caller can push them without waiting for
/// the next anti-entropy round.
pub fn ingest(
    vault: &Vault,
    replica: &mut Replica,
    marks: &mut Marks,
    key: &SyncKey,
    identity: &DeviceIdentity,
) -> Result<Vec<Op>> {
    let mut minted = Vec::new();

    for summary in vault.list_entries()? {
        let entry = vault.get_entry(&summary.id)?;
        let sync_entry = SyncEntry::from(&entry);
        let content = sync_entry.content_hash();

        if marks.get(&summary.id).is_some_and(|m| m.content == content) {
            continue;
        }

        let payload = sync_entry.seal(key, &summary.id)?;
        let op = mint(replica, identity, &summary.id, OpKind::Upsert, payload)?;
        marks.insert(summary.id.clone(), EntityMark { content, hlc: op.hlc.clone() });
        minted.push(op);
    }

    // Deletions. The vault soft-deletes into the Recycle Bin, so a deleted
    // entry is still there to be read — which is what lets a tombstone be
    // published at all, and why `pass` does not need a tombstone table of
    // its own.
    for id in vault.recycled_entry_ids() {
        if marks.get(&id).is_some_and(|m| m.content == TOMBSTONE) {
            continue;
        }

        let op = mint(replica, identity, &id, OpKind::Delete, String::new())?;
        marks.insert(id, EntityMark { content: TOMBSTONE.to_string(), hlc: op.hlc.clone() });
        minted.push(op);
    }

    Ok(minted)
}

/// Write the merge's winners back into the vault.
///
/// Does not save: the caller holds the master password and decides when to
/// pay for re-encrypting the file.
pub fn materialise(vault: &mut Vault, replica: &Replica, marks: &mut Marks, key: &SyncKey) -> Result<Applied> {
    let mut applied = Applied::default();

    // Collected first because writing to the vault borrows it mutably while
    // the replica's state is borrowed immutably here.
    let winners: Vec<(String, String, bool, passlib::sync::Hlc)> = replica
        .entries()
        .into_iter()
        .map(|e| (e.entity.clone(), e.payload.clone(), false, e.hlc.clone()))
        .chain(
            replica
                .tombstones()
                .into_iter()
                .map(|e| (e.entity.clone(), String::new(), true, e.hlc.clone())),
        )
        .collect();

    // Walked once rather than per entity: `recycled_entry_ids` iterates the
    // whole database, and each entity is visited exactly once below, so a
    // snapshot taken here stays correct for the whole pass.
    let recycled: std::collections::BTreeSet<String> = vault.recycled_entry_ids().into_iter().collect();

    for (entity, payload, deleted, hlc) in winners {
        // Already reconciled at exactly this clock: nothing to do. This is
        // the common case on every round after the first.
        if marks.get(&entity).is_some_and(|m| m.hlc == hlc) {
            continue;
        }

        if deleted {
            if delete_if_present(vault, &entity)? {
                applied.deleted += 1;
            }
            marks.insert(entity, EntityMark { content: TOMBSTONE.to_string(), hlc });
            continue;
        }

        // An op this vault's key cannot open is skipped, not fatal. Failing
        // the pass here would mean one peer with an unrelated vault stops
        // every *other* peer's changes from ever being written — and the
        // mark is deliberately left alone so the op is retried if the right
        // key turns up later.
        let Ok(incoming) = SyncEntry::open(key, &entity, &payload) else {
            applied.unreadable += 1;
            continue;
        };
        let content = incoming.content_hash();

        // One entity that cannot be written must not abort the pass. If it
        // did, the round would end with `dirty` still set, retry from the
        // top next time, and fail in the same place forever — logging the
        // same error every round while every *other* peer's changes waited
        // behind it.
        match write_one(vault, &entity, &incoming, &recycled) {
            Ok(Written::Created) => applied.created += 1,
            Ok(Written::Updated) => applied.updated += 1,
            Ok(Written::Unchanged) => {}
            Err(e) => {
                applied.failed += 1;
                // The mark is left alone, so the next round tries again.
                let _ = e;
                continue;
            }
        }

        marks.insert(entity, EntityMark { content, hlc });
    }

    Ok(applied)
}

/// What writing one incoming entry did.
enum Written {
    Created,
    Updated,
    Unchanged,
}

/// Put one incoming entry into the vault, whatever state it is in here.
fn write_one(
    vault: &mut Vault,
    entity: &str,
    incoming: &SyncEntry,
    recycled: &std::collections::BTreeSet<String>,
) -> Result<Written> {
    let Ok(existing) = vault.get_entry_including_deleted(entity) else {
        vault.add_entry(incoming.clone().into_password_entry(entity)?)?;
        return Ok(Written::Created);
    };

    let was_deleted = recycled.contains(entity);
    if was_deleted {
        // A peer edited an entry this device had deleted, and the edit is
        // the later change: the entry comes back. The alternative — letting
        // a delete be final — makes a deletion on one device silently
        // discard work done on another, which is the worse failure for a
        // password.
        vault.restore_entry(entity)?;
    }

    if SyncEntry::from(&existing).content_hash() != incoming.content_hash() {
        write_entry(vault, entity, incoming)?;
        return Ok(Written::Updated);
    }
    Ok(if was_deleted { Written::Updated } else { Written::Unchanged })
}

/// Mint one signed op on the local replica.
fn mint(
    replica: &mut Replica,
    identity: &DeviceIdentity,
    entity: &str,
    kind: OpKind,
    payload: String,
) -> Result<Op> {
    replica.local_change(entity, kind, payload, |op| identity.sign_op(op))
}

fn delete_if_present(vault: &mut Vault, entity: &str) -> Result<bool> {
    match vault.delete_entry(entity) {
        Ok(()) => Ok(true),
        // Already gone, or never here: a tombstone for an entry this device
        // has never seen is normal, not an error.
        Err(PassError::EntryNotFound(_)) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Overwrite a vault entry from an incoming one, field by field.
///
/// Goes through [`Vault::update_entry`] rather than delete-and-re-add so
/// that the KDBX history keeps the password being replaced — the safety net
/// `docs/SYNC_STRATEGY.md` promises for the one case where last-writer-wins
/// can surprise someone.
fn write_entry(vault: &mut Vault, entity: &str, incoming: &SyncEntry) -> Result<()> {
    vault.update_entry(
        entity,
        Some(incoming.website.clone()),
        Some(incoming.url.clone()),
        Some(incoming.username.clone()),
        Some(incoming.password.clone()),
        Some(incoming.notes.clone()),
        Some(incoming.additional_urls.clone()),
    )?;

    match &incoming.totp_uri {
        Some(uri) => vault.set_entry_totp(entity, passlib::totp::parse_otpauth_uri(uri)?)?,
        None => vault.clear_entry_totp(entity)?,
    }

    Ok(())
}
