//! Conflict resolution for merging two independently-edited copies of a
//! vault's entries (e.g. one from this device, one pulled from a synced
//! copy on another device).
//!
//! Every [`crate::entry::PasswordEntry`] carries a `revision` counter that
//! is bumped on every edit (including deletion, which is a tombstone
//! rather than a removal). That turns the entry set into a small
//! last-writer-wins CRDT: merging is a plain per-id union that keeps
//! whichever side has the higher revision, with a deterministic tie-break
//! when two sides bumped the same entry independently. No shared merge
//! base or history is required, and `merge_entries(a, b)` always produces
//! the same result regardless of which side is "mine" and which is
//! "theirs" or which device performs the merge.

use crate::entry::PasswordEntry;
use std::collections::HashMap;

/// Outcome of a merge, useful for logging or notifying the user about
/// what changed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MergeSummary {
    /// Entries present on the other side but not on this one.
    pub added: usize,
    /// Entries where the other side had a strictly newer revision.
    pub updated: usize,
    /// Entries that were identical (or where this side was already newer).
    pub unchanged: usize,
    /// Entries edited independently on both sides (same revision, different
    /// content) whose winner was picked by the tie-break rule.
    pub conflicts: usize,
}

impl MergeSummary {
    /// Whether the merge actually changed this side's entries.
    pub fn changed(&self) -> bool {
        self.added > 0 || self.updated > 0 || self.conflicts > 0
    }
}

/// Merge `theirs` into `mine`, returning the merged entry set and a
/// summary of what happened. Commutative and idempotent: merging the same
/// pair of states twice, or in either order, converges to the same result.
pub fn merge_entries(mine: &[PasswordEntry], theirs: &[PasswordEntry]) -> (Vec<PasswordEntry>, MergeSummary) {
    let mut merged: HashMap<String, PasswordEntry> = HashMap::with_capacity(mine.len());
    for entry in mine {
        merged.insert(entry.id.clone(), entry.clone());
    }

    let mut summary = MergeSummary::default();

    for their_entry in theirs {
        match merged.get(&their_entry.id) {
            None => {
                merged.insert(their_entry.id.clone(), their_entry.clone());
                summary.added += 1;
            }
            Some(my_entry) => {
                if my_entry.revision == their_entry.revision {
                    if my_entry.fingerprint() == their_entry.fingerprint() {
                        summary.unchanged += 1;
                    } else {
                        // Both sides bumped this entry independently without
                        // seeing each other's change: a genuine conflict.
                        summary.conflicts += 1;
                        let winner = pick_winner(my_entry, their_entry).clone();
                        merged.insert(their_entry.id.clone(), winner);
                    }
                } else if their_entry.revision > my_entry.revision {
                    merged.insert(their_entry.id.clone(), their_entry.clone());
                    summary.updated += 1;
                } else {
                    // My revision is already newer; nothing to do.
                    summary.unchanged += 1;
                }
            }
        }
    }

    let mut result: Vec<PasswordEntry> = merged.into_values().collect();
    result.sort_by(|a, b| a.id.cmp(&b.id));
    (result, summary)
}

/// Deterministic winner selection for two entries that share a revision
/// number. Order of preference:
/// 1. Higher revision (shouldn't apply here, kept for reuse/safety).
/// 2. A deletion beats a live edit — a safer default for a password
///    manager than accidentally resurrecting a credential that was
///    deliberately removed on another device.
/// 3. The more recent `updated_at`.
/// 4. The content fingerprint, as an arbitrary but stable last resort so
///    the outcome never depends on which side happens to run the merge.
fn pick_winner<'a>(a: &'a PasswordEntry, b: &'a PasswordEntry) -> &'a PasswordEntry {
    if a.revision != b.revision {
        return if a.revision > b.revision { a } else { b };
    }
    match (a.is_deleted(), b.is_deleted()) {
        (true, false) => return a,
        (false, true) => return b,
        _ => {}
    }
    if a.updated_at != b.updated_at {
        return if a.updated_at > b.updated_at { a } else { b };
    }
    if a.fingerprint() >= b.fingerprint() {
        a
    } else {
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(website: &str) -> PasswordEntry {
        PasswordEntry::new(
            website.to_string(),
            format!("https://{website}.example"),
            "user".to_string(),
            "hunter2".to_string(),
        )
    }

    #[test]
    fn new_entries_on_either_side_are_added() {
        let mine = vec![entry("github")];
        let theirs = vec![entry("gitlab")];

        let (merged, summary) = merge_entries(&mine, &theirs);

        assert_eq!(merged.len(), 2);
        assert_eq!(summary.added, 1);
        assert_eq!(summary.updated, 0);
        assert_eq!(summary.conflicts, 0);
    }

    #[test]
    fn newer_revision_wins_regardless_of_side() {
        let mine_entry = entry("github");
        let mut theirs_entry = mine_entry.clone();
        theirs_entry.update(Some("GitHub Enterprise".to_string()), None, None);

        assert!(theirs_entry.revision > mine_entry.revision);

        let (merged, summary) = merge_entries(&[mine_entry.clone()], &[theirs_entry.clone()]);
        assert_eq!(merged[0].website, "GitHub Enterprise");
        assert_eq!(summary.updated, 1);

        // Same merge run the other way round must converge to the same result.
        let (merged_rev, _) = merge_entries(&[theirs_entry], &[mine_entry]);
        assert_eq!(merged_rev[0].website, "GitHub Enterprise");
    }

    #[test]
    fn concurrent_edits_resolve_deterministically_both_ways() {
        let base = entry("github");
        let mut a = base.clone();
        a.update(Some("A's edit".to_string()), None, None);
        let mut b = base.clone();
        b.update(Some("B's edit".to_string()), None, None);

        assert_eq!(a.revision, b.revision); // concurrent, same base revision

        let (merged_ab, summary_ab) = merge_entries(&[a.clone()], &[b.clone()]);
        let (merged_ba, summary_ba) = merge_entries(&[b.clone()], &[a.clone()]);

        assert_eq!(summary_ab.conflicts, 1);
        assert_eq!(summary_ba.conflicts, 1);
        // merge(a, b) and merge(b, a) must agree on the winner.
        assert_eq!(merged_ab[0].website, merged_ba[0].website);
    }

    #[test]
    fn deletion_propagates_as_tombstone() {
        let base = entry("github");
        let mut deleted = base.clone();
        deleted.mark_deleted();

        let (merged, summary) = merge_entries(&[base], &[deleted]);

        assert_eq!(summary.updated, 1);
        assert!(merged[0].is_deleted());
    }

    #[test]
    fn deletion_wins_a_same_revision_conflict_with_a_live_edit() {
        let base = entry("github");
        let mut deleted = base.clone();
        deleted.mark_deleted();
        let mut edited = base.clone();
        edited.update(Some("still alive".to_string()), None, None);

        assert_eq!(deleted.revision, edited.revision);

        let (merged, summary) = merge_entries(&[deleted], &[edited]);

        assert_eq!(summary.conflicts, 1);
        assert!(merged[0].is_deleted());
    }

    #[test]
    fn identical_entries_are_unchanged() {
        let e = entry("github");
        let (merged, summary) = merge_entries(&[e.clone()], &[e.clone()]);

        assert_eq!(summary.unchanged, 1);
        assert!(!summary.changed());
        assert_eq!(merged.len(), 1);
    }
}
