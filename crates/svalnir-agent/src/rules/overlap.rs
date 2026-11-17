//! Overlap between the candidates of the rules.
//!
//! `docs/CLEANUP_RULES.md` section 8 owns the contract: one object has one
//! execution rule revision, and a parent and a descendant are not two
//! deletions.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use svalnir_core::file::{FileObjectEvidence, LosslessPath};
use svalnir_core::rule::RuleRef;

use super::model::DiscoveredCandidate;

/// The largest number of conflicts in one [`OverlapResolution`].
pub const MAX_REPORTED_CONFLICTS: usize = 1_024;

/// How two candidates overlap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverlapKind {
    /// The two candidates are one object: the same path, or the same
    /// device and inode on one volume.
    SameObject,
    /// One candidate is below the other candidate.
    Nested,
}

/// One candidate of a conflict.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Claim {
    /// The rule revision that found the candidate.
    pub rule: RuleRef,
    /// The path of the candidate.
    pub path: LosslessPath,
    /// `st_dev` and `st_ino` of the candidate.
    pub object: FileObjectEvidence,
}

/// One conflict between two candidates.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OverlapConflict {
    /// How the two candidates overlap.
    pub kind: OverlapKind,
    /// The candidate that keeps the claim. It is a candidate of the
    /// result. `None` when no candidate keeps the claim: the ownership is
    /// ambiguous and the two candidates are rejected, or another conflict
    /// rejected the candidate that won this one.
    pub claimant: Option<Claim>,
    /// The candidates that the conflict rejects: one, or the two
    /// candidates of an ambiguous conflict.
    pub rejected: Vec<Claim>,
}

/// The candidates with no overlap, and the conflicts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlapResolution {
    /// The candidates that no conflict rejected, in the input sequence.
    /// No two of them are one object, and no one is below another one.
    pub candidates: Vec<DiscoveredCandidate>,
    /// The conflicts, in the input sequence of their first candidate.
    pub conflicts: Vec<OverlapConflict>,
    /// The number of conflicts that are not in `conflicts`.
    pub conflicts_omitted: u64,
}

fn claim_of(candidate: &DiscoveredCandidate) -> Claim {
    Claim {
        rule: candidate.candidate.rule.clone(),
        path: candidate.candidate.candidate.path.clone(),
        object: candidate.evidence.object,
    }
}

/// Which candidate of an overlapping pair keeps the claim.
enum Winner {
    First,
    Second,
    Neither,
}

/// Gives each overlapping path to one rule revision.
///
/// Each pair of candidates is examined. Two candidates overlap when they
/// are one object or when one is below the other one. The decision of a
/// pair is:
///
/// - One rule revision, one object: the first candidate of the input
///   keeps the claim.
/// - One rule revision, nested: the parent keeps the claim, because its
///   removal includes the descendant.
/// - Two rule revisions: the candidate whose approved root is below the
///   approved root of the other candidate keeps the claim. That root is
///   the more specific statement of ownership, and the removal of the
///   other candidate would remove data of that root.
/// - Two rule revisions with the same root, or with roots that are not
///   nested: the ownership is ambiguous. No candidate keeps the claim.
///   The most permissive rule is not selected.
///
/// A candidate that a decision rejects stays rejected, so the result does
/// not depend on the input sequence, except for the selection between two
/// equal candidates of one rule revision. The comparison is quadratic;
/// the caller bounds the list.
pub fn resolve_overlaps(candidates: Vec<DiscoveredCandidate>) -> OverlapResolution {
    let paths: Vec<PathBuf> = candidates
        .iter()
        .map(|candidate| candidate.candidate.candidate.path.to_path_buf())
        .collect();
    let roots: Vec<PathBuf> = candidates
        .iter()
        .map(|candidate| candidate.root.path.to_path_buf())
        .collect();
    let mut rejected: Vec<bool> = vec![false; candidates.len()];
    // The conflicts as indices. The claims are made after each pair is
    // decided, so that no conflict names a claimant that a later pair
    // rejected.
    let mut decided: Vec<(OverlapKind, Option<usize>, Vec<usize>)> = Vec::new();
    let mut conflicts_omitted: u64 = 0;

    for (first, first_candidate) in candidates.iter().enumerate() {
        for (second, second_candidate) in
            candidates.iter().enumerate().skip(first.saturating_add(1))
        {
            let (first_path, second_path) = (&paths[first], &paths[second]);
            let same_object: bool = first_path == second_path
                || (first_candidate.root.volume_id == second_candidate.root.volume_id
                    && first_candidate.evidence.object == second_candidate.evidence.object);
            let first_in_second: bool = first_path.starts_with(second_path);
            let second_in_first: bool = second_path.starts_with(first_path);
            if !(same_object || first_in_second || second_in_first) {
                continue;
            }
            let kind: OverlapKind = if same_object {
                OverlapKind::SameObject
            } else {
                OverlapKind::Nested
            };
            let same_rule: bool = first_candidate.candidate.rule == second_candidate.candidate.rule;
            let (first_root, second_root) = (&roots[first], &roots[second]);
            let winner: Winner = if same_rule {
                if same_object || second_in_first {
                    Winner::First
                } else {
                    Winner::Second
                }
            } else if first_root != second_root && first_root.starts_with(second_root) {
                Winner::First
            } else if first_root != second_root && second_root.starts_with(first_root) {
                Winner::Second
            } else {
                Winner::Neither
            };
            let (claimant, losers): (Option<usize>, Vec<usize>) = match winner {
                Winner::First => (Some(first), vec![second]),
                Winner::Second => (Some(second), vec![first]),
                Winner::Neither => (None, vec![first, second]),
            };
            for loser in &losers {
                rejected[*loser] = true;
            }
            if decided.len() < MAX_REPORTED_CONFLICTS {
                decided.push((kind, claimant, losers));
            } else {
                conflicts_omitted = conflicts_omitted.saturating_add(1);
            }
        }
    }
    let claim_at = |index: usize| candidates.get(index).map(claim_of);
    let conflicts: Vec<OverlapConflict> = decided
        .into_iter()
        .map(|(kind, claimant, losers)| OverlapConflict {
            kind,
            claimant: claimant
                .filter(|index| rejected.get(*index) == Some(&false))
                .and_then(claim_at),
            rejected: losers.into_iter().filter_map(claim_at).collect(),
        })
        .collect();
    let candidates: Vec<DiscoveredCandidate> = candidates
        .into_iter()
        .zip(rejected)
        .filter_map(|(candidate, is_rejected)| (!is_rejected).then_some(candidate))
        .collect();
    OverlapResolution {
        candidates,
        conflicts,
        conflicts_omitted,
    }
}
