//! The scan ghost: a pure comparison of two scans of one root
//! (`DESIGN.md` section 5, "Scan ghost").

use crate::{
    data::model::{ScanEnd, ScanSummary, SizeMetric},
    ui::data_state::format_bytes,
};
use std::collections::{BTreeSet, HashMap};
use std::path::Path;

/// The change of one item between two scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// The item is larger by this many bytes.
    Larger(u64),
    /// The item is smaller by this many bytes.
    Smaller(u64),
    /// The item has the same size.
    Same,
    /// The earlier scan has no item with this path.
    New,
}

/// An item of the earlier scan that the later scan does not have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoneItem {
    /// The name.
    pub name: String,
    /// The size in the earlier scan.
    pub bytes: u64,
}

/// The comparison of two scans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanDelta {
    /// One change for each child of the later scan, in its order. Empty when
    /// the scans are not comparable.
    pub changes: Vec<Change>,
    /// The items that are gone, the largest first. Empty when the scans are
    /// not comparable.
    pub gone: Vec<GoneItem>,
    /// Whether the two scans can be compared.
    pub comparable: bool,
}

/// The causes of the gaps of a scan.
fn causes(summary: &ScanSummary) -> BTreeSet<&str> {
    summary.gaps.iter().map(|g| g.cause_text.as_str()).collect()
}

/// Whether two scans can be compared: neither was cancelled, and either both
/// are complete, or both are partial for the same set of causes and ended the
/// same way.
#[must_use]
pub fn comparable(earlier: &ScanSummary, now: &ScanSummary) -> bool {
    if earlier.ended == ScanEnd::Cancelled || now.ended == ScanEnd::Cancelled {
        return false;
    }
    if earlier.complete && now.complete {
        return true;
    }
    earlier.complete == now.complete && earlier.ended == now.ended && causes(earlier) == causes(now)
}

/// Compares `now` with `earlier` in `metric`, matching children by path.
#[must_use]
pub fn scan_delta(earlier: &ScanSummary, now: &ScanSummary, metric: SizeMetric) -> ScanDelta {
    if !comparable(earlier, now) {
        return ScanDelta {
            changes: Vec::new(),
            gone: Vec::new(),
            comparable: false,
        };
    }
    let before: HashMap<&Path, u64> = earlier
        .children
        .iter()
        .map(|c| (c.path.as_path(), c.size(metric)))
        .collect();
    let changes: Vec<Change> = now
        .children
        .iter()
        .map(|child| match before.get(child.path.as_path()) {
            None => Change::New,
            Some(&old) => {
                let size: u64 = child.size(metric);
                match size.cmp(&old) {
                    std::cmp::Ordering::Greater => Change::Larger(size.saturating_sub(old)),
                    std::cmp::Ordering::Less => Change::Smaller(old.saturating_sub(size)),
                    std::cmp::Ordering::Equal => Change::Same,
                }
            }
        })
        .collect();
    let present: BTreeSet<&Path> = now.children.iter().map(|c| c.path.as_path()).collect();
    let mut gone: Vec<GoneItem> = earlier
        .children
        .iter()
        .filter(|c| !present.contains(c.path.as_path()) && c.size(metric) > 0)
        .map(|c| GoneItem {
            name: c.name.clone(),
            bytes: c.size(metric),
        })
        .collect();
    gone.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.name.cmp(&b.name)));
    ScanDelta {
        changes,
        gone,
        comparable: true,
    }
}

/// The legend text of a change and whether the item is larger: "+2.1 GB",
/// "−800.0 MB" (with U+2212), or "new". A same size has no text.
#[must_use]
pub fn change_text(change: Change) -> Option<(String, bool)> {
    let sized = |sign: char, bytes: u64| -> String {
        let (text, unit) = format_bytes(bytes);
        format!("{sign}{text} {unit}")
    };
    match change {
        Change::Larger(bytes) => Some((sized('+', bytes), true)),
        Change::Smaller(bytes) => Some((sized('\u{2212}', bytes), false)),
        Change::New => Some(("new".to_owned(), true)),
        Change::Same => None,
    }
}

/// The most names that the "Not in this scan" line lists.
const GONE_LISTED: usize = 5;

/// The line of the items that are gone, or `None` without any.
#[must_use]
pub fn gone_text(gone: &[GoneItem]) -> Option<String> {
    if gone.is_empty() {
        return None;
    }
    let listed: Vec<String> = gone
        .iter()
        .take(GONE_LISTED)
        .map(|g| {
            let (text, unit) = format_bytes(g.bytes);
            format!("{} ({text} {unit})", g.name)
        })
        .collect();
    let more: usize = gone.len().saturating_sub(GONE_LISTED);
    let tail: String = if more > 0 {
        format!(", and {more} more")
    } else {
        String::new()
    };
    Some(format!("Not in this scan: {}{tail}", listed.join(", ")))
}

/// The cells that a growth of `diff` bytes takes at `per_cell` bytes a cell:
/// rounded, 0 below half a cell, at most `max`.
#[must_use]
pub fn growth_cells(diff: u64, per_cell: u64, max: u32) -> u32 {
    if per_cell == 0 {
        return 0;
    }
    let cells: u128 = (u128::from(diff) * 2 + u128::from(per_cell)) / (u128::from(per_cell) * 2);
    u32::try_from(cells).unwrap_or(u32::MAX).min(max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::model::{ChildSize, GapRow};
    use std::{path::PathBuf, time::SystemTime};

    fn child(name: &str, bytes: u64) -> ChildSize {
        ChildSize {
            name: name.to_owned(),
            path: PathBuf::from("/r").join(name),
            is_directory: true,
            logical: bytes,
            allocated: bytes,
        }
    }

    fn scan(children: Vec<ChildSize>, complete: bool, causes: &[&str]) -> ScanSummary {
        ScanSummary {
            root: PathBuf::from("/r"),
            children,
            total_logical: 0,
            total_allocated: 0,
            entries_examined: 0,
            complete,
            ended: ScanEnd::Finished,
            gaps: causes
                .iter()
                .map(|c| GapRow {
                    cause_text: (*c).to_owned(),
                    count: 1,
                })
                .collect(),
            elapsed: None,
            finished_at: SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn larger_smaller_same_new_and_gone() {
        let a = scan(
            vec![
                child("a", 100),
                child("b", 500),
                child("c", 7),
                child("d", 90),
            ],
            true,
            &[],
        );
        let b = scan(
            vec![
                child("a", 160),
                child("b", 200),
                child("c", 7),
                child("e", 1),
            ],
            true,
            &[],
        );
        let delta = scan_delta(&a, &b, SizeMetric::Allocated);
        assert!(delta.comparable);
        assert_eq!(
            delta.changes,
            [
                Change::Larger(60),
                Change::Smaller(300),
                Change::Same,
                Change::New
            ]
        );
        assert_eq!(
            delta.gone,
            [GoneItem {
                name: "d".to_owned(),
                bytes: 90
            }]
        );
    }

    #[test]
    fn arithmetic_saturates_and_the_metric_is_used() {
        let mut big = child("a", u64::MAX);
        big.logical = 5;
        let a = scan(vec![child("a", 0)], true, &[]);
        let b = scan(vec![big], true, &[]);
        assert_eq!(
            scan_delta(&a, &b, SizeMetric::Allocated).changes,
            [Change::Larger(u64::MAX)]
        );
        assert_eq!(
            scan_delta(&a, &b, SizeMetric::Logical).changes,
            [Change::Larger(5)]
        );
    }

    #[test]
    fn scans_that_differ_in_their_gaps_are_not_comparable() {
        let a = scan(vec![child("a", 1)], false, &["permission denied"]);
        let b = scan(vec![child("a", 2)], false, &["permission denied"]);
        let c = scan(vec![child("a", 2)], false, &["no such file"]);
        let d = scan(vec![child("a", 2)], true, &[]);
        assert!(scan_delta(&a, &b, SizeMetric::Allocated).comparable);
        for other in [&c, &d] {
            let delta = scan_delta(&a, other, SizeMetric::Allocated);
            assert!(!delta.comparable);
            assert!(delta.changes.is_empty() && delta.gone.is_empty());
        }
        let mut cancelled = scan(vec![child("a", 2)], true, &[]);
        cancelled.ended = ScanEnd::Cancelled;
        assert!(!scan_delta(&d, &cancelled, SizeMetric::Allocated).comparable);
    }

    #[test]
    fn texts_use_the_real_minus_and_avoid_the_banned_words() {
        assert_eq!(
            change_text(Change::Larger(2_100_000_000)),
            Some(("+2.1 GB".to_owned(), true))
        );
        assert_eq!(
            change_text(Change::Smaller(800_000_000)),
            Some(("\u{2212}800.0 MB".to_owned(), false))
        );
        assert_eq!(change_text(Change::New), Some(("new".to_owned(), true)));
        assert_eq!(change_text(Change::Same), None);
        let gone = [
            GoneItem {
                name: "A".to_owned(),
                bytes: 3_100_000_000,
            },
            GoneItem {
                name: "B".to_owned(),
                bytes: 200_000_000,
            },
        ];
        assert_eq!(
            gone_text(&gone).as_deref(),
            Some("Not in this scan: A (3.1 GB), B (200.0 MB)")
        );
        assert_eq!(gone_text(&[]), None);
    }

    #[test]
    fn growth_rounds_to_cells() {
        assert_eq!(growth_cells(0, 100, 50), 0);
        assert_eq!(growth_cells(49, 100, 50), 0, "below half a cell");
        assert_eq!(growth_cells(50, 100, 50), 1);
        assert_eq!(growth_cells(1_000, 100, 4), 4, "at most the segment");
        assert_eq!(growth_cells(1_000, 0, 4), 0);
        assert_eq!(growth_cells(u64::MAX, 1, u32::MAX), u32::MAX);
    }
}
