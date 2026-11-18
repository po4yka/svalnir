//! Pure grouping of the children of a scan root into chart segments.

use crate::data::model::{ChildSize, SizeMetric};

/// One segment of the breakdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// The label.
    pub label: String,
    /// The size in the chosen metric.
    pub bytes: u64,
    /// Whether this is the "Other" remainder.
    pub is_other: bool,
    /// The index of the child in the input, for a child segment.
    pub source_index: Option<usize>,
}

/// The default number of segments: seven children and "Other".
pub const DEFAULT_SEGMENTS: usize = 8;

/// Sorts the children by `metric` (largest first, ties by name), keeps the
/// `max_segments - 1` largest, and sums the rest into "Other (N items)".
/// A child of zero bytes is not a segment; it counts in the N of "Other".
#[must_use]
pub fn breakdown(children: &[ChildSize], metric: SizeMetric, max_segments: usize) -> Vec<Segment> {
    let mut order: Vec<usize> = (0..children.len())
        .filter(|&index| children[index].size(metric) > 0)
        .collect();
    order.sort_by(|&a, &b| {
        children[b]
            .size(metric)
            .cmp(&children[a].size(metric))
            .then_with(|| children[a].name.cmp(&children[b].name))
    });
    let zero_count: usize = children.len() - order.len();
    let keep: usize = if order.len() + usize::from(zero_count > 0) <= max_segments {
        order.len()
    } else {
        max_segments.saturating_sub(1)
    };
    let mut segments: Vec<Segment> = order[..keep]
        .iter()
        .map(|&index| Segment {
            label: children[index].name.clone(),
            bytes: children[index].size(metric),
            is_other: false,
            source_index: Some(index),
        })
        .collect();
    let rest: &[usize] = &order[keep..];
    let rest_bytes: u64 = rest
        .iter()
        .map(|&index| children[index].size(metric))
        .fold(0_u64, u64::saturating_add);
    if rest_bytes > 0 {
        segments.push(Segment {
            label: format!("Other ({} items)", rest.len() + zero_count),
            bytes: rest_bytes,
            is_other: true,
            source_index: None,
        });
    }
    segments
}

#[cfg(test)]
mod tests {
    use super::*;

    fn child(name: &str, allocated: u64) -> ChildSize {
        ChildSize {
            name: name.to_owned(),
            is_directory: true,
            logical: allocated / 2,
            allocated,
        }
    }

    #[test]
    fn sorted_with_other_remainder() {
        let children: Vec<ChildSize> = (1..=10_u64)
            .map(|n| child(&format!("c{n:02}"), n * 100))
            .chain([child("zero", 0)])
            .collect();
        let segments = breakdown(&children, SizeMetric::Allocated, 8);
        assert_eq!(segments.len(), 8);
        assert_eq!(segments[0].label, "c10");
        assert_eq!(segments[6].label, "c04");
        let other = &segments[7];
        assert!(other.is_other);
        assert_eq!(other.bytes, (1 + 2 + 3) * 100);
        assert_eq!(other.label, "Other (4 items)");
        let sum: u64 = segments.iter().map(|s| s.bytes).sum();
        assert_eq!(sum, 5500);
    }

    #[test]
    fn few_children_have_no_other() {
        let children = [child("b", 10), child("a", 10), child("c", 30)];
        let segments = breakdown(&children, SizeMetric::Allocated, 8);
        let labels: Vec<&str> = segments.iter().map(|s| s.label.as_str()).collect();
        assert_eq!(labels, ["c", "a", "b"]);
        assert!(segments.iter().all(|s| !s.is_other));
    }

    #[test]
    fn all_zero_is_empty() {
        let children = [child("a", 0), child("b", 0)];
        assert_eq!(breakdown(&children, SizeMetric::Allocated, 8), Vec::new());
    }

    #[test]
    fn metric_selects_the_size() {
        let children = [child("a", 100), child("b", 10)];
        let segments = breakdown(&children, SizeMetric::Logical, 8);
        assert_eq!(segments[0].bytes, 50);
    }
}
