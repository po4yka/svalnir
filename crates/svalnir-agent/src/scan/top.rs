//! A bounded list of the largest items.

use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;

use svalnir_core::quantity::Bytes;

use super::model::{LargeDirectory, LargeFile};

/// The order of an item: allocated size, then logical size.
pub(super) type Rank = (Bytes, Bytes);

/// An item that a [`TopList`] can order.
pub(super) trait Ranked {
    /// The allocated size and the logical size of the item.
    fn rank(&self) -> Rank;
    /// The path bytes of the item. They make the order total, so the list
    /// does not depend on the order of the directory listing.
    fn path_bytes(&self) -> &[u8];
}

impl Ranked for LargeFile {
    fn rank(&self) -> Rank {
        (self.allocated_bytes, self.logical_bytes)
    }

    fn path_bytes(&self) -> &[u8] {
        self.path.as_bytes()
    }
}

impl Ranked for LargeDirectory {
    fn rank(&self) -> Rank {
        (self.allocated_bytes, self.logical_bytes)
    }

    fn path_bytes(&self) -> &[u8] {
        self.path.as_bytes()
    }
}

/// Compares two items. The larger rank is greater. For an equal rank, the
/// path that sorts first is greater.
fn compare(left: (Rank, &[u8]), right: (Rank, &[u8])) -> Ordering {
    left.0.cmp(&right.0).then_with(|| right.1.cmp(left.1))
}

struct Slot<T>(T);

impl<T: Ranked> Ord for Slot<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        compare(
            (self.0.rank(), self.0.path_bytes()),
            (other.0.rank(), other.0.path_bytes()),
        )
    }
}

impl<T: Ranked> PartialOrd for Slot<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Ranked> PartialEq for Slot<T> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl<T: Ranked> Eq for Slot<T> {}

/// The `limit` largest items that the list received. The list never holds
/// more than `limit` items.
pub(super) struct TopList<T: Ranked> {
    limit: usize,
    /// A min-heap: the top of the heap is the smallest item of the list.
    heap: BinaryHeap<Reverse<Slot<T>>>,
}

impl<T: Ranked> TopList<T> {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            limit,
            heap: BinaryHeap::new(),
        }
    }

    /// Whether an item with this rank and path would enter the list. The
    /// caller uses this check to make the item only when necessary.
    pub(super) fn admits(&self, rank: Rank, path: &[u8]) -> bool {
        if self.heap.len() < self.limit {
            return true;
        }
        self.heap.peek().is_some_and(|Reverse(smallest)| {
            compare((rank, path), (smallest.0.rank(), smallest.0.path_bytes())) == Ordering::Greater
        })
    }

    /// Adds the item when it is one of the `limit` largest.
    pub(super) fn offer(&mut self, item: T) {
        if !self.admits(item.rank(), item.path_bytes()) {
            return;
        }
        if self.heap.len() >= self.limit {
            drop(self.heap.pop());
        }
        self.heap.push(Reverse(Slot(item)));
    }

    /// The items, largest first.
    pub(super) fn into_largest_first(self) -> Vec<T> {
        self.heap
            .into_sorted_vec()
            .into_iter()
            .map(|Reverse(Slot(item))| item)
            .collect()
    }
}
