//! Raw native samples.
//!
//! A raw sample has the native numbers of one call with no interpretation.
//! The native adapter makes it, and a test can make it from literals. The
//! builders in [`super::host`] and [`super::pressure`] turn a raw sample into
//! observations.

/// The fields of `vm_statistics64` that the collector reads.
///
/// Each count is a number of pages of the runtime VM page size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawVmStatistics {
    /// `free_count`. The speculative pages are a part of this count.
    pub free_count: u32,
    /// `active_count`.
    pub active_count: u32,
    /// `inactive_count`.
    pub inactive_count: u32,
    /// `wire_count`.
    pub wire_count: u32,
    /// `speculative_count`.
    pub speculative_count: u32,
    /// `pageins`: cumulative page-ins. Not swap-ins.
    pub pageins: u64,
    /// `pageouts`: cumulative page-outs. Not swap-outs.
    pub pageouts: u64,
    /// The fields of revision 1 of the structure. `None` when the kernel
    /// returned only revision 0.
    pub revision_1: Option<RawVmStatisticsRevision1>,
}

/// The fields that revision 1 of `vm_statistics64` adds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawVmStatisticsRevision1 {
    /// `decompressions`: cumulative page decompressions.
    pub decompressions: u64,
    /// `compressions`: cumulative page compressions.
    pub compressions: u64,
    /// `swapins`: cumulative pages swapped in through compressor segments.
    pub swapins: u64,
    /// `swapouts`: cumulative pages swapped out through compressor segments.
    pub swapouts: u64,
    /// `compressor_page_count`: pages that hold the compressed data.
    pub compressor_page_count: u32,
    /// `external_page_count`: file-backed pages.
    pub external_page_count: u32,
    /// `internal_page_count`: anonymous pages.
    pub internal_page_count: u32,
    /// `total_uncompressed_pages_in_compressor`: the logical pages that the
    /// compressed data represents.
    pub total_uncompressed_pages_in_compressor: u64,
}

/// The byte fields of `xsw_usage`, the value of `vm.swapusage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawSwapUsage {
    /// `xsu_total`: allocated swap space.
    pub total: u64,
    /// `xsu_avail`: allocated swap space that is not in use.
    pub available: u64,
    /// `xsu_used`: swap space in use.
    pub used: u64,
}
