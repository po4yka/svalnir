//! Physical memory, VM statistics, and swap space of the host.
//!
//! `docs/RESOURCE_MODEL.md` sections 9 and 12 own the metrics. Each builder
//! takes a raw sample, so a test or a replay can make the same observations
//! from recorded numbers. Each `collect_*` function makes one native query
//! in one acquisition window.

use svalnir_core::observation::{
    MetricId, MetricKind, Observation, Reading, Sample, UnavailableReason, Unit, metric,
};
use svalnir_core::quantity::{Bytes, CounterValue, PageCount};

use super::context::{CollectError, CollectionContext, MetricSpec, Provenance, reading_from};
use super::native;
use super::raw::{RawSwapUsage, RawVmStatistics, RawVmStatisticsRevision1};

/// The native API of the physical-memory query.
pub const PHYSICAL_NATIVE_API: &str = "sysctlbyname";
/// The native API of the VM statistics query.
pub const VM_NATIVE_API: &str = "host_statistics64(HOST_VM_INFO64)";
/// The native API of the page-size query.
pub const PAGE_SIZE_NATIVE_API: &str = "host_page_size";
/// The native API of the swap-space query.
pub const SWAP_NATIVE_API: &str = "sysctlbyname(vm.swapusage)";

/// Makes the `memory.physical_bytes` observation from a raw `hw.memsize`.
///
/// A raw zero is not a physical memory size: the reading is unavailable.
pub fn physical_memory_observation(
    context: &CollectionContext,
    raw: Result<u64, UnavailableReason>,
    sample: &Sample,
) -> Observation<Bytes> {
    let reading: Reading<Bytes> = reading_from(raw.and_then(|bytes| {
        if bytes == 0 {
            Err(UnavailableReason::InconsistentData)
        } else {
            Ok(Bytes::new(bytes))
        }
    }));
    context.observation(
        MetricSpec::new(metric::MEMORY_PHYSICAL_BYTES, Unit::Byte, MetricKind::Gauge),
        context.host_scope(),
        reading,
        Provenance {
            adapter: &context.adapters.sysctl,
            native_api: PHYSICAL_NATIVE_API,
            native_field: "hw.memsize",
        },
        sample,
    )
}

/// Reads the physical memory of the host.
///
/// # Errors
///
/// Returns a [`CollectError`] when the clock gives no acquisition window.
pub fn collect_physical_memory(
    context: &CollectionContext,
) -> Result<Observation<Bytes>, CollectError> {
    let acquisition = context.begin()?;
    let raw: Result<u64, UnavailableReason> = native::physical_memory_bytes();
    let sample: Sample = context.finish(acquisition)?;
    Ok(physical_memory_observation(context, raw, &sample))
}

/// The VM statistics of the host from one `host_statistics64` call.
///
/// Each observation has the same sample. The page gauges and the counters
/// use the unit `page`; [`VmStatistics::page_bytes`] converts a page count
/// with the runtime page size of this sample.
///
/// The categories are not disjoint. Do not add them to make a "used memory"
/// value: the speculative pages are a part of the free pages, and the
/// internal and external pages overlap the other gauges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmStatistics {
    /// The runtime VM page size of this sample, from `host_page_size`.
    pub page_size: Reading<Bytes>,
    /// The acquisition of the statistics and of the page size.
    pub sample: Sample,
    /// `memory.vm.free_pages`.
    pub free: Observation<PageCount>,
    /// `memory.vm.active_pages`.
    pub active: Observation<PageCount>,
    /// `memory.vm.inactive_pages`.
    pub inactive: Observation<PageCount>,
    /// `memory.vm.wired_pages`.
    pub wired: Observation<PageCount>,
    /// `memory.vm.speculative_pages`. A part of the free pages.
    pub speculative: Observation<PageCount>,
    /// `memory.vm.internal_pages`: anonymous pages.
    pub internal: Observation<PageCount>,
    /// `memory.vm.external_pages`: file-backed pages.
    pub external: Observation<PageCount>,
    /// `memory.vm.pageins_total`. Not swap-ins.
    pub pageins: Observation<CounterValue>,
    /// `memory.vm.pageouts_total`. Not swap-outs.
    pub pageouts: Observation<CounterValue>,
    /// `memory.compressor.physical_pages`: the pages that the compressed
    /// data physically occupies.
    pub compressor_physical: Observation<PageCount>,
    /// `memory.compressor.uncompressed_pages`: the logical pages that the
    /// compressed data represents. Not a physical quantity.
    pub compressor_uncompressed: Observation<PageCount>,
    /// `memory.compressor.compressions_total`.
    pub compressions: Observation<CounterValue>,
    /// `memory.compressor.decompressions_total`.
    pub decompressions: Observation<CounterValue>,
    /// `memory.swap.swapins_total`: pages swapped in through compressor
    /// segments.
    pub swapins: Observation<CounterValue>,
    /// `memory.swap.swapouts_total`: pages swapped out through compressor
    /// segments.
    pub swapouts: Observation<CounterValue>,
}

impl VmStatistics {
    /// The byte representation of a page count of this sample.
    ///
    /// The result is unavailable when the count or the page size is
    /// unavailable, and has the reason `overflow` when the product does not
    /// fit. A count of another sample is `inconsistent_data`: the page size
    /// of this sample is not its evidence. The bytes describe that count only: the bytes of the physical
    /// compressor pages and of the uncompressed pages are different
    /// quantities.
    pub fn page_bytes(&self, pages: &Observation<PageCount>) -> Reading<Bytes> {
        if pages.sample.sample_id != self.sample.sample_id {
            // The count is of another sample: this page size is not its
            // evidence.
            return Reading::Unavailable(UnavailableReason::InconsistentData);
        }
        let count: PageCount = match &pages.reading {
            Reading::Available(count) => *count,
            Reading::Unavailable(reason) => return Reading::Unavailable(reason.clone()),
            Reading::Unrecognized(text) => return Reading::Unrecognized(text.clone()),
        };
        let page_size: Bytes = match &self.page_size {
            Reading::Available(page_size) => *page_size,
            Reading::Unavailable(reason) => return Reading::Unavailable(reason.clone()),
            Reading::Unrecognized(text) => return Reading::Unrecognized(text.clone()),
        };
        match count.to_bytes(page_size) {
            Some(bytes) => Reading::Available(bytes),
            None => Reading::Unavailable(UnavailableReason::Overflow),
        }
    }
}

/// The inputs of the VM observations of one sample.
struct VmFields<'a> {
    context: &'a CollectionContext,
    sample: &'a Sample,
    raw: Result<RawVmStatistics, UnavailableReason>,
    revision_1: Result<RawVmStatisticsRevision1, UnavailableReason>,
}

impl VmFields<'_> {
    fn provenance<'b>(&'b self, field: &'b str) -> Provenance<'b> {
        Provenance {
            adapter: &self.context.adapters.mach_host,
            native_api: VM_NATIVE_API,
            native_field: field,
        }
    }

    fn gauge(
        &self,
        id: MetricId,
        field: &str,
        pages: Result<u64, UnavailableReason>,
    ) -> Observation<PageCount> {
        self.context.observation(
            MetricSpec::new(id, Unit::Page, MetricKind::Gauge),
            self.context.host_scope(),
            reading_from(pages.map(PageCount::new)),
            self.provenance(field),
            self.sample,
        )
    }

    fn counter(
        &self,
        id: MetricId,
        field: &str,
        count: Result<u64, UnavailableReason>,
    ) -> Observation<CounterValue> {
        self.context.observation(
            MetricSpec::new(id, Unit::Page, MetricKind::Counter),
            self.context.host_scope(),
            reading_from(count.map(CounterValue::new)),
            self.provenance(field),
            self.sample,
        )
    }

    /// A field of revision 0 of the native structure.
    fn base(&self, select: fn(&RawVmStatistics) -> u64) -> Result<u64, UnavailableReason> {
        self.raw.as_ref().map(select).map_err(Clone::clone)
    }

    /// A field that revision 1 of the native structure adds.
    fn extended(
        &self,
        select: fn(&RawVmStatisticsRevision1) -> u64,
    ) -> Result<u64, UnavailableReason> {
        self.revision_1.as_ref().map(select).map_err(Clone::clone)
    }

    fn base_gauge(
        &self,
        id: MetricId,
        field: &str,
        select: fn(&RawVmStatistics) -> u64,
    ) -> Observation<PageCount> {
        self.gauge(id, field, self.base(select))
    }

    fn base_counter(
        &self,
        id: MetricId,
        field: &str,
        select: fn(&RawVmStatistics) -> u64,
    ) -> Observation<CounterValue> {
        self.counter(id, field, self.base(select))
    }

    fn extended_gauge(
        &self,
        id: MetricId,
        field: &str,
        select: fn(&RawVmStatisticsRevision1) -> u64,
    ) -> Observation<PageCount> {
        self.gauge(id, field, self.extended(select))
    }

    fn extended_counter(
        &self,
        id: MetricId,
        field: &str,
        select: fn(&RawVmStatisticsRevision1) -> u64,
    ) -> Observation<CounterValue> {
        self.counter(id, field, self.extended(select))
    }
}

/// Makes the VM observations from a raw sample and a raw page size.
///
/// A page size of zero is not valid. A field of revision 1 of the native
/// structure is `unsupported` when the kernel returned only revision 0.
pub fn vm_statistics(
    context: &CollectionContext,
    raw: Result<RawVmStatistics, UnavailableReason>,
    page_size: Result<u64, UnavailableReason>,
    sample: &Sample,
) -> VmStatistics {
    let page_size: Reading<Bytes> = reading_from(page_size.and_then(|bytes| {
        if bytes == 0 {
            Err(UnavailableReason::InconsistentData)
        } else {
            Ok(Bytes::new(bytes))
        }
    }));
    let revision_1: Result<RawVmStatisticsRevision1, UnavailableReason> = raw
        .clone()
        .and_then(|raw| raw.revision_1.ok_or(UnavailableReason::Unsupported));
    let fields = VmFields {
        context,
        sample,
        raw,
        revision_1,
    };
    VmStatistics {
        free: fields.base_gauge(metric::MEMORY_VM_FREE_PAGES, "free_count", |raw| {
            raw.free_count.into()
        }),
        active: fields.base_gauge(metric::MEMORY_VM_ACTIVE_PAGES, "active_count", |raw| {
            raw.active_count.into()
        }),
        inactive: fields.base_gauge(metric::MEMORY_VM_INACTIVE_PAGES, "inactive_count", |raw| {
            raw.inactive_count.into()
        }),
        wired: fields.base_gauge(metric::MEMORY_VM_WIRED_PAGES, "wire_count", |raw| {
            raw.wire_count.into()
        }),
        speculative: fields.base_gauge(
            metric::MEMORY_VM_SPECULATIVE_PAGES,
            "speculative_count",
            |raw| raw.speculative_count.into(),
        ),
        internal: fields.extended_gauge(
            metric::MEMORY_VM_INTERNAL_PAGES,
            "internal_page_count",
            |raw| raw.internal_page_count.into(),
        ),
        external: fields.extended_gauge(
            metric::MEMORY_VM_EXTERNAL_PAGES,
            "external_page_count",
            |raw| raw.external_page_count.into(),
        ),
        pageins: fields.base_counter(metric::MEMORY_VM_PAGEINS_TOTAL, "pageins", |raw| {
            raw.pageins
        }),
        pageouts: fields.base_counter(metric::MEMORY_VM_PAGEOUTS_TOTAL, "pageouts", |raw| {
            raw.pageouts
        }),
        compressor_physical: fields.extended_gauge(
            metric::MEMORY_COMPRESSOR_PHYSICAL_PAGES,
            "compressor_page_count",
            |raw| raw.compressor_page_count.into(),
        ),
        compressor_uncompressed: fields.extended_gauge(
            metric::MEMORY_COMPRESSOR_UNCOMPRESSED_PAGES,
            "total_uncompressed_pages_in_compressor",
            |raw| raw.total_uncompressed_pages_in_compressor,
        ),
        compressions: fields.extended_counter(
            metric::MEMORY_COMPRESSOR_COMPRESSIONS_TOTAL,
            "compressions",
            |raw| raw.compressions,
        ),
        decompressions: fields.extended_counter(
            metric::MEMORY_COMPRESSOR_DECOMPRESSIONS_TOTAL,
            "decompressions",
            |raw| raw.decompressions,
        ),
        swapins: fields.extended_counter(metric::MEMORY_SWAP_SWAPINS_TOTAL, "swapins", |raw| {
            raw.swapins
        }),
        swapouts: fields.extended_counter(metric::MEMORY_SWAP_SWAPOUTS_TOTAL, "swapouts", |raw| {
            raw.swapouts
        }),
        page_size,
        sample: sample.clone(),
    }
}

/// Reads the VM statistics and the runtime page size of the host.
///
/// The two queries are in one acquisition window.
///
/// The kernel limits how frequently a process that is not a platform binary
/// gets new host statistics. A call above that limit gets the values of an
/// earlier call, so two samples that are less than some seconds apart can
/// have the same counters. Sample at an interval of seconds, not less.
///
/// # Errors
///
/// Returns a [`CollectError`] when the clock gives no acquisition window.
pub fn collect_vm_statistics(context: &CollectionContext) -> Result<VmStatistics, CollectError> {
    let acquisition = context.begin()?;
    let page_size: Result<u64, UnavailableReason> = native::vm_page_size();
    let raw: Result<RawVmStatistics, UnavailableReason> = native::vm_statistics();
    let sample: Sample = context.finish(acquisition)?;
    Ok(vm_statistics(context, raw, page_size, &sample))
}

/// The swap space of the host from one `vm.swapusage` read.
///
/// Swap space is occupancy and allocation. It is not swap activity: the
/// activity is in the swap-in and swap-out counters of [`VmStatistics`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapUsage {
    /// `memory.swap.allocated_bytes`: `xsu_total`.
    pub allocated: Observation<Bytes>,
    /// `memory.swap.used_bytes`: `xsu_used`.
    pub used: Observation<Bytes>,
    /// `memory.swap.available_bytes`: `xsu_avail`.
    pub available: Observation<Bytes>,
}

/// Makes the swap observations from a raw `xsw_usage`.
///
/// A used or available value that is larger than the allocated value is not
/// consistent: that reading is unavailable.
pub fn swap_usage(
    context: &CollectionContext,
    raw: Result<RawSwapUsage, UnavailableReason>,
    sample: &Sample,
) -> SwapUsage {
    let within_allocated = |select: fn(&RawSwapUsage) -> u64| {
        raw.as_ref().map_err(Clone::clone).and_then(|raw| {
            let value: u64 = select(raw);
            if value > raw.total {
                Err(UnavailableReason::InconsistentData)
            } else {
                Ok(Bytes::new(value))
            }
        })
    };
    let gauge = |id: MetricId, field: &str, value: Result<Bytes, UnavailableReason>| {
        context.observation(
            MetricSpec::new(id, Unit::Byte, MetricKind::Gauge),
            context.host_scope(),
            reading_from(value),
            Provenance {
                adapter: &context.adapters.sysctl,
                native_api: SWAP_NATIVE_API,
                native_field: field,
            },
            sample,
        )
    };
    let used: Observation<Bytes> = gauge(
        metric::MEMORY_SWAP_USED_BYTES,
        "xsu_used",
        within_allocated(|raw| raw.used),
    );
    let available: Observation<Bytes> = gauge(
        metric::MEMORY_SWAP_AVAILABLE_BYTES,
        "xsu_avail",
        within_allocated(|raw| raw.available),
    );
    let allocated: Observation<Bytes> = gauge(
        metric::MEMORY_SWAP_ALLOCATED_BYTES,
        "xsu_total",
        raw.map(|raw| Bytes::new(raw.total)),
    );
    SwapUsage {
        allocated,
        used,
        available,
    }
}

/// Reads the swap space of the host.
///
/// # Errors
///
/// Returns a [`CollectError`] when the clock gives no acquisition window.
pub fn collect_swap_usage(context: &CollectionContext) -> Result<SwapUsage, CollectError> {
    let acquisition = context.begin()?;
    let raw: Result<RawSwapUsage, UnavailableReason> = native::swap_usage();
    let sample: Sample = context.finish(acquisition)?;
    Ok(swap_usage(context, raw, &sample))
}

#[cfg(test)]
mod tests {
    use svalnir_core::observation::{
        Coverage, MetricKind, Reading, ScopeKind, UnavailableReason, Unit, metric,
    };
    use svalnir_core::quantity::{Bytes, CounterValue, PageCount};

    use super::super::context::testing;
    use super::super::raw::{RawSwapUsage, RawVmStatistics, RawVmStatisticsRevision1};
    #[cfg(target_os = "macos")]
    use super::{collect_physical_memory, collect_swap_usage, collect_vm_statistics};
    use super::{physical_memory_observation, swap_usage, vm_statistics};

    const PAGE_16K: u64 = 16_384;

    fn raw_vm() -> RawVmStatistics {
        RawVmStatistics {
            free_count: 100,
            active_count: 200,
            inactive_count: 300,
            wire_count: 400,
            speculative_count: 40,
            pageins: 5_000,
            pageouts: 6_000,
            revision_1: Some(RawVmStatisticsRevision1 {
                decompressions: 7_000,
                compressions: 8_000,
                swapins: 9_000,
                swapouts: 10_000,
                compressor_page_count: 50,
                external_page_count: 60,
                internal_page_count: 70,
                total_uncompressed_pages_in_compressor: 150,
            }),
        }
    }

    #[test]
    fn physical_memory_is_bytes_and_a_zero_is_not_a_size() {
        let (context, _clock) = testing::context();
        let sample = testing::sample_at(&context, 10);
        let observation = physical_memory_observation(&context, Ok(51_539_607_552), &sample);
        assert_eq!(observation.metric_id, metric::MEMORY_PHYSICAL_BYTES);
        assert_eq!(observation.unit, Unit::Byte);
        assert_eq!(observation.kind, MetricKind::Gauge);
        assert_eq!(observation.value(), Some(&Bytes::new(51_539_607_552)));
        assert_eq!(observation.source.native_field, "hw.memsize");

        let zero = physical_memory_observation(&context, Ok(0), &sample);
        assert_eq!(zero.reason(), Some(&UnavailableReason::InconsistentData));
        let failed =
            physical_memory_observation(&context, Err(UnavailableReason::Unsupported), &sample);
        assert_eq!(failed.value(), None);
        assert_eq!(failed.reason(), Some(&UnavailableReason::Unsupported));
        assert_eq!(failed.coverage, Coverage::Unknown);
    }

    #[test]
    fn each_vm_gauge_has_its_own_metric_and_the_page_unit() {
        let (context, _clock) = testing::context();
        let sample = testing::sample_at(&context, 10);
        let vm = vm_statistics(&context, Ok(raw_vm()), Ok(PAGE_16K), &sample);

        for (observation, id, field, pages) in [
            (&vm.free, metric::MEMORY_VM_FREE_PAGES, "free_count", 100),
            (
                &vm.active,
                metric::MEMORY_VM_ACTIVE_PAGES,
                "active_count",
                200,
            ),
            (
                &vm.inactive,
                metric::MEMORY_VM_INACTIVE_PAGES,
                "inactive_count",
                300,
            ),
            (&vm.wired, metric::MEMORY_VM_WIRED_PAGES, "wire_count", 400),
            (
                &vm.speculative,
                metric::MEMORY_VM_SPECULATIVE_PAGES,
                "speculative_count",
                40,
            ),
            (
                &vm.internal,
                metric::MEMORY_VM_INTERNAL_PAGES,
                "internal_page_count",
                70,
            ),
            (
                &vm.external,
                metric::MEMORY_VM_EXTERNAL_PAGES,
                "external_page_count",
                60,
            ),
            (
                &vm.compressor_physical,
                metric::MEMORY_COMPRESSOR_PHYSICAL_PAGES,
                "compressor_page_count",
                50,
            ),
            (
                &vm.compressor_uncompressed,
                metric::MEMORY_COMPRESSOR_UNCOMPRESSED_PAGES,
                "total_uncompressed_pages_in_compressor",
                150,
            ),
        ] {
            assert_eq!(observation.metric_id, id);
            assert_eq!(observation.unit, Unit::Page);
            assert_eq!(observation.kind, MetricKind::Gauge);
            assert_eq!(observation.scope.kind, ScopeKind::Host);
            assert_eq!(observation.value(), Some(&PageCount::new(pages)));
            assert_eq!(observation.source.native_field, field);
            assert_eq!(observation.source.adapter_id.as_str(), "macos.mach_host");
            assert_eq!(observation.sample, sample);
            serde_json::to_string(observation).unwrap();
        }
    }

    #[test]
    fn each_vm_counter_has_its_own_metric_and_the_counter_kind() {
        let (context, _clock) = testing::context();
        let sample = testing::sample_at(&context, 10);
        let vm = vm_statistics(&context, Ok(raw_vm()), Ok(PAGE_16K), &sample);
        for (observation, id, field, count) in [
            (
                &vm.pageins,
                metric::MEMORY_VM_PAGEINS_TOTAL,
                "pageins",
                5_000,
            ),
            (
                &vm.pageouts,
                metric::MEMORY_VM_PAGEOUTS_TOTAL,
                "pageouts",
                6_000,
            ),
            (
                &vm.decompressions,
                metric::MEMORY_COMPRESSOR_DECOMPRESSIONS_TOTAL,
                "decompressions",
                7_000,
            ),
            (
                &vm.compressions,
                metric::MEMORY_COMPRESSOR_COMPRESSIONS_TOTAL,
                "compressions",
                8_000,
            ),
            (
                &vm.swapins,
                metric::MEMORY_SWAP_SWAPINS_TOTAL,
                "swapins",
                9_000,
            ),
            (
                &vm.swapouts,
                metric::MEMORY_SWAP_SWAPOUTS_TOTAL,
                "swapouts",
                10_000,
            ),
        ] {
            assert_eq!(observation.metric_id, id);
            assert_eq!(observation.unit, Unit::Page);
            assert_eq!(observation.kind, MetricKind::Counter);
            assert_eq!(observation.value(), Some(&CounterValue::new(count)));
            assert_eq!(observation.source.native_field, field);
            serde_json::to_string(observation).unwrap();
        }
    }

    #[test]
    fn page_ins_are_not_swap_ins_and_the_compressor_metrics_are_distinct() {
        let (context, _clock) = testing::context();
        let sample = testing::sample_at(&context, 10);
        let vm = vm_statistics(&context, Ok(raw_vm()), Ok(PAGE_16K), &sample);
        assert_ne!(vm.pageins.metric_id, vm.swapins.metric_id);
        assert_ne!(vm.pageouts.metric_id, vm.swapouts.metric_id);
        assert_ne!(vm.pageins.value(), vm.swapins.value());
        assert_ne!(
            vm.compressor_physical.metric_id,
            vm.compressor_uncompressed.metric_id
        );
        // 50 physical pages hold the content of 150 logical pages.
        assert_eq!(
            vm.page_bytes(&vm.compressor_physical),
            Reading::Available(Bytes::new(50 * PAGE_16K))
        );
        assert_eq!(
            vm.page_bytes(&vm.compressor_uncompressed),
            Reading::Available(Bytes::new(150 * PAGE_16K))
        );
    }

    #[test]
    fn the_byte_conversion_uses_the_page_size_of_the_sample() {
        let (context, _clock) = testing::context();
        let sample = testing::sample_at(&context, 10);
        let small = vm_statistics(&context, Ok(raw_vm()), Ok(4_096), &sample);
        let large = vm_statistics(&context, Ok(raw_vm()), Ok(PAGE_16K), &sample);
        assert_eq!(
            small.page_bytes(&small.free),
            Reading::Available(Bytes::new(409_600))
        );
        assert_eq!(
            large.page_bytes(&large.free),
            Reading::Available(Bytes::new(1_638_400))
        );
    }

    #[test]
    fn a_count_of_another_sample_is_not_converted() {
        let (context, _clock) = testing::context();
        let first = vm_statistics(
            &context,
            Ok(raw_vm()),
            Ok(4_096),
            &testing::sample_at(&context, 10),
        );
        let second = vm_statistics(
            &context,
            Ok(raw_vm()),
            Ok(PAGE_16K),
            &testing::sample_at(&context, 5_000_000),
        );
        assert_eq!(
            first.page_bytes(&second.free),
            Reading::Unavailable(UnavailableReason::InconsistentData)
        );
    }

    #[test]
    fn a_byte_conversion_that_overflows_is_unavailable() {
        let (context, _clock) = testing::context();
        let sample = testing::sample_at(&context, 10);
        let mut raw = raw_vm();
        if let Some(revision_1) = raw.revision_1.as_mut() {
            revision_1.total_uncompressed_pages_in_compressor = u64::MAX / 2;
        }
        let vm = vm_statistics(&context, Ok(raw), Ok(PAGE_16K), &sample);
        // The page count itself is a valid measurement.
        assert_eq!(
            vm.compressor_uncompressed.value(),
            Some(&PageCount::new(u64::MAX / 2))
        );
        assert_eq!(
            vm.page_bytes(&vm.compressor_uncompressed),
            Reading::Unavailable(UnavailableReason::Overflow)
        );
    }

    #[test]
    fn a_missing_page_size_keeps_the_page_counts_and_blocks_the_bytes() {
        let (context, _clock) = testing::context();
        let sample = testing::sample_at(&context, 10);
        for page_size in [Err(UnavailableReason::TransientFailure), Ok(0)] {
            let vm = vm_statistics(&context, Ok(raw_vm()), page_size, &sample);
            assert!(!vm.page_size.is_available());
            assert_eq!(vm.free.value(), Some(&PageCount::new(100)));
            assert!(!vm.page_bytes(&vm.free).is_available());
        }
    }

    #[test]
    fn a_failed_query_makes_each_field_unavailable_and_not_zero() {
        let (context, _clock) = testing::context();
        let sample = testing::sample_at(&context, 10);
        let vm = vm_statistics(
            &context,
            Err(UnavailableReason::TransientFailure),
            Ok(PAGE_16K),
            &sample,
        );
        for observation in [&vm.free, &vm.wired, &vm.internal, &vm.compressor_physical] {
            assert_eq!(observation.value(), None);
            assert_eq!(
                observation.reason(),
                Some(&UnavailableReason::TransientFailure)
            );
        }
        for observation in [&vm.pageins, &vm.swapins, &vm.swapouts, &vm.compressions] {
            assert_eq!(observation.value(), None);
            assert_eq!(
                observation.reason(),
                Some(&UnavailableReason::TransientFailure)
            );
        }
        assert_eq!(
            vm.page_bytes(&vm.free),
            Reading::Unavailable(UnavailableReason::TransientFailure)
        );
    }

    #[test]
    fn revision_0_keeps_the_base_fields_and_marks_the_others_unsupported() {
        let (context, _clock) = testing::context();
        let sample = testing::sample_at(&context, 10);
        let mut raw = raw_vm();
        raw.revision_1 = None;
        let vm = vm_statistics(&context, Ok(raw), Ok(PAGE_16K), &sample);
        assert_eq!(vm.free.value(), Some(&PageCount::new(100)));
        assert_eq!(vm.pageins.value(), Some(&CounterValue::new(5_000)));
        for observation in [&vm.internal, &vm.external, &vm.compressor_physical] {
            assert_eq!(observation.reason(), Some(&UnavailableReason::Unsupported));
        }
        for observation in [&vm.swapins, &vm.swapouts, &vm.decompressions] {
            assert_eq!(observation.reason(), Some(&UnavailableReason::Unsupported));
        }
    }

    #[test]
    fn swap_space_has_three_distinct_gauges() {
        let (context, _clock) = testing::context();
        let sample = testing::sample_at(&context, 10);
        let raw = RawSwapUsage {
            total: 3_000,
            available: 1_000,
            used: 2_000,
        };
        let swap = swap_usage(&context, Ok(raw), &sample);
        assert_eq!(
            swap.allocated.metric_id,
            metric::MEMORY_SWAP_ALLOCATED_BYTES
        );
        assert_eq!(swap.used.metric_id, metric::MEMORY_SWAP_USED_BYTES);
        assert_eq!(
            swap.available.metric_id,
            metric::MEMORY_SWAP_AVAILABLE_BYTES
        );
        assert_eq!(swap.allocated.value(), Some(&Bytes::new(3_000)));
        assert_eq!(swap.used.value(), Some(&Bytes::new(2_000)));
        assert_eq!(swap.available.value(), Some(&Bytes::new(1_000)));
        assert_eq!(swap.used.source.native_field, "xsu_used");
        assert_eq!(swap.used.unit, Unit::Byte);
        serde_json::to_string(&swap.used).unwrap();

        // No swap file is a measured zero.
        let none = swap_usage(
            &context,
            Ok(RawSwapUsage {
                total: 0,
                available: 0,
                used: 0,
            }),
            &sample,
        );
        assert_eq!(none.used.value(), Some(&Bytes::ZERO));
    }

    #[test]
    fn swap_values_that_are_not_consistent_or_not_read_are_unavailable() {
        let (context, _clock) = testing::context();
        let sample = testing::sample_at(&context, 10);
        let swap = swap_usage(
            &context,
            Ok(RawSwapUsage {
                total: 100,
                available: 50,
                used: 101,
            }),
            &sample,
        );
        assert_eq!(swap.allocated.value(), Some(&Bytes::new(100)));
        assert_eq!(swap.available.value(), Some(&Bytes::new(50)));
        assert_eq!(
            swap.used.reason(),
            Some(&UnavailableReason::InconsistentData)
        );

        let failed = swap_usage(&context, Err(UnavailableReason::PermissionDenied), &sample);
        for observation in [&failed.allocated, &failed.used, &failed.available] {
            assert_eq!(observation.value(), None);
            assert_eq!(
                observation.reason(),
                Some(&UnavailableReason::PermissionDenied)
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_host_queries_keep_their_invariants() {
        let context = super::CollectionContext::for_current_process().unwrap();

        let physical = collect_physical_memory(&context).unwrap();
        let physical_bytes: Bytes = *physical.value().unwrap();
        assert!(physical_bytes > Bytes::ZERO);

        let vm = collect_vm_statistics(&context).unwrap();
        let page_size: Bytes = *vm.page_size.value().unwrap();
        assert!(page_size.get().is_power_of_two());
        assert!(page_size.get() >= 4_096);
        // The speculative pages are a part of the free pages.
        assert!(vm.speculative.value().unwrap() <= vm.free.value().unwrap());
        // No resident category is larger than the physical memory.
        for observation in [&vm.free, &vm.active, &vm.inactive, &vm.wired] {
            let bytes: Bytes = *vm.page_bytes(observation).value().unwrap();
            assert!(bytes <= physical_bytes);
        }
        let compressor: Bytes = *vm.page_bytes(&vm.compressor_physical).value().unwrap();
        assert!(compressor <= physical_bytes);
        assert!(vm.swapins.is_available());
        assert!(vm.swapouts.is_available());
        assert!(vm.pageins.is_available());
        assert!(vm.sample.acquisition_duration().is_some());

        let swap = collect_swap_usage(&context).unwrap();
        let allocated: Bytes = *swap.allocated.value().unwrap();
        assert!(*swap.used.value().unwrap() <= allocated);
        assert!(*swap.available.value().unwrap() <= allocated);

        // Each acquisition has its own sample.
        assert_ne!(physical.sample.sample_id, vm.sample.sample_id);
        assert_ne!(vm.sample.sample_id, swap.used.sample.sample_id);
    }
}
