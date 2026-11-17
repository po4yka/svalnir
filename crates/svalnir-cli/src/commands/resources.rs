//! `status`, `memory status`, and `swap status`.
//!
//! Each command reads the host one time in this process and writes a
//! snapshot. The data collection ([`collect`]) is separate from the views
//! and the text rendering, which take values and read nothing.

use serde::Serialize;
use svalnir_agent::platform::memory::{
    self, MemorySnapshot, PageRate, RateLimits, RateUnavailable, SwapActivity, SwapUsage,
    VmStatistics,
};
use svalnir_agent::platform::volume::{self, FoundationCapacity, VolumeCapacity};
use svalnir_core::id::SampleId;
use svalnir_core::observation::{Observation, UnavailableReason};
use svalnir_core::quantity::{Bytes, CounterValue, Nanoseconds, PageCount};
use svalnir_core::state::PressureState;
use svalnir_core::volume::VolumeIdentity;

use super::{CommandFailure, Invocation};
use crate::host::{Host, ReadingView, ScopeCoverage};
use crate::output::{ErrorBody, ExitStatus, Kind};
use crate::text::{escape, field, human_bytes, observed, observed_bytes, put_line};

/// The longest interval between two samples that gives a swap rate.
pub(crate) const MAX_RATE_INTERVAL: Nanoseconds =
    Nanoseconds::new(3_600_000_000_000 + 60_000_000_000);

/// The statement of each snapshot about the agent.
const AGENT_NOTE: &str = "This build has no background agent. The command measured the host in its own process, one time.";

/// The statement of each snapshot about the policies.
const POLICY_NOTE: &str = "No policy is active in this build. No automatic cleanup and no automatic application control can occur.";

/// The statement about the growth signals of `memory status`.
const GROWTH_NOTE: &str =
    "A growth signal needs retained samples from the background agent. One snapshot has none.";

/// The disk part of a snapshot, as the collectors gave it.
#[derive(Debug, Clone)]
#[expect(
    clippy::large_enum_variant,
    reason = "a snapshot has one disk reading, and a box adds an allocation to each one"
)]
pub(crate) enum DiskReading {
    /// The startup data volume and its capacity.
    Measured {
        identity: VolumeIdentity,
        capacity: VolumeCapacity,
        foundation: FoundationCapacity,
    },
    /// The startup data volume has an identity, and the `statfs` capacity
    /// collection failed. The reading has no capacity.
    CapacityUnavailable {
        identity: VolumeIdentity,
        reason: String,
    },
    /// The startup data volume has no identity, so nothing was measured.
    Unresolved(String),
}

/// One reading of the host.
#[derive(Debug, Clone)]
pub(crate) struct HostReading {
    pub(crate) disk: DiskReading,
    pub(crate) memory: MemorySnapshot,
}

/// Reads the disk capacity of the startup data volume.
///
/// A failed collection does not end the command. The `statfs` capacity is
/// required: when it fails, the reading says so and the scope coverage is
/// partial. The Foundation values are optional planning values: when they
/// fail, their observations are unavailable and the coverage is unchanged.
pub(crate) fn collect_disk(host: &Host) -> DiskReading {
    let mounted = match Host::startup_data_volume() {
        Ok(mounted) => mounted,
        Err(error) => return DiskReading::Unresolved(error.to_string()),
    };
    let capacity: VolumeCapacity = match volume::collect_capacity(host.context(), &mounted.identity)
    {
        Ok(capacity) => capacity,
        Err(error) => {
            return DiskReading::CapacityUnavailable {
                identity: mounted.identity,
                reason: error.to_string(),
            };
        }
    };
    let foundation: FoundationCapacity =
        match volume::collect_foundation_capacity(host.context(), &mounted.identity) {
            Ok(foundation) => foundation,
            Err(_) => volume::foundation_capacity_observations(
                host.context(),
                &mounted.identity,
                Err(UnavailableReason::TransientFailure),
                &capacity.total.sample,
            ),
        };
    DiskReading::Measured {
        identity: mounted.identity,
        capacity,
        foundation,
    }
}

/// Reads the disk capacity and the memory state of the host.
///
/// A disk collection failure keeps the memory reading. Only a memory
/// collection failure is an error.
pub(crate) fn collect(host: &Host) -> Result<HostReading, ErrorBody> {
    let disk: DiskReading = collect_disk(host);
    let memory: MemorySnapshot = memory::collect_memory_snapshot(host.context())?;
    Ok(HostReading { disk, memory })
}

/// The disk capacity of the startup data volume.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct DiskView {
    /// The logical selector of the volume.
    selector: &'static str,
    /// The identity of the volume. `null` when the volume was not resolved.
    volume: Option<VolumeIdentity>,
    /// The reason there is no volume identity.
    unresolved_reason: Option<String>,
    total: Option<Observation<Bytes>>,
    free: Option<Observation<Bytes>>,
    available: Option<Observation<Bytes>>,
    important_available: Option<Observation<Bytes>>,
    opportunistic_available: Option<Observation<Bytes>>,
}

impl DiskView {
    pub(crate) fn new(reading: &DiskReading, coverage: &mut ScopeCoverage) -> Self {
        match reading {
            DiskReading::Measured {
                identity,
                capacity,
                foundation,
            } => {
                coverage.require(&capacity.total);
                coverage.require(&capacity.available);
                Self {
                    selector: "startup-data",
                    volume: Some(identity.clone()),
                    unresolved_reason: None,
                    total: Some(capacity.total.clone()),
                    free: Some(capacity.free.clone()),
                    available: Some(capacity.available.clone()),
                    important_available: Some(foundation.important.clone()),
                    opportunistic_available: Some(foundation.opportunistic.clone()),
                }
            }
            DiskReading::CapacityUnavailable { identity, reason } => {
                coverage.missing("disk.available_bytes");
                Self {
                    selector: "startup-data",
                    volume: Some(identity.clone()),
                    unresolved_reason: Some(reason.clone()),
                    total: None,
                    free: None,
                    available: None,
                    important_available: None,
                    opportunistic_available: None,
                }
            }
            DiskReading::Unresolved(reason) => {
                coverage.missing("disk.available_bytes");
                Self {
                    selector: "startup-data",
                    volume: None,
                    unresolved_reason: Some(reason.clone()),
                    total: None,
                    free: None,
                    available: None,
                    important_available: None,
                    opportunistic_available: None,
                }
            }
        }
    }

    fn render(&self, out: &mut String) {
        if let (Some(volume), Some(reason)) = (&self.volume, &self.unresolved_reason) {
            put_line!(
                out,
                "Disk (startup data volume, {})",
                volume.mount_point.display_label()
            );
            field(
                out,
                "Capacity",
                13,
                &format!("unavailable ({})", escape(reason)),
            );
            return;
        }
        let Some(volume) = &self.volume else {
            let reason: &str = self.unresolved_reason.as_deref().unwrap_or("unknown");
            put_line!(out, "Disk (startup data volume)");
            field(
                out,
                "Volume",
                13,
                &format!("not resolved ({})", escape(reason)),
            );
            return;
        };
        put_line!(
            out,
            "Disk (startup data volume, {})",
            volume.mount_point.display_label()
        );
        let rows: [(&str, &Option<Observation<Bytes>>); 5] = [
            ("Total", &self.total),
            ("Free", &self.free),
            ("Available", &self.available),
            ("Important", &self.important_available),
            ("Opportunistic", &self.opportunistic_available),
        ];
        for (label, observation) in rows {
            if let Some(observation) = observation {
                field(out, label, 13, &observed_bytes(observation));
            }
        }
        out.push_str(
            "  `Available` is the baseline policy input. `Important` and `Opportunistic` are planning values of the system.\n",
        );
    }
}

/// The page counts of the memory composition.
#[derive(Debug, Clone, Serialize)]
struct PagesView {
    free: Observation<PageCount>,
    active: Observation<PageCount>,
    inactive: Observation<PageCount>,
    wired: Observation<PageCount>,
    speculative: Observation<PageCount>,
    internal: Observation<PageCount>,
    external: Observation<PageCount>,
    compressor_physical: Observation<PageCount>,
    compressor_uncompressed: Observation<PageCount>,
}

/// The cumulative paging counters.
#[derive(Debug, Clone, Serialize)]
#[expect(
    clippy::struct_field_names,
    reason = "each field has the name of its counter metric"
)]
struct PagingCountersView {
    pageins_total: Observation<CounterValue>,
    pageouts_total: Observation<CounterValue>,
    compressions_total: Observation<CounterValue>,
    decompressions_total: Observation<CounterValue>,
}

/// A signal that this build cannot give.
#[derive(Debug, Clone, Serialize)]
struct UnavailableSignal {
    availability: &'static str,
    reason: &'static str,
    note: &'static str,
}

/// Memory pressure and composition.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct MemoryView {
    pressure: Observation<PressureState>,
    physical: Observation<Bytes>,
    page_size: ReadingView<Bytes>,
    pages: PagesView,
    counters: PagingCountersView,
    growth: UnavailableSignal,
}

impl MemoryView {
    pub(crate) fn new(snapshot: &MemorySnapshot, coverage: &mut ScopeCoverage) -> Self {
        let vm: &VmStatistics = &snapshot.vm;
        coverage.require(&snapshot.pressure);
        coverage.require(&snapshot.physical);
        for pages in [
            &vm.free,
            &vm.active,
            &vm.inactive,
            &vm.wired,
            &vm.compressor_physical,
        ] {
            coverage.require(pages);
        }
        if !vm.page_size.is_available() {
            coverage.missing("memory.vm.page_size");
        }
        Self {
            pressure: snapshot.pressure.clone(),
            physical: snapshot.physical.clone(),
            page_size: ReadingView::of(&vm.page_size),
            pages: PagesView {
                free: vm.free.clone(),
                active: vm.active.clone(),
                inactive: vm.inactive.clone(),
                wired: vm.wired.clone(),
                speculative: vm.speculative.clone(),
                internal: vm.internal.clone(),
                external: vm.external.clone(),
                compressor_physical: vm.compressor_physical.clone(),
                compressor_uncompressed: vm.compressor_uncompressed.clone(),
            },
            counters: PagingCountersView {
                pageins_total: vm.pageins.clone(),
                pageouts_total: vm.pageouts.clone(),
                compressions_total: vm.compressions.clone(),
                decompressions_total: vm.decompressions.clone(),
            },
            growth: UnavailableSignal {
                availability: "unavailable",
                reason: "not_collected",
                note: GROWTH_NOTE,
            },
        }
    }

    /// The text of a page count: the bytes when the page size is known.
    fn pages_text(&self, pages: &Observation<PageCount>) -> String {
        observed(pages, |count| {
            let bytes: Option<Bytes> = self
                .page_size
                .value
                .and_then(|page_size| count.to_bytes(page_size));
            match bytes {
                Some(bytes) => format!("{} ({count} pages)", human_bytes(bytes.get())),
                None => format!("{count} pages"),
            }
        })
    }

    pub(crate) fn pressure_text(&self) -> String {
        observed(&self.pressure, |state| escape(state.as_str()))
    }

    fn render(&self, out: &mut String, detailed: bool) {
        out.push_str("Memory\n");
        field(out, "Pressure", 13, &self.pressure_text());
        field(out, "Physical", 13, &observed_bytes(&self.physical));
        let pages: &PagesView = &self.pages;
        let mut rows: Vec<(&str, &Observation<PageCount>)> = vec![
            ("Free", &pages.free),
            ("Active", &pages.active),
            ("Inactive", &pages.inactive),
            ("Wired", &pages.wired),
            ("Compressor", &pages.compressor_physical),
        ];
        if detailed {
            rows.extend([
                ("Compressed", &pages.compressor_uncompressed),
                ("Speculative", &pages.speculative),
                ("Anonymous", &pages.internal),
                ("File-backed", &pages.external),
            ]);
        }
        for (label, observation) in rows {
            field(out, label, 13, &self.pages_text(observation));
        }
        if detailed {
            out.push_str(
                "  `Compressed` is the logical content in the compressor. `Speculative` is a part of `Free`. `Anonymous` and `File-backed` are not disjoint from the other rows.\n",
            );
            let counters: &PagingCountersView = &self.counters;
            for (label, counter) in [
                ("Page-ins", &counters.pageins_total),
                ("Page-outs", &counters.pageouts_total),
                ("Compressions", &counters.compressions_total),
                ("Decompress.", &counters.decompressions_total),
            ] {
                field(
                    out,
                    label,
                    13,
                    &observed(counter, |count| format!("{count} since boot")),
                );
            }
            field(
                out,
                "Growth",
                13,
                &format!("unavailable (not_collected). {GROWTH_NOTE}"),
            );
        }
    }
}

/// One swap rate, or the reason there is none.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct RateView {
    /// Pages for each second. An approximate value.
    pages_per_second: Option<f64>,
    unit: &'static str,
    availability: &'static str,
    reason: Option<String>,
    /// The exact increase of the counter in the interval, in pages.
    increase_pages: Option<String>,
    interval_ns: Option<Nanoseconds>,
    earlier_sample: Option<SampleId>,
    later_sample: Option<SampleId>,
}

impl RateView {
    fn new(rate: &Result<PageRate, RateUnavailable>) -> Self {
        let unavailable = |reason: &str| Self {
            pages_per_second: None,
            unit: "pages_per_second",
            availability: "unavailable",
            reason: Some(reason.to_owned()),
            increase_pages: None,
            interval_ns: None,
            earlier_sample: None,
            later_sample: None,
        };
        match rate {
            Ok(rate) => {
                let per_second: f64 = rate.pages_per_second();
                if !per_second.is_finite() {
                    return unavailable("inconsistent_data");
                }
                Self {
                    pages_per_second: Some(per_second),
                    unit: "pages_per_second",
                    availability: "available",
                    reason: None,
                    increase_pages: Some(rate.rate.increase.to_string()),
                    interval_ns: Some(rate.rate.interval),
                    earlier_sample: Some(rate.rate.earlier_sample.clone()),
                    later_sample: Some(rate.rate.later_sample.clone()),
                }
            }
            Err(error) => unavailable(error.reason().as_str()),
        }
    }

    pub(crate) fn text(&self) -> String {
        match (self.pages_per_second, &self.reason) {
            (Some(rate), _) => format!("{rate:.1} pages/s"),
            (None, Some(reason)) => format!("unavailable ({})", escape(reason)),
            (None, None) => "unavailable".to_owned(),
        }
    }
}

/// The swap rates between two samples.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct SwapActivityView {
    pub(crate) swapins: RateView,
    pub(crate) swapouts: RateView,
}

impl SwapActivityView {
    pub(crate) fn new(activity: &SwapActivity) -> Self {
        Self {
            swapins: RateView::new(&activity.swapins),
            swapouts: RateView::new(&activity.swapouts),
        }
    }
}

/// Global swap usage and activity.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct SwapView {
    allocated: Observation<Bytes>,
    used: Observation<Bytes>,
    available: Observation<Bytes>,
    swapins_total: Observation<CounterValue>,
    swapouts_total: Observation<CounterValue>,
    /// The rates. One snapshot has one sample, so the rates have no value.
    activity: SwapActivityView,
}

impl SwapView {
    /// `earlier` is the previous sample of the same collection context, when
    /// there is one.
    pub(crate) fn new(
        snapshot: &MemorySnapshot,
        earlier: Option<&VmStatistics>,
        coverage: &mut ScopeCoverage,
    ) -> Self {
        let swap: &SwapUsage = &snapshot.swap;
        coverage.require(&swap.allocated);
        coverage.require(&swap.used);
        let activity: SwapActivity = memory::swap_activity(
            earlier,
            &snapshot.vm,
            RateLimits::with_max_interval(MAX_RATE_INTERVAL),
        );
        Self {
            allocated: swap.allocated.clone(),
            used: swap.used.clone(),
            available: swap.available.clone(),
            swapins_total: snapshot.vm.swapins.clone(),
            swapouts_total: snapshot.vm.swapouts.clone(),
            activity: SwapActivityView::new(&activity),
        }
    }

    pub(crate) fn used_text(&self) -> String {
        observed_bytes(&self.used)
    }

    pub(crate) fn activity(&self) -> &SwapActivityView {
        &self.activity
    }

    fn render(&self, out: &mut String, detailed: bool) {
        out.push_str("Swap\n");
        field(out, "Used", 13, &observed_bytes(&self.used));
        field(out, "Allocated", 13, &observed_bytes(&self.allocated));
        field(out, "Available", 13, &observed_bytes(&self.available));
        if detailed {
            for (label, counter, rate) in [
                ("Swap-ins", &self.swapins_total, &self.activity.swapins),
                ("Swap-outs", &self.swapouts_total, &self.activity.swapouts),
            ] {
                field(
                    out,
                    label,
                    13,
                    &format!(
                        "{}; rate {}",
                        observed(counter, |count| format!("{count} pages since boot")),
                        rate.text()
                    ),
                );
            }
            out.push_str(
                "  A rate needs two samples. One snapshot has one sample; `svalnir monitor` shows the rates.\n  Swap usage alone is not a reason to stop an application.\n",
            );
        }
    }
}

/// The state of the agent and of the policies in this build.
#[derive(Debug, Clone, Serialize)]
struct ServiceView {
    state: &'static str,
    note: &'static str,
}

/// The result of `status`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct StatusView {
    disk: DiskView,
    memory: MemoryView,
    swap: SwapView,
    agent: ServiceView,
    policies: ServiceView,
    coverage: ScopeCoverage,
}

impl StatusView {
    pub(crate) fn new(reading: &HostReading) -> Self {
        let mut coverage = ScopeCoverage::new();
        Self {
            disk: DiskView::new(&reading.disk, &mut coverage),
            memory: MemoryView::new(&reading.memory, &mut coverage),
            swap: SwapView::new(&reading.memory, None, &mut coverage),
            agent: ServiceView {
                state: "not_running",
                note: AGENT_NOTE,
            },
            policies: ServiceView {
                state: "none_active",
                note: POLICY_NOTE,
            },
            coverage,
        }
    }

    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        self.disk.render(&mut out);
        out.push('\n');
        self.memory.render(&mut out, false);
        out.push('\n');
        self.swap.render(&mut out, false);
        out.push('\n');
        put_line!(out, "Agent: not running. {AGENT_NOTE}");
        put_line!(out, "Policies: none active. {POLICY_NOTE}");
        out.push_str(&self.coverage.text_line());
        out
    }
}

/// The result of `memory status`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct MemoryStatusView {
    memory: MemoryView,
    coverage: ScopeCoverage,
}

impl MemoryStatusView {
    pub(crate) fn new(snapshot: &MemorySnapshot) -> Self {
        let mut coverage = ScopeCoverage::new();
        Self {
            memory: MemoryView::new(snapshot, &mut coverage),
            coverage,
        }
    }

    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        self.memory.render(&mut out, true);
        out.push_str(&self.coverage.text_line());
        out
    }
}

/// The result of `swap status`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct SwapStatusView {
    swap: SwapView,
    coverage: ScopeCoverage,
}

impl SwapStatusView {
    pub(crate) fn new(snapshot: &MemorySnapshot) -> Self {
        let mut coverage = ScopeCoverage::new();
        Self {
            swap: SwapView::new(snapshot, None, &mut coverage),
            coverage,
        }
    }

    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        self.swap.render(&mut out, true);
        out.push_str(&self.coverage.text_line());
        out
    }
}

/// The exit status of a snapshot: 4 when the required scope is partial.
pub(crate) fn snapshot_status(coverage: &ScopeCoverage) -> ExitStatus {
    if coverage.is_partial() {
        ExitStatus::Partial
    } else {
        ExitStatus::Success
    }
}

pub(crate) fn status(invocation: &mut Invocation<'_>) -> Result<ExitStatus, CommandFailure> {
    let host: Host = Host::open()?;
    let view = StatusView::new(&collect(&host)?);
    invocation.emit(Kind::Snapshot, &view, StatusView::render)?;
    Ok(snapshot_status(&view.coverage))
}

pub(crate) fn memory_status(invocation: &mut Invocation<'_>) -> Result<ExitStatus, CommandFailure> {
    let host: Host = Host::open()?;
    let snapshot: MemorySnapshot =
        memory::collect_memory_snapshot(host.context()).map_err(ErrorBody::from)?;
    let view = MemoryStatusView::new(&snapshot);
    invocation.emit(Kind::Snapshot, &view, MemoryStatusView::render)?;
    Ok(snapshot_status(&view.coverage))
}

pub(crate) fn swap_status(invocation: &mut Invocation<'_>) -> Result<ExitStatus, CommandFailure> {
    let host: Host = Host::open()?;
    let snapshot: MemorySnapshot =
        memory::collect_memory_snapshot(host.context()).map_err(ErrorBody::from)?;
    let view = SwapStatusView::new(&snapshot);
    invocation.emit(Kind::Snapshot, &view, SwapStatusView::render)?;
    Ok(snapshot_status(&view.coverage))
}

#[cfg(test)]
mod tests {
    use svalnir_core::observation::{Reading, UnavailableReason};

    use super::{DiskReading, HostReading, MemoryStatusView, StatusView, SwapStatusView};
    use crate::output::ExitStatus;
    use crate::test_support::{memory_snapshot, volume_capacity};

    fn reading() -> HostReading {
        let (identity, capacity, foundation) = volume_capacity();
        HostReading {
            disk: DiskReading::Measured {
                identity,
                capacity,
                foundation,
            },
            memory: memory_snapshot(),
        }
    }

    #[test]
    fn status_text_shows_each_part_and_the_absent_agent() {
        let view = StatusView::new(&reading());
        let text = view.render();
        assert!(text.contains("Disk (startup data volume, /System/Volumes/Data)"));
        assert!(text.contains("Available      100.0 GiB"), "{text}");
        assert!(text.contains("Pressure       normal"), "{text}");
        assert!(text.contains("Physical       16.0 GiB"), "{text}");
        assert!(
            text.contains("Free           1.0 GiB (65536 pages)"),
            "{text}"
        );
        assert!(text.contains("Used           2.0 GiB"), "{text}");
        assert!(text.contains("Agent: not running."));
        assert!(text.contains("Policies: none active."));
        assert!(text.ends_with("Required scope: complete\n"));
        assert_eq!(super::snapshot_status(&view.coverage), ExitStatus::Success);
    }

    #[test]
    fn status_json_has_canonical_observations() {
        let view = StatusView::new(&reading());
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(
            json["disk"]["available"]["metric_id"],
            "disk.available_bytes"
        );
        assert_eq!(json["disk"]["available"]["value"], "107374182400");
        assert_eq!(json["disk"]["available"]["unit"], "byte");
        assert_eq!(json["disk"]["available"]["availability"], "available");
        assert_eq!(
            json["disk"]["volume"]["mount_point"]["value"],
            "/System/Volumes/Data"
        );
        assert_eq!(json["memory"]["pressure"]["value"], "normal");
        assert_eq!(json["memory"]["page_size"]["value"], "16384");
        assert_eq!(
            json["swap"]["activity"]["swapins"]["availability"],
            "unavailable"
        );
        assert_eq!(
            json["swap"]["activity"]["swapins"]["reason"],
            "not_initialized"
        );
        assert_eq!(
            json["swap"]["activity"]["swapins"]["pages_per_second"],
            serde_json::Value::Null
        );
        assert_eq!(json["agent"]["state"], "not_running");
        assert_eq!(json["policies"]["state"], "none_active");
        assert_eq!(json["coverage"]["required_scope"], "complete");
    }

    #[test]
    fn an_unavailable_required_metric_makes_the_scope_partial() {
        let mut reading = reading();
        reading.memory.pressure.reading = Reading::Unavailable(UnavailableReason::PermissionDenied);
        let view = StatusView::new(&reading);
        let text = view.render();
        assert!(
            text.contains("Pressure       unavailable (permission_denied)"),
            "{text}"
        );
        assert!(text.contains("Required scope: partial (no value for memory.pressure)"));
        assert_eq!(super::snapshot_status(&view.coverage), ExitStatus::Partial);
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["memory"]["pressure"]["value"], serde_json::Value::Null);
        assert_eq!(json["memory"]["pressure"]["reason"], "permission_denied");
        assert_eq!(json["coverage"]["missing_required"][0], "memory.pressure");
    }

    #[test]
    fn a_failed_capacity_collection_keeps_memory_and_gives_a_partial_scope() {
        let mut reading = reading();
        if let DiskReading::Measured { identity, .. } = reading.disk.clone() {
            reading.disk = DiskReading::CapacityUnavailable {
                identity,
                reason: "the clock failed".to_owned(),
            };
        }
        let view = StatusView::new(&reading);
        let text = view.render();
        assert!(
            text.contains("Capacity       unavailable (the clock failed)"),
            "{text}"
        );
        assert!(text.contains("Pressure       normal"), "{text}");
        assert!(text.contains("no value for disk.available_bytes"), "{text}");
        assert_eq!(super::snapshot_status(&view.coverage), ExitStatus::Partial);
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["memory"]["pressure"]["value"], "normal");
        assert_eq!(json["disk"]["available"], serde_json::Value::Null);
    }

    #[test]
    fn an_unavailable_optional_metric_keeps_the_scope_complete() {
        let mut reading = reading();
        if let DiskReading::Measured { foundation, .. } = &mut reading.disk {
            foundation.important.reading = Reading::Unavailable(UnavailableReason::Unsupported);
        }
        reading.memory.vm.speculative.reading =
            Reading::Unavailable(UnavailableReason::Unsupported);
        let view = StatusView::new(&reading);
        assert!(
            view.render()
                .contains("Important      unavailable (unsupported)")
        );
        assert_eq!(super::snapshot_status(&view.coverage), ExitStatus::Success);
    }

    #[test]
    fn an_unresolved_volume_is_partial_and_is_not_zero() {
        let mut reading = reading();
        reading.disk = DiskReading::Unresolved("the volume query is unavailable".to_owned());
        let view = StatusView::new(&reading);
        let text = view.render();
        assert!(text.contains("Volume         not resolved (the volume query is unavailable)"));
        assert!(!text.contains("0 B"));
        assert_eq!(super::snapshot_status(&view.coverage), ExitStatus::Partial);
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["disk"]["available"], serde_json::Value::Null);
    }

    #[test]
    fn memory_status_shows_the_composition_and_the_counters() {
        let view = MemoryStatusView::new(&memory_snapshot());
        let text = view.render();
        assert!(text.contains("Compressed     "), "{text}");
        assert!(text.contains("Page-ins       1000 since boot"), "{text}");
        assert!(
            text.contains("Growth         unavailable (not_collected)"),
            "{text}"
        );
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["memory"]["pages"]["wired"]["unit"], "page");
        assert_eq!(json["memory"]["growth"]["availability"], "unavailable");
    }

    #[test]
    fn swap_status_shows_usage_and_says_why_there_is_no_rate() {
        let view = SwapStatusView::new(&memory_snapshot());
        let text = view.render();
        assert!(text.contains("Allocated      4.0 GiB"), "{text}");
        assert!(
            text.contains(
                "Swap-ins       500 pages since boot; rate unavailable (not_initialized)"
            ),
            "{text}"
        );
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["swap"]["used"]["value"], "2147483648");
        assert_eq!(json["swap"]["swapouts_total"]["kind"], "counter");
    }
}
