//! The context of one process for a person: its working directory and its
//! listening TCP ports.
//!
//! Owning specification: `docs/RESOURCE_MODEL.md` section 11.
//!
//! The values are evidence for a person before a stop. They are not policy
//! inputs, and they do not establish membership in an application group, so
//! no policy, grouping, or controller code reads them. The collector reads
//! them only on request, for one process generation: the inventory, `processes
//! top`, and the periodic sampling of the agent do not read them. Nothing
//! writes them to the agent log or to the store.
//!
//! # Identity
//!
//! The collector reads the identity evidence of the PID before and after the
//! two queries. When the evidence is not that of the requested generation at
//! both reads, each value is unavailable with `identity_changed` (or
//! `resource_gone` for a process that exited), so a reused PID never gives
//! the data of another process.
//!
//! # Bounds
//!
//! The collector examines at most [`ContextLimits::max_descriptors`] file
//! descriptors and reports at most [`ContextLimits::max_ports`] ports. When a
//! ceiling is reached, the port set is marked `truncated` and the observation
//! has the coverage `partial`.

use std::collections::BTreeSet;
use std::net::IpAddr;

use serde::Serialize;
use svalnir_core::file::LosslessPath;
use svalnir_core::id::{ProcessGenerationId, SampleId};
use svalnir_core::observation::{
    Coverage, MetricId, MetricKind, Observation, ObservationValue, Reading, Sample, Scope, Source,
    UnavailableReason, Unit,
};
use svalnir_core::process::ProcessIdentity;
use svalnir_core::time::{MonotonicNanos, WallTime};

use super::inventory::{ADAPTER_REVISION, CollectError, ProcessCollector};
use super::source::{
    ProcessSource, QueryFailure, RawListeningSocket, RawListeningSockets, RawProcessInfo,
    SocketFamily,
};

/// The metric name of the working directory of a process.
pub const WORKING_DIRECTORY_METRIC: &str = "process.working_directory";

/// The metric name of the listening TCP ports of a process.
pub const LISTENING_TCP_PORTS_METRIC: &str = "process.listening_tcp_ports";

/// The default ceiling on the file descriptors examined for one process.
pub const DEFAULT_MAX_DESCRIPTORS: usize = 4096;

/// The default ceiling on the ports reported for one process.
pub const DEFAULT_MAX_PORTS: usize = 64;

const WORKING_DIRECTORY_API: &str = "proc_pidinfo(PROC_PIDVNODEPATHINFO)";
const WORKING_DIRECTORY_FIELD: &str = "pvi_cdir.vip_path";
const LISTENING_PORTS_API: &str =
    "proc_pidinfo(PROC_PIDLISTFDS) + proc_pidfdinfo(PROC_PIDFDSOCKETINFO)";
const LISTENING_PORTS_FIELD: &str =
    "soi_proto.pri_tcp: tcpsi_state == TSI_S_LISTEN, tcpsi_ini.insi_lport, tcpsi_ini.insi_laddr";

/// The ceilings of one context collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextLimits {
    /// The largest number of file descriptors examined. At least 1.
    pub max_descriptors: usize,
    /// The largest number of ports reported. At least 1.
    pub max_ports: usize,
}

impl Default for ContextLimits {
    fn default() -> Self {
        Self {
            max_descriptors: DEFAULT_MAX_DESCRIPTORS,
            max_ports: DEFAULT_MAX_PORTS,
        }
    }
}

/// The address family of a listening port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressFamily {
    /// IPv4.
    Ipv4,
    /// IPv6. The socket can also accept IPv4 connections unless it has
    /// `IPV6_V6ONLY`; the adapter does not read that option.
    Ipv6,
}

impl AddressFamily {
    /// The serialized spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}

/// One listening TCP port of a process: the local endpoint only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct ListeningPort {
    /// The address family of the socket.
    pub family: AddressFamily,
    /// The bind address.
    pub address: IpAddr,
    /// The port.
    pub port: u16,
    /// The bind address is the unspecified address (`0.0.0.0` or `::`): the
    /// socket accepts connections on each address of its family.
    pub wildcard: bool,
}

impl From<RawListeningSocket> for ListeningPort {
    fn from(socket: RawListeningSocket) -> Self {
        Self {
            family: match socket.family {
                SocketFamily::Ipv4 => AddressFamily::Ipv4,
                SocketFamily::Ipv6 => AddressFamily::Ipv6,
            },
            address: socket.address,
            port: socket.port,
            wildcard: socket.address.is_unspecified(),
        }
    }
}

/// The listening TCP ports of one process, as a sorted set with no
/// duplicates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListeningPorts {
    /// The ports, sorted by family, address, and port.
    pub ports: Vec<ListeningPort>,
    /// A ceiling was reached: the process has more descriptors than the
    /// collector examined, or more ports than it reports.
    pub truncated: bool,
}

impl ListeningPorts {
    /// The set of `raw`, with the ceiling of `max_ports`.
    pub fn from_raw(raw: &RawListeningSockets, max_ports: usize) -> Self {
        let set: BTreeSet<ListeningPort> = raw
            .sockets
            .iter()
            .copied()
            .map(ListeningPort::from)
            .collect();
        let truncated: bool = raw.descriptors_truncated || set.len() > max_ports;
        Self {
            ports: set.into_iter().take(max_ports).collect(),
            truncated,
        }
    }
}

impl ObservationValue for ListeningPorts {
    fn accepts_unit(unit: &Unit) -> bool {
        matches!(unit, Unit::Endpoint)
    }
}

/// The context of one process generation. Both values share one sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessContext {
    /// [`WORKING_DIRECTORY_METRIC`]: the current working directory. A path
    /// of the user: it follows the privacy rules for paths in logs and
    /// exports.
    pub working_directory: Observation<LosslessPath>,
    /// [`LISTENING_TCP_PORTS_METRIC`]: the listening TCP ports.
    pub listening_ports: Observation<ListeningPorts>,
}

impl<S: ProcessSource> ProcessCollector<S> {
    /// Collects the context of one process generation.
    ///
    /// The call reads data only. A failed query gives an unavailable value
    /// with its reason, never an empty one. A process of another user gives
    /// `permission_denied` with no query of its data.
    ///
    /// # Errors
    ///
    /// Returns a [`CollectError`] when a clock gives no value or a fixed
    /// identity is not valid, so no sample can be recorded.
    pub fn collect_context(
        &self,
        identity: &ProcessIdentity,
        limits: ContextLimits,
    ) -> Result<ProcessContext, CollectError> {
        let source: &S = self.source();
        let started: MonotonicNanos = source.monotonic_now().map_err(CollectError::Clock)?;
        let readings: Readings = if identity.uid != source.effective_uid() {
            Readings::both(UnavailableReason::PermissionDenied)
        } else if limits.max_descriptors == 0 || limits.max_ports == 0 {
            Readings::both(UnavailableReason::NotCollected)
        } else {
            read_generation(source, identity, limits)
        };
        let finished: MonotonicNanos = source.monotonic_now().map_err(CollectError::Clock)?;
        let captured_at: WallTime = source.wall_now().map_err(CollectError::Clock)?;
        let sample: Sample = Sample {
            sample_id: SampleId::new(format!("pc-{}-{}", started.get(), identity.pid.get()))?,
            clock_domain: self.clock_domain().clone(),
            boot_id: self.context().boot_id.clone(),
            collector_epoch: self.context().collector_epoch.clone(),
            started_monotonic_ns: started,
            finished_monotonic_ns: finished.max(started),
            captured_at,
        };
        let generation_id: &ProcessGenerationId = &identity.generation_id;
        let coverage: Coverage = match &readings.ports {
            Reading::Available(ports) if ports.truncated => Coverage::Partial,
            _ => Coverage::Complete,
        };
        Ok(ProcessContext {
            working_directory: Observation {
                metric_id: MetricId::new(WORKING_DIRECTORY_METRIC)?,
                scope: Scope::process(generation_id.clone()),
                reading: readings.directory,
                unit: Unit::Path,
                kind: MetricKind::Gauge,
                coverage: Coverage::Complete,
                source: self.context_source(WORKING_DIRECTORY_API, WORKING_DIRECTORY_FIELD),
                sample: sample.clone(),
            },
            listening_ports: Observation {
                metric_id: MetricId::new(LISTENING_TCP_PORTS_METRIC)?,
                scope: Scope::process(generation_id.clone()),
                reading: readings.ports,
                unit: Unit::Endpoint,
                kind: MetricKind::Gauge,
                coverage,
                source: self.context_source(LISTENING_PORTS_API, LISTENING_PORTS_FIELD),
                sample,
            },
        })
    }

    fn context_source(&self, api: &str, field: &str) -> Source {
        Source {
            adapter_id: self.adapter_id().clone(),
            adapter_revision: ADAPTER_REVISION.to_owned(),
            native_api: api.to_owned(),
            native_field: field.to_owned(),
            worker_id: self.context().worker_id.clone(),
        }
    }
}

/// The two readings of one collection.
struct Readings {
    directory: Reading<LosslessPath>,
    ports: Reading<ListeningPorts>,
}

impl Readings {
    fn both(reason: UnavailableReason) -> Self {
        Self {
            directory: Reading::Unavailable(reason.clone()),
            ports: Reading::Unavailable(reason),
        }
    }
}

/// The reason the evidence of the PID is not that of `identity`, or `None`
/// when it is.
fn generation_mismatch(
    identity: &ProcessIdentity,
    info: Result<RawProcessInfo, QueryFailure>,
) -> Option<UnavailableReason> {
    match info {
        Ok(info) if info.zombie => Some(UnavailableReason::ResourceGone),
        Ok(info)
            if info.pid == identity.pid
                && info.start_time == identity.start_time
                && info.effective_uid == identity.uid =>
        {
            None
        }
        Ok(_) => Some(UnavailableReason::IdentityChanged),
        Err(QueryFailure::Gone) => Some(UnavailableReason::ResourceGone),
        Err(failure) => Some(failure.reason()),
    }
}

fn read_generation<S: ProcessSource>(
    source: &S,
    identity: &ProcessIdentity,
    limits: ContextLimits,
) -> Readings {
    if let Some(reason) = generation_mismatch(identity, source.process_info(identity.pid)) {
        return Readings::both(reason);
    }
    let directory: Result<LosslessPath, QueryFailure> = source.working_directory(identity.pid);
    let sockets: Result<RawListeningSockets, QueryFailure> =
        source.listening_tcp_sockets(identity.pid, limits.max_descriptors);
    // The PID can name another process after the queries. Then the values
    // can be of that process, so neither is reported.
    if let Some(reason) = generation_mismatch(identity, source.process_info(identity.pid)) {
        return Readings::both(reason);
    }
    Readings {
        directory: match directory {
            Ok(path) => Reading::Available(path),
            Err(failure) => Reading::Unavailable(failure.reason()),
        },
        ports: match sockets {
            Ok(raw) => Reading::Available(ListeningPorts::from_raw(&raw, limits.max_ports)),
            Err(failure) => Reading::Unavailable(failure.reason()),
        },
    }
}
