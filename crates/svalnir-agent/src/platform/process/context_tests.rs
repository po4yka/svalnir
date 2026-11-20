//! Tests of the context collection of one process with synthetic data. No
//! test reads a live process.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use svalnir_core::file::LosslessPath;
use svalnir_core::observation::{Coverage, Reading, UnavailableReason, Unit};
use svalnir_core::process::{ProcessIdentity, Uid};

use super::fake::{FakeSource, info, pid, usage};
use super::{
    AddressFamily, ContextLimits, LISTENING_TCP_PORTS_METRIC, ListeningPort, ListeningPorts,
    ProcessContext, ProcessSnapshot, QueryFailure, RawListeningSocket, RawListeningSockets,
    SocketFamily, WORKING_DIRECTORY_METRIC,
};

const PROCESS: i32 = 300;

fn socket(family: SocketFamily, address: IpAddr, port: u16) -> RawListeningSocket {
    RawListeningSocket {
        family,
        address,
        port,
    }
}

fn loopback(port: u16) -> RawListeningSocket {
    socket(SocketFamily::Ipv4, IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

fn sockets(list: Vec<RawListeningSocket>, descriptors_truncated: bool) -> RawListeningSockets {
    RawListeningSockets {
        sockets: list,
        descriptors_truncated,
    }
}

/// A source with one process that has a working directory and two sockets.
fn source() -> FakeSource {
    let mut source = FakeSource::new().with_process(info(PROCESS, 50), "/bin/server", usage(1, 1));
    source.directories.insert(
        pid(PROCESS),
        Ok(LosslessPath::from_bytes("/Users/u/project").unwrap()),
    );
    source.sockets.insert(
        pid(PROCESS),
        Ok(sockets(vec![loopback(8080), loopback(3000)], false)),
    );
    source
}

/// The identity of the process of [`source`], from a snapshot.
fn identity() -> ProcessIdentity {
    let snapshot: ProcessSnapshot = FakeSource::new()
        .with_process(info(PROCESS, 50), "/bin/server", usage(1, 1))
        .collector()
        .collect()
        .unwrap();
    snapshot.find_pid(pid(PROCESS)).unwrap().identity.clone()
}

fn collect(source: FakeSource, identity: &ProcessIdentity) -> ProcessContext {
    source
        .collector()
        .collect_context(identity, ContextLimits::default())
        .unwrap()
}

#[test]
fn the_context_of_a_generation_has_its_directory_and_its_sorted_ports() {
    let source: FakeSource = source();
    let identity: ProcessIdentity = identity();
    let context: ProcessContext = collect(source, &identity);

    let directory = &context.working_directory;
    assert_eq!(directory.metric_id.as_str(), WORKING_DIRECTORY_METRIC);
    assert_eq!(directory.unit, Unit::Path);
    assert_eq!(directory.coverage, Coverage::Complete);
    assert_eq!(
        directory.value().unwrap().as_bytes(),
        b"/Users/u/project".as_slice()
    );
    assert_eq!(
        directory.source.native_api,
        "proc_pidinfo(PROC_PIDVNODEPATHINFO)"
    );
    assert_eq!(
        directory.scope.identity_id.as_str(),
        identity.generation_id.as_str()
    );

    let ports = &context.listening_ports;
    assert_eq!(ports.metric_id.as_str(), LISTENING_TCP_PORTS_METRIC);
    assert_eq!(ports.unit, Unit::Endpoint);
    assert_eq!(ports.coverage, Coverage::Complete);
    let value: &ListeningPorts = ports.value().unwrap();
    assert!(!value.truncated);
    let numbers: Vec<u16> = value.ports.iter().map(|port| port.port).collect();
    assert_eq!(numbers, vec![3000, 8080]);
    // The two values share one sample.
    assert_eq!(directory.sample, ports.sample);
}

#[test]
fn a_pid_that_names_another_generation_after_the_reads_gives_identity_changed() {
    let mut source: FakeSource = source();
    let identity: ProcessIdentity = identity();
    // The first reading is of the requested generation; the second is of a
    // process that reused the PID.
    source = source.with_info_sequence(
        pid(PROCESS),
        vec![Ok(info(PROCESS, 50)), Ok(info(PROCESS, 51))],
    );
    let context: ProcessContext = collect(source, &identity);
    assert_eq!(
        context.working_directory.reason(),
        Some(&UnavailableReason::IdentityChanged)
    );
    assert_eq!(
        context.listening_ports.reason(),
        Some(&UnavailableReason::IdentityChanged)
    );
}

#[test]
fn a_pid_of_another_generation_before_the_reads_gives_identity_changed_and_no_query() {
    let mut source: FakeSource = source();
    let identity: ProcessIdentity = identity();
    source = source.with_info_sequence(pid(PROCESS), vec![Ok(info(PROCESS, 99))]);
    let collector = source.collector();
    let context: ProcessContext = collector
        .collect_context(&identity, ContextLimits::default())
        .unwrap();
    assert_eq!(
        context.listening_ports.reason(),
        Some(&UnavailableReason::IdentityChanged)
    );
    assert!(collector.source().socket_ceilings.borrow().is_empty());
}

#[test]
fn a_process_that_exited_gives_resource_gone() {
    let mut source: FakeSource = source();
    let identity: ProcessIdentity = identity();
    source = source.with_info_sequence(pid(PROCESS), vec![Err(QueryFailure::Gone)]);
    let context: ProcessContext = collect(source, &identity);
    assert_eq!(
        context.working_directory.reason(),
        Some(&UnavailableReason::ResourceGone)
    );
    assert_eq!(
        context.listening_ports.reason(),
        Some(&UnavailableReason::ResourceGone)
    );
}

#[test]
fn a_process_of_another_user_gives_permission_denied_with_no_query() {
    let source: FakeSource = source();
    let mut identity: ProcessIdentity = identity();
    identity.uid = Uid::new(0);
    let collector = source.collector();
    let context: ProcessContext = collector
        .collect_context(&identity, ContextLimits::default())
        .unwrap();
    assert_eq!(
        context.working_directory.reason(),
        Some(&UnavailableReason::PermissionDenied)
    );
    assert_eq!(
        context.listening_ports.reason(),
        Some(&UnavailableReason::PermissionDenied)
    );
    assert!(collector.source().socket_ceilings.borrow().is_empty());
}

#[test]
fn a_failed_query_is_unavailable_and_not_empty() {
    let mut source: FakeSource = source();
    let identity: ProcessIdentity = identity();
    source
        .directories
        .insert(pid(PROCESS), Err(QueryFailure::PermissionDenied));
    source
        .sockets
        .insert(pid(PROCESS), Err(QueryFailure::Failed(5)));
    let context: ProcessContext = collect(source, &identity);
    assert_eq!(
        context.working_directory.reason(),
        Some(&UnavailableReason::PermissionDenied)
    );
    assert_eq!(
        context.listening_ports.reason(),
        Some(&UnavailableReason::TransientFailure)
    );
    assert!(context.listening_ports.value().is_none());
}

#[test]
fn the_descriptor_ceiling_reaches_the_source_and_its_truncation_is_partial() {
    let mut source: FakeSource = source();
    let identity: ProcessIdentity = identity();
    source
        .sockets
        .insert(pid(PROCESS), Ok(sockets(vec![loopback(1)], true)));
    let collector = source.collector();
    let limits = ContextLimits {
        max_descriptors: 7,
        max_ports: 64,
    };
    let context: ProcessContext = collector.collect_context(&identity, limits).unwrap();
    assert_eq!(*collector.source().socket_ceilings.borrow(), vec![7]);
    assert_eq!(context.listening_ports.coverage, Coverage::Partial);
    assert!(context.listening_ports.value().unwrap().truncated);
}

#[test]
fn the_port_ceiling_keeps_the_first_ports_of_the_order_and_marks_truncation() {
    let raw = sockets((1..=5).rev().map(loopback).collect(), false);
    let ports: ListeningPorts = ListeningPorts::from_raw(&raw, 3);
    assert!(ports.truncated);
    let numbers: Vec<u16> = ports.ports.iter().map(|port| port.port).collect();
    assert_eq!(numbers, vec![1, 2, 3]);

    let exact: ListeningPorts = ListeningPorts::from_raw(&raw, 5);
    assert!(!exact.truncated);
    assert_eq!(exact.ports.len(), 5);
}

#[test]
fn two_descriptors_of_one_socket_give_one_port_and_a_wildcard_is_marked() {
    let any_v6 = socket(SocketFamily::Ipv6, IpAddr::V6(Ipv6Addr::UNSPECIFIED), 443);
    let raw = sockets(vec![loopback(22), any_v6, loopback(22)], false);
    let ports: ListeningPorts = ListeningPorts::from_raw(&raw, 64);
    assert_eq!(
        ports.ports,
        vec![
            ListeningPort {
                family: AddressFamily::Ipv4,
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 22,
                wildcard: false,
            },
            ListeningPort {
                family: AddressFamily::Ipv6,
                address: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                port: 443,
                wildcard: true,
            },
        ]
    );
}

#[test]
fn a_zero_ceiling_collects_nothing() {
    let source: FakeSource = source();
    let identity: ProcessIdentity = identity();
    let collector = source.collector();
    let limits = ContextLimits {
        max_descriptors: 0,
        max_ports: 1,
    };
    let context: ProcessContext = collector.collect_context(&identity, limits).unwrap();
    assert_eq!(
        context.listening_ports.reason(),
        Some(&UnavailableReason::NotCollected)
    );
    assert!(matches!(
        context.working_directory.reading,
        Reading::Unavailable(UnavailableReason::NotCollected)
    ));
}

#[test]
fn the_port_set_serializes_with_the_family_the_address_and_the_wildcard_mark() {
    let raw = sockets(
        vec![socket(
            SocketFamily::Ipv4,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            8080,
        )],
        false,
    );
    let json = serde_json::to_value(ListeningPorts::from_raw(&raw, 64)).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "ports": [{"family": "ipv4", "address": "0.0.0.0", "port": 8080, "wildcard": true}],
            "truncated": false
        })
    );
}
