//! Tests of the Darwin context queries on the host that runs the tests.
//!
//! Each test inspects only a child process that it starts in a temporary
//! directory and that it kills and reaps. The child inherits a TCP listener
//! on an ephemeral loopback port from the test, so no external tool opens a
//! socket. No test inspects an unrelated application.

use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use svalnir_core::observation::{Coverage, UnavailableReason};
use svalnir_core::process::{Pid, ProcessIdentity};

use super::native::{SocketFdInfoBytes, parse_listening_socket};
use super::{
    AddressFamily, ContextLimits, ListeningPort, ListeningPorts, ProcessCollector, ProcessContext,
    ProcessSnapshot, SocketFamily,
};

/// Sets or clears `FD_CLOEXEC` on a descriptor that the test owns.
fn set_close_on_exec(listener: &TcpListener, close: bool) {
    let descriptor = listener.as_raw_fd();
    // SAFETY: `descriptor` is open for the life of `listener`. `F_GETFD`
    // reads the descriptor flags and changes nothing.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    assert!(flags >= 0);
    let flags = if close {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    // SAFETY: as above; `F_SETFD` changes only the flags of this descriptor.
    let status = unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags) };
    assert_eq!(status, 0);
}

/// A `/bin/sleep` child in a temporary directory that holds a copy of a
/// loopback listener. The guard kills and reaps it.
struct ListeningChild {
    child: Child,
    directory: tempfile::TempDir,
    port: u16,
}

impl ListeningChild {
    fn spawn() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port: u16 = listener.local_addr().unwrap().port();
        // The child inherits the descriptor through `exec`. Another test
        // that spawns a child at the same time can inherit it too, which
        // only keeps the socket open longer.
        set_close_on_exec(&listener, false);
        let child = Command::new("/bin/sleep")
            .arg("60")
            .current_dir(directory.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        set_close_on_exec(&listener, true);
        // The child holds its own copy; the test closes its copy.
        drop(listener);
        Self {
            child,
            directory,
            port,
        }
    }

    fn pid(&self) -> Pid {
        Pid::new(i32::try_from(self.child.id()).unwrap()).unwrap()
    }

    fn kill_and_reap(&mut self) {
        // The child is a process that this test started. An error means
        // that it exited already.
        let killed = self.child.kill();
        let reaped = self.child.wait();
        drop((killed, reaped));
    }
}

impl Drop for ListeningChild {
    fn drop(&mut self) {
        self.kill_and_reap();
    }
}

fn identity_of(
    collector: &ProcessCollector<super::DarwinProcessSource>,
    pid: Pid,
) -> ProcessIdentity {
    // The child is in the snapshot as soon as `spawn` returns, because
    // `posix_spawn` returns after the new image is loaded.
    let snapshot: ProcessSnapshot = collector.collect().unwrap();
    snapshot.find_pid(pid).unwrap().identity.clone()
}

fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap()
}

#[test]
fn a_child_in_a_temporary_directory_has_that_directory_and_its_loopback_port() {
    let child = ListeningChild::spawn();
    let collector = ProcessCollector::for_this_host().unwrap();
    let identity: ProcessIdentity = identity_of(&collector, child.pid());

    let context: ProcessContext = collector
        .collect_context(&identity, ContextLimits::default())
        .unwrap();

    let directory = context.working_directory.value().unwrap();
    // The temporary directory can be under a symbolic link (`/var` to
    // `/private/var`); the kernel reports the resolved path.
    assert_eq!(
        canonical(&directory.to_path_buf()),
        canonical(child.directory.path())
    );
    let ports: &ListeningPorts = context.listening_ports.value().unwrap();
    assert!(!ports.truncated);
    assert_eq!(context.listening_ports.coverage, Coverage::Complete);
    assert!(
        ports.ports.contains(&ListeningPort {
            family: AddressFamily::Ipv4,
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: child.port,
            wildcard: false,
        }),
        "{ports:?}"
    );
}

#[test]
fn a_child_that_exited_is_unavailable() {
    let mut child = ListeningChild::spawn();
    let collector = ProcessCollector::for_this_host().unwrap();
    let identity: ProcessIdentity = identity_of(&collector, child.pid());
    child.kill_and_reap();

    let context: ProcessContext = collector
        .collect_context(&identity, ContextLimits::default())
        .unwrap();
    // The PID was not reused at once, so the reason is that the process is
    // gone. A reuse in the same interval gives `identity_changed`.
    for reason in [
        context.working_directory.reason(),
        context.listening_ports.reason(),
    ] {
        assert!(
            matches!(
                reason,
                Some(UnavailableReason::ResourceGone | UnavailableReason::IdentityChanged)
            ),
            "{reason:?}"
        );
    }
    assert!(context.listening_ports.value().is_none());
}

#[test]
fn the_descriptor_ceiling_truncates_the_ports_of_a_child() {
    let child = ListeningChild::spawn();
    let collector = ProcessCollector::for_this_host().unwrap();
    let identity: ProcessIdentity = identity_of(&collector, child.pid());
    // The child has at least four descriptors: the three standard streams
    // and the listener.
    let limits = ContextLimits {
        max_descriptors: 1,
        max_ports: 64,
    };
    let context: ProcessContext = collector.collect_context(&identity, limits).unwrap();
    assert!(context.listening_ports.value().unwrap().truncated);
    assert_eq!(context.listening_ports.coverage, Coverage::Partial);
}

/// A `socket_fdinfo` buffer with the fields that the parser reads.
fn socket_bytes(
    kind: i32,
    family: i32,
    state: i32,
    flags: u8,
    address: [u8; 16],
) -> SocketFdInfoBytes {
    let mut bytes = SocketFdInfoBytes([0; 792]);
    bytes.0[256..260].copy_from_slice(&kind.to_ne_bytes());
    bytes.0[184..188].copy_from_slice(&family.to_ne_bytes());
    bytes.0[344..348].copy_from_slice(&state.to_ne_bytes());
    let port: i32 = i32::from(5000_u16.to_be());
    bytes.0[268..272].copy_from_slice(&port.to_ne_bytes());
    bytes.0[288] = flags;
    bytes.0[312..328].copy_from_slice(&address);
    // A remote address that the parser must not read.
    bytes.0[264..268].copy_from_slice(&i32::from(9_u16.to_be()).to_ne_bytes());
    bytes
}

#[test]
fn the_parser_keeps_a_listening_tcp_socket_and_rejects_the_others() {
    let mut v6 = [0_u8; 16];
    v6[15] = 1;
    let listening = socket_bytes(2, libc::AF_INET6, 1, 0x2, v6);
    let parsed = parse_listening_socket(&listening).unwrap().unwrap();
    assert_eq!(parsed.family, SocketFamily::Ipv6);
    assert_eq!(parsed.address, IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));
    assert_eq!(parsed.port, 5000);

    let mut v4 = [0_u8; 16];
    v4[12..16].copy_from_slice(&[127, 0, 0, 1]);
    let mapped = socket_bytes(2, libc::AF_INET6, 1, 0x1, v4);
    let parsed = parse_listening_socket(&mapped).unwrap().unwrap();
    assert_eq!(parsed.family, SocketFamily::Ipv6);
    assert_eq!(
        parsed.address,
        IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped())
    );

    // An established socket, a UDP socket (kind `SOCKINFO_IN`), and a Unix
    // domain socket are not listening TCP sockets.
    let established = socket_bytes(2, libc::AF_INET, 4, 0x1, v4);
    assert_eq!(parse_listening_socket(&established).unwrap(), None);
    let udp = socket_bytes(1, libc::AF_INET, 0, 0x1, v4);
    assert_eq!(parse_listening_socket(&udp).unwrap(), None);
    let unix = socket_bytes(3, libc::AF_UNIX, 0, 0, [0; 16]);
    assert_eq!(parse_listening_socket(&unix).unwrap(), None);
}
