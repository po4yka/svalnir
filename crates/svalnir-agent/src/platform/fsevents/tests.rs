use std::path::PathBuf;

use super::{EventInbox, EventStream as _, MAX_PENDING_EVENTS, RawEvent, UnsupportedStream};

fn event(index: usize) -> RawEvent {
    RawEvent {
        path: PathBuf::from(format!("/root/{index}")),
        flags: 0,
        id: u64::try_from(index).unwrap(),
    }
}

#[test]
fn the_inbox_keeps_the_bound_and_records_the_loss() {
    let inbox = EventInbox::default();
    inbox.push((0..MAX_PENDING_EVENTS).map(|index| Some(event(index))));
    let full = inbox.take();
    assert_eq!(full.events.len(), MAX_PENDING_EVENTS);
    assert!(!full.lost);
    // One event more than the bound: the batch keeps the bound and
    // records the loss.
    inbox.push((0..=MAX_PENDING_EVENTS).map(|index| Some(event(index))));
    let over = inbox.take();
    assert_eq!(over.events.len(), MAX_PENDING_EVENTS);
    assert!(over.lost);
    // An event with no readable path is a loss.
    inbox.push([None]);
    assert!(inbox.take().lost);
    // A take leaves an empty batch.
    assert_eq!(inbox.take(), super::EventBatch::default());
}

#[test]
fn an_unsupported_stream_does_not_start() {
    let mut stream = UnsupportedStream;
    assert_eq!(
        stream.start(&[PathBuf::from("/root")]),
        Err(super::WatchError::Unsupported)
    );
    assert_eq!(stream.drain(), super::EventBatch::default());
}

#[cfg(target_os = "macos")]
#[test]
fn the_flags_are_those_of_the_sdk() {
    use objc2_core_services as sdk;

    use super::flags;

    assert_eq!(
        flags::MUST_SCAN_SUBDIRS,
        sdk::kFSEventStreamEventFlagMustScanSubDirs
    );
    assert_eq!(flags::USER_DROPPED, sdk::kFSEventStreamEventFlagUserDropped);
    assert_eq!(
        flags::KERNEL_DROPPED,
        sdk::kFSEventStreamEventFlagKernelDropped
    );
    assert_eq!(
        flags::EVENT_IDS_WRAPPED,
        sdk::kFSEventStreamEventFlagEventIdsWrapped
    );
    assert_eq!(flags::HISTORY_DONE, sdk::kFSEventStreamEventFlagHistoryDone);
    assert_eq!(flags::ROOT_CHANGED, sdk::kFSEventStreamEventFlagRootChanged);
    assert_eq!(flags::MOUNT, sdk::kFSEventStreamEventFlagMount);
    assert_eq!(flags::UNMOUNT, sdk::kFSEventStreamEventFlagUnmount);
}

/// The one test of the native stream: it watches a temporary directory,
/// makes a directory in it, and waits for an event below the root. It
/// watches no other directory.
#[cfg(target_os = "macos")]
#[test]
fn the_native_stream_gives_an_event_below_a_temporary_root() {
    use std::time::{Duration, Instant};

    let directory = tempfile::tempdir().unwrap();
    // FSEvents gives the real path: `/var` is a symbolic link.
    let root: PathBuf = std::fs::canonicalize(directory.path()).unwrap();
    let mut stream = super::system_stream();
    stream.start(std::slice::from_ref(&root)).unwrap();
    std::fs::create_dir(root.join("changed")).unwrap();
    let deadline: Instant = Instant::now() + Duration::from_secs(20);
    let mut seen: bool = false;
    while !seen && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        let batch = stream.drain();
        assert!(!batch.lost);
        seen = batch
            .events
            .iter()
            .any(|event| event.path.starts_with(&root));
    }
    stream.stop();
    assert!(seen, "no event below the temporary root in 20 s");
    // Events that arrived before the stop stay in the inbox until a drain.
    drop(stream.drain());
    // After the stop, no callback runs: a change gives no event.
    std::fs::create_dir(root.join("after-stop")).unwrap();
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(stream.drain().events, Vec::new());
}
