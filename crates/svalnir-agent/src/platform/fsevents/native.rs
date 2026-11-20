//! The `FSEvents` stream of macOS.
//!
//! Ownership and lifetime:
//!
//! - [`Stream`] owns one reference of an `FSEventStreamRef` from
//!   `FSEventStreamCreate`. Its `Drop` stops the stream (when it started),
//!   invalidates it, waits until the dispatch queue ran each block that it
//!   had, and releases the reference. After the drop, no callback runs.
//! - The context of the stream holds one strong count of the
//!   [`Arc`] of the inbox: `FSEventStreamCreate` calls the retain callback,
//!   and the last release of the stream calls the release callback. The
//!   inbox therefore lives at least as long as the stream, whatever the
//!   sequence of the drops is.
//! - The callback runs on the private serial queue of the stream, one call
//!   at a time. It reads only the arrays that `FSEvents` passes for the
//!   time of the call, copies each path, and appends to the inbox. It
//!   catches each panic, so no unwind crosses the frames of `FSEvents`.

use std::ffi::{CStr, c_char, c_void};
use std::os::unix::ffi::OsStrExt as _;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::sync::Arc;

use dispatch2::{DispatchQueue, DispatchRetained};
use objc2_core_foundation::{CFArray, CFRetained, CFString};
use objc2_core_services::{
    ConstFSEventStreamRef, FSEventStreamContext, FSEventStreamCreate, FSEventStreamEventFlags,
    FSEventStreamEventId, FSEventStreamInvalidate, FSEventStreamRef, FSEventStreamRelease,
    FSEventStreamSetDispatchQueue, FSEventStreamStart, FSEventStreamStop,
    kFSEventStreamCreateFlagWatchRoot,
};

use super::{EventBatch, EventInbox, EventStream, RawEvent, STREAM_LATENCY_SECONDS, WatchError};

/// `kFSEventStreamEventIdSinceNow` of `FSEvents.h`: a stream with this
/// start gives only the events after its start. The bindings have no
/// constant for it.
const EVENT_ID_SINCE_NOW: FSEventStreamEventId = 0xFFFF_FFFF_FFFF_FFFF;

/// The label of the dispatch queue of the stream.
const QUEUE_LABEL: &str = "dev.po4yka.svalnir.catalog-watch";

/// One running stream.
struct Stream {
    /// Not null.
    raw: FSEventStreamRef,
    queue: DispatchRetained<DispatchQueue>,
    started: bool,
}

// SAFETY: The owner uses the stream reference only through `&mut self` of
// `NativeEventStream`, so one thread at a time calls `FSEventStreamStart`,
// `FSEventStreamStop`, `FSEventStreamInvalidate`, and
// `FSEventStreamRelease`. The callback does not use the reference. The
// dispatch queue reference is thread-safe.
unsafe impl Send for Stream {}

impl Stream {
    fn as_ptr(&self) -> FSEventStreamRef {
        self.raw
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        if self.started {
            // SAFETY: `raw` is a valid stream that this value owns, and it
            // started.
            unsafe { FSEventStreamStop(self.as_ptr()) };
        }
        // SAFETY: `raw` is a valid stream, scheduled on `queue`, as
        // `FSEventStreamInvalidate` requires.
        unsafe { FSEventStreamInvalidate(self.as_ptr()) };
        // The queue is serial: after this empty block, no callback of the
        // stream runs or is queued.
        self.queue.exec_sync(|| {});
        // SAFETY: This value owns one reference of `raw`, and nothing uses
        // the reference after this call.
        unsafe { FSEventStreamRelease(self.as_ptr()) };
    }
}

/// The `FSEvents` stream of the candidate source.
#[derive(Debug)]
pub(super) struct NativeEventStream {
    inbox: Arc<EventInbox>,
    stream: Option<Stream>,
}

impl std::fmt::Debug for Stream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Stream")
            .field("started", &self.started)
            .finish_non_exhaustive()
    }
}

impl NativeEventStream {
    pub(super) fn new() -> Self {
        Self {
            inbox: Arc::new(EventInbox::default()),
            stream: None,
        }
    }
}

/// The retain callback of the context: one more strong count of the inbox.
unsafe extern "C-unwind" fn retain_inbox(info: *const c_void) -> *const c_void {
    // SAFETY: `info` is the pointer of `Arc::as_ptr` of an inbox whose
    // owner holds a strong count during `FSEventStreamCreate`, or of a
    // later retain of the stream.
    unsafe { Arc::increment_strong_count(info.cast::<EventInbox>()) };
    info
}

/// The release callback of the context: one strong count less.
unsafe extern "C-unwind" fn release_inbox(info: *const c_void) {
    // SAFETY: Each release follows one retain of `retain_inbox` of the same
    // pointer.
    unsafe { Arc::decrement_strong_count(info.cast::<EventInbox>()) };
}

/// The path of one event: a C string, copied.
fn event_path(path: *const c_char) -> Option<PathBuf> {
    if path.is_null() {
        return None;
    }
    // SAFETY: FSEvents gives a NUL-terminated path for each event of a
    // stream with no `kFSEventStreamCreateFlagUseCFTypes`, valid for the
    // time of the callback. The path is copied before the return.
    let bytes: &[u8] = unsafe { CStr::from_ptr(path) }.to_bytes();
    Some(Path::new(std::ffi::OsStr::from_bytes(bytes)).to_path_buf())
}

/// The callback of the stream.
unsafe extern "C-unwind" fn on_events(
    _stream: ConstFSEventStreamRef,
    info: *mut c_void,
    count: usize,
    paths: NonNull<c_void>,
    event_flags: NonNull<FSEventStreamEventFlags>,
    event_ids: NonNull<FSEventStreamEventId>,
) {
    // SAFETY: `info` is the inbox pointer of the context, and the stream
    // holds a strong count of it for its lifetime (module documentation).
    let inbox: &EventInbox = unsafe { &*info.cast_const().cast::<EventInbox>() };
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: With no `kFSEventStreamCreateFlagUseCFTypes`, `paths` is
        // an array of `count` C string pointers, valid for the call.
        let paths: &[*const c_char] =
            unsafe { std::slice::from_raw_parts(paths.cast::<*const c_char>().as_ptr(), count) };
        // SAFETY: FSEvents gives `count` flags, valid for the call.
        let flags: &[FSEventStreamEventFlags] =
            unsafe { std::slice::from_raw_parts(event_flags.as_ptr(), count) };
        // SAFETY: FSEvents gives `count` identifiers, valid for the call.
        let ids: &[FSEventStreamEventId] =
            unsafe { std::slice::from_raw_parts(event_ids.as_ptr(), count) };
        inbox.push(paths.iter().zip(flags).zip(ids).map(|((path, flags), id)| {
            event_path(*path).map(|path| RawEvent {
                path,
                flags: *flags,
                id: *id,
            })
        }));
    }));
    if outcome.is_err() {
        inbox.mark_lost();
    }
}

impl EventStream for NativeEventStream {
    fn start(&mut self, roots: &[PathBuf]) -> Result<(), WatchError> {
        self.stop();
        drop(self.inbox.take());
        let strings: Vec<CFRetained<CFString>> = roots
            .iter()
            .map(|root| root.to_str().map(CFString::from_str))
            .collect::<Option<_>>()
            .ok_or(WatchError::PathNotUnicode)?;
        let paths: CFRetained<CFArray<CFString>> = CFArray::from_retained_objects(&strings);
        let mut context = FSEventStreamContext {
            version: 0,
            info: Arc::as_ptr(&self.inbox).cast_mut().cast::<c_void>(),
            retain: Some(retain_inbox),
            release: Some(release_inbox),
            copyDescription: None,
        };
        // SAFETY: The callback has the signature of
        // `FSEventStreamCallback` and reads the arrays as a stream with no
        // `kFSEventStreamCreateFlagUseCFTypes` gives them. The context is
        // valid for the call, and FSEvents copies it and retains `info`.
        // The array holds `CFString` paths, as the function requires.
        let raw: FSEventStreamRef = unsafe {
            FSEventStreamCreate(
                None,
                Some(on_events),
                &raw mut context,
                (*paths).as_ref(),
                EVENT_ID_SINCE_NOW,
                STREAM_LATENCY_SECONDS,
                kFSEventStreamCreateFlagWatchRoot,
            )
        };
        if raw.is_null() {
            return Err(WatchError::Refused("FSEventStreamCreate"));
        }
        let queue: DispatchRetained<DispatchQueue> = DispatchQueue::new(QUEUE_LABEL, None);
        // SAFETY: `raw` is a valid stream that is not scheduled.
        unsafe { FSEventStreamSetDispatchQueue(raw, Some(&queue)) };
        // From here the drop of `stream` invalidates and releases it.
        let mut stream = Stream {
            raw,
            queue,
            started: false,
        };
        // SAFETY: `raw` is a valid stream, scheduled on a queue.
        if !unsafe { FSEventStreamStart(stream.as_ptr()) } {
            return Err(WatchError::Refused("FSEventStreamStart"));
        }
        stream.started = true;
        self.stream = Some(stream);
        Ok(())
    }

    fn stop(&mut self) {
        drop(self.stream.take());
    }

    fn drain(&mut self) -> EventBatch {
        self.inbox.take()
    }
}

impl Drop for NativeEventStream {
    fn drop(&mut self) {
        self.stop();
    }
}
