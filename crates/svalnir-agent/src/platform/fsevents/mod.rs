//! The `FSEvents` adapter: one event stream on the approved roots of the
//! candidate source.
//!
//! Owning specification: `docs/ARCHITECTURE.md` section 5 ("Disk and
//! filesystem state"). The flags and their meaning are those of
//! `FSEvents.h` of the macOS SDK.
//!
//! An event names a directory in which something changed. It is not a
//! record of each change: `FSEvents` coalesces events, and it can drop them.
//! The adapter gives the events as they arrive, with their flags, and the
//! consumer ([`crate::runtime::invalidation`]) decides what each event
//! makes dirty. An event never makes a candidate and never authorizes an
//! action.
//!
//! The stream calls back on a private serial dispatch queue. The callback
//! only appends to a bounded inbox ([`EventInbox`]); the owner of the
//! stream takes the inbox with [`EventStream::drain`]. When the inbox is
//! full, the callback keeps no further event and records the loss, so a
//! burst of events costs a bounded quantity of memory and the consumer
//! reconciles each root.
//!
//! | Item | Content |
//! | --- | --- |
//! | [`EventStream`] | The interface of a stream: start, stop, and drain |
//! | [`system_stream`] | The stream of this platform |
//! | [`flags`] | The event flags of `FSEvents.h` that the consumer reads |

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, PoisonError};

use thiserror::Error;

#[cfg(target_os = "macos")]
mod native;

/// The event flags of `FSEvents.h` (`FSEventStreamEventFlags`) that the
/// consumer reads. The values are those of the macOS SDK; a test on macOS
/// compares them with the constants of the bindings.
pub mod flags {
    /// The consumer must scan the directory of the event and each
    /// directory below it: events were coalesced hierarchically.
    pub const MUST_SCAN_SUBDIRS: u32 = 0x0000_0001;
    /// Events were dropped in the buffer of the client.
    pub const USER_DROPPED: u32 = 0x0000_0002;
    /// Events were dropped in the kernel.
    pub const KERNEL_DROPPED: u32 = 0x0000_0004;
    /// The 64-bit event identifier wrapped. Earlier identifiers are not
    /// valid any more.
    pub const EVENT_IDS_WRAPPED: u32 = 0x0000_0008;
    /// The end of the historical events. The path has no meaning.
    pub const HISTORY_DONE: u32 = 0x0000_0010;
    /// A directory on the path to a watched root changed. The path is the
    /// watched root, and the identifier is zero.
    pub const ROOT_CHANGED: u32 = 0x0000_0020;
    /// A volume was mounted below a watched root.
    pub const MOUNT: u32 = 0x0000_0040;
    /// A volume was unmounted below a watched root.
    pub const UNMOUNT: u32 = 0x0000_0080;
}

/// The largest number of events that the inbox keeps between two drains.
/// A later event is not kept, and the batch records the loss.
pub const MAX_PENDING_EVENTS: usize = 4096;

/// The latency of the stream, in seconds: `FSEvents` holds the events of
/// this interval and gives them in one callback. It is the first stage of
/// the debounce; the consumer has the second.
pub const STREAM_LATENCY_SECONDS: f64 = 2.0;

/// One event of the stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawEvent {
    /// The path of the event, as `FSEvents` gives it: the directory in
    /// which something changed, or the root, the mount point, or the
    /// directory that a flag names.
    pub path: PathBuf,
    /// The flags of the event ([`flags`]).
    pub flags: u32,
    /// The event identifier. Zero for a [`flags::ROOT_CHANGED`] event.
    pub id: u64,
}

/// The events of the stream since the last drain.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventBatch {
    /// The events, in the sequence of the stream.
    pub events: Vec<RawEvent>,
    /// True when events since the last drain were lost: the inbox was
    /// full, or an event had no path that the adapter could read. The
    /// consumer then knows nothing of what changed.
    pub lost: bool,
}

/// The reason a stream did not start.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WatchError {
    /// This platform has no `FSEvents`.
    #[error("FSEvents is not available on this platform")]
    Unsupported,
    /// A root path is not valid Unicode, so it has no `CFString`.
    #[error("a root path is not valid Unicode")]
    PathNotUnicode,
    /// The platform refused the stream. `FSEvents` gives no reason.
    #[error("the platform refused the event stream ({0})")]
    Refused(&'static str),
}

/// One event stream.
///
/// The owner calls each method from one thread at a time. A stream gives
/// only the events after its start (`kFSEventStreamEventIdSinceNow`): the
/// owner makes its own full reconciliation of the roots after each start.
pub trait EventStream: Send + std::fmt::Debug {
    /// Starts a stream on `roots`. A stream that runs stops first, and its
    /// events that were not drained are discarded.
    ///
    /// # Errors
    ///
    /// Returns a [`WatchError`] when no stream runs after the call.
    fn start(&mut self, roots: &[PathBuf]) -> Result<(), WatchError>;

    /// Stops the stream. After the call, no callback runs.
    fn stop(&mut self);

    /// Takes the events since the last drain.
    fn drain(&mut self) -> EventBatch;
}

/// The bounded inbox between the callback of the stream and its owner.
#[derive(Debug, Default)]
pub struct EventInbox {
    state: Mutex<EventBatch>,
}

impl EventInbox {
    fn lock(&self) -> MutexGuard<'_, EventBatch> {
        // A callback that panicked while it held the lock left a batch
        // that is still a valid value: the panic is caught at the
        // callback, and the batch is marked as lost below.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Appends the events of one callback. An event after the bound is
    /// not kept, and the batch records the loss.
    pub fn push(&self, events: impl IntoIterator<Item = Option<RawEvent>>) {
        let mut batch: MutexGuard<'_, EventBatch> = self.lock();
        for event in events {
            match event {
                Some(event) if batch.events.len() < MAX_PENDING_EVENTS => batch.events.push(event),
                _ => batch.lost = true,
            }
        }
    }

    /// Records that events were lost.
    pub fn mark_lost(&self) {
        self.lock().lost = true;
    }

    /// Takes the batch and leaves an empty one.
    pub fn take(&self) -> EventBatch {
        std::mem::take(&mut *self.lock())
    }
}

/// A stream that never starts: the stream of a platform with no `FSEvents`,
/// and of a source with no event stream.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnsupportedStream;

impl EventStream for UnsupportedStream {
    fn start(&mut self, _roots: &[PathBuf]) -> Result<(), WatchError> {
        Err(WatchError::Unsupported)
    }

    fn stop(&mut self) {}

    fn drain(&mut self) -> EventBatch {
        EventBatch::default()
    }
}

/// The event stream of this platform: `FSEvents` on macOS, and
/// [`UnsupportedStream`] on each other platform.
#[must_use]
pub fn system_stream() -> Box<dyn EventStream> {
    #[cfg(target_os = "macos")]
    {
        Box::new(native::NativeEventStream::new())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Box::new(UnsupportedStream)
    }
}

#[cfg(test)]
mod tests;
