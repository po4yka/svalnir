//! The native calls of the XPC transport.
//!
//! Each `unsafe` block of the transport is in this file. The declarations
//! are those of the macOS SDK headers `xpc/xpc.h`, `xpc/connection.h`,
//! `xpc/endpoint.h`, `dispatch/queue.h`, `Security/SecCode.h`,
//! `Security/SecRequirement.h`, and `CoreFoundation/CFString.h`.
//!
//! # Ownership
//!
//! - [`Object`] owns one reference to an XPC object and releases it in
//!   `Drop`. A function of XPC that returns a retained object gives its
//!   reference to an [`Object`]. The event of a handler is borrowed for
//!   the call of the handler: [`Event`] retains a peer connection that it
//!   keeps, and [`Message`] has the lifetime of the call.
//! - [`Queue`] owns one reference to a dispatch queue.
//! - [`Requirement`] owns one reference to a `SecRequirementRef`.
//!
//! # Threads
//!
//! XPC calls an event handler on the target queue of its connection. The
//! transport uses one serial queue, so no two handlers run at the same
//! time. [`handler_block`] requires a handler that is `Send` and `Sync`,
//! because the thread that makes a handler is not the thread that runs it.
//! A panic of a handler does not unwind into XPC: the block catches it.
//!
//! # Code identity
//!
//! `SecCodeCreateWithXPCMessage` makes the code object of the process that
//! sent a message from the audit token of that message, not from a process
//! identifier. `SecCodeCheckValidity` then validates that code against a
//! requirement. The transport calls no API that takes a process
//! identifier.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::marker::PhantomData;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::NonNull;

use block2::{Block, RcBlock};

/// A pointer to an XPC object (`xpc_object_t`).
type XpcObject = *mut c_void;

/// A type of the platform whose layout this file does not use.
#[repr(C)]
struct Opaque {
    _private: [u8; 0],
}

/// `XPC_CONNECTION_MACH_SERVICE_LISTENER` of `xpc/connection.h`.
const MACH_SERVICE_LISTENER: u64 = 1;

/// `kSecCSDefaultFlags` of `Security/CSCommon.h`.
const SEC_CS_DEFAULT_FLAGS: u32 = 0;

/// `kCFStringEncodingUTF8` of `CoreFoundation/CFString.h`.
const CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

/// `errSecCSReqFailed` of `Security/CSCommon.h`: the code does not satisfy
/// the requirement.
pub(super) const ERR_SEC_CS_REQ_FAILED: i32 = -67050;

/// `errSecCSUnsigned` of `Security/CSCommon.h`: the code has no signature.
pub(super) const ERR_SEC_CS_UNSIGNED: i32 = -67062;

unsafe extern "C" {
    static _xpc_type_connection: Opaque;
    static _xpc_type_dictionary: Opaque;
    static _xpc_error_connection_invalid: Opaque;

    fn xpc_connection_create_mach_service(
        name: *const c_char,
        targetq: *mut c_void,
        flags: u64,
    ) -> XpcObject;
    fn xpc_connection_set_event_handler(connection: XpcObject, handler: &Block<dyn Fn(XpcObject)>);
    fn xpc_connection_set_target_queue(connection: XpcObject, targetq: *mut c_void);
    fn xpc_connection_resume(connection: XpcObject);
    fn xpc_connection_cancel(connection: XpcObject);
    fn xpc_connection_send_message(connection: XpcObject, message: XpcObject);
    fn xpc_connection_get_euid(connection: XpcObject) -> libc::uid_t;
    // `au_asid_t` of `bsm/audit.h` is `pid_t`.
    fn xpc_connection_get_asid(connection: XpcObject) -> libc::pid_t;
    fn xpc_connection_set_peer_code_signing_requirement(
        connection: XpcObject,
        requirement: *const c_char,
    ) -> c_int;
    fn xpc_get_type(object: XpcObject) -> *const Opaque;
    fn xpc_retain(object: XpcObject) -> XpcObject;
    fn xpc_release(object: XpcObject);
    fn xpc_dictionary_create_reply(original: XpcObject) -> XpcObject;
    fn xpc_dictionary_get_count(dictionary: XpcObject) -> usize;
    fn xpc_dictionary_get_data(
        dictionary: XpcObject,
        key: *const c_char,
        length: *mut usize,
    ) -> *const c_void;
    fn xpc_dictionary_set_data(
        dictionary: XpcObject,
        key: *const c_char,
        bytes: *const c_void,
        length: usize,
    );

    fn dispatch_queue_create(label: *const c_char, attributes: *const c_void) -> *mut c_void;
    fn dispatch_release(object: *mut c_void);
}

#[cfg(test)]
unsafe extern "C" {
    fn xpc_connection_create(name: *const c_char, targetq: *mut c_void) -> XpcObject;
    fn xpc_endpoint_create(connection: XpcObject) -> XpcObject;
    fn xpc_connection_create_from_endpoint(endpoint: XpcObject) -> XpcObject;
    fn xpc_connection_send_message_with_reply_sync(
        connection: XpcObject,
        message: XpcObject,
    ) -> XpcObject;
    fn xpc_dictionary_create_empty() -> XpcObject;
    fn xpc_dictionary_set_int64(dictionary: XpcObject, key: *const c_char, value: i64);
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecRequirementCreateWithString(
        text: *const c_void,
        flags: u32,
        requirement: *mut *mut c_void,
    ) -> i32;
    fn SecCodeCreateWithXPCMessage(message: XpcObject, flags: u32, target: *mut *mut c_void)
    -> i32;
    fn SecCodeCheckValidity(code: *mut c_void, flags: u32, requirement: *mut c_void) -> i32;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFStringCreateWithBytes(
        allocator: *const c_void,
        bytes: *const u8,
        length: isize,
        encoding: u32,
        is_external_representation: u8,
    ) -> *const c_void;
    fn CFRelease(object: *const c_void);
}

/// One owned reference to an XPC object.
#[derive(Debug)]
pub(super) struct Object(NonNull<c_void>);

// SAFETY: an XPC object is reference counted with atomic operations, and
// XPC permits a retain, a release, and a call on a connection from each
// thread. This file gives no mutable access to a dictionary through a
// shared reference of an `Object`.
unsafe impl Send for Object {}
// SAFETY: see `Send`. Each method on `&Object` of this file is a call that
// XPC permits from more than one thread: connection calls, and reads of an
// immutable message.
unsafe impl Sync for Object {}

impl Object {
    /// Takes the reference that a creating function of XPC returned.
    /// `None` for a null pointer.
    fn from_owned(pointer: XpcObject) -> Option<Self> {
        NonNull::new(pointer).map(Self)
    }

    /// Retains a borrowed object.
    ///
    /// # Safety
    ///
    /// `pointer` must be null or a pointer to a live XPC object.
    unsafe fn retain(pointer: XpcObject) -> Option<Self> {
        let pointer: NonNull<c_void> = NonNull::new(pointer)?;
        // SAFETY: the caller states that the object is live. `xpc_retain`
        // returns its argument.
        let retained: XpcObject = unsafe { xpc_retain(pointer.as_ptr()) };
        NonNull::new(retained).map(Self)
    }

    fn as_ptr(&self) -> XpcObject {
        self.0.as_ptr()
    }
}

impl Clone for Object {
    fn clone(&self) -> Self {
        // SAFETY: `self` owns a reference, so the object is live.
        // `xpc_retain` returns its argument, which is not null.
        let retained: XpcObject = unsafe { xpc_retain(self.as_ptr()) };
        Self(NonNull::new(retained).unwrap_or(self.0))
    }
}

impl Drop for Object {
    fn drop(&mut self) {
        // SAFETY: `self` owns one reference to a live object, and this is
        // its one release.
        unsafe { xpc_release(self.as_ptr()) };
    }
}

/// One owned reference to a serial dispatch queue.
#[derive(Debug)]
pub(super) struct Queue(NonNull<c_void>);

// SAFETY: a dispatch queue is reference counted with atomic operations,
// and each thread can use it.
unsafe impl Send for Queue {}
// SAFETY: see `Send`.
unsafe impl Sync for Queue {}

impl Queue {
    /// Makes a serial queue. `None` when the platform gives no queue.
    pub(super) fn serial(label: &CStr) -> Option<Self> {
        // SAFETY: `label` is a NUL-terminated string that lives for the
        // call; the function copies it. A null attribute makes a serial
        // queue.
        let queue: *mut c_void = unsafe { dispatch_queue_create(label.as_ptr(), std::ptr::null()) };
        NonNull::new(queue).map(Self)
    }
}

impl Drop for Queue {
    fn drop(&mut self) {
        // SAFETY: `self` owns one reference to a live queue, and this is
        // its one release. A connection that has the queue as its target
        // has its own reference.
        unsafe { dispatch_release(self.0.as_ptr()) };
    }
}

/// An XPC connection: a listener or the connection of one peer.
#[derive(Debug, Clone)]
pub(super) struct Connection(Object);

impl Connection {
    /// Makes the listener of the Mach service `name`. The platform
    /// reports a name that the process cannot register to the event
    /// handler, after `resume`.
    pub(super) fn mach_listener(name: &CStr, queue: &Queue) -> Option<Self> {
        // SAFETY: `name` is a NUL-terminated string that lives for the
        // call, and `queue` is a live queue. The function returns a
        // retained connection.
        let listener: XpcObject = unsafe {
            xpc_connection_create_mach_service(
                name.as_ptr(),
                queue.0.as_ptr(),
                MACH_SERVICE_LISTENER,
            )
        };
        Object::from_owned(listener).map(Self)
    }

    /// Makes an anonymous listener. It registers no name: a peer connects
    /// only with an endpoint of the listener.
    #[cfg(test)]
    pub(super) fn anonymous_listener(queue: &Queue) -> Option<Self> {
        // SAFETY: a null name makes an anonymous listener, and `queue` is
        // a live queue. The function returns a retained connection.
        let listener: XpcObject =
            unsafe { xpc_connection_create(std::ptr::null(), queue.0.as_ptr()) };
        Object::from_owned(listener).map(Self)
    }

    /// Sets the event handler. Call this one time, before `resume`.
    pub(super) fn set_event_handler(&self, handler: &RcBlock<dyn Fn(XpcObject)>) {
        // SAFETY: the connection is live, and `handler` is a live block
        // with the signature of `xpc_handler_t`. XPC copies the block.
        unsafe { xpc_connection_set_event_handler(self.0.as_ptr(), handler) };
    }

    /// Sets the queue on which XPC calls the event handler.
    pub(super) fn set_target_queue(&self, queue: &Queue) {
        // SAFETY: the connection and the queue are live. XPC retains the
        // queue.
        unsafe { xpc_connection_set_target_queue(self.0.as_ptr(), queue.0.as_ptr()) };
    }

    /// Requires that each peer of the connection satisfies `requirement`.
    /// XPC then drops a request of a peer that does not. Call this one
    /// time, before `resume`.
    ///
    /// # Errors
    ///
    /// Returns the status of XPC when it refuses the requirement text.
    pub(super) fn require_peer(&self, requirement: &CStr) -> Result<(), c_int> {
        // SAFETY: the connection is live, and `requirement` is a
        // NUL-terminated string that lives for the call; XPC copies it.
        let status: c_int = unsafe {
            xpc_connection_set_peer_code_signing_requirement(self.0.as_ptr(), requirement.as_ptr())
        };
        if status == 0 { Ok(()) } else { Err(status) }
    }

    /// Starts the delivery of events.
    pub(super) fn resume(&self) {
        // SAFETY: the connection is live and has its event handler.
        unsafe { xpc_connection_resume(self.0.as_ptr()) };
    }

    /// Cancels the connection. XPC delivers a last invalid event.
    pub(super) fn cancel(&self) {
        // SAFETY: the connection is live.
        unsafe { xpc_connection_cancel(self.0.as_ptr()) };
    }

    /// Sends a reply dictionary.
    pub(super) fn send(&self, message: &Dictionary) {
        // SAFETY: the connection and the dictionary are live. XPC retains
        // what it needs of the message.
        unsafe { xpc_connection_send_message(self.0.as_ptr(), message.0.as_ptr()) };
    }

    /// The effective user of the peer, from the platform.
    pub(super) fn effective_uid(&self) -> u32 {
        // SAFETY: the connection is live. The call reads a value that XPC
        // recorded for the connection.
        unsafe { xpc_connection_get_euid(self.0.as_ptr()) }
    }

    /// The audit session identifier of the peer, from the platform.
    pub(super) fn audit_session(&self) -> i32 {
        // SAFETY: the connection is live. The call reads a value that XPC
        // recorded for the connection.
        unsafe { xpc_connection_get_asid(self.0.as_ptr()) }
    }
}

/// A dictionary that this process made: a reply, or a request of a test.
#[derive(Debug)]
pub(super) struct Dictionary(Object);

impl Dictionary {
    /// Sets the data value of `key`.
    pub(super) fn set_data(&mut self, key: &CStr, bytes: &[u8]) {
        // SAFETY: the dictionary is live, and this process has the only
        // reference that changes it (`&mut self`). `key` is a
        // NUL-terminated string, and `bytes` is valid for a read of its
        // length. XPC copies the two.
        unsafe {
            xpc_dictionary_set_data(
                self.0.as_ptr(),
                key.as_ptr(),
                bytes.as_ptr().cast::<c_void>(),
                bytes.len(),
            );
        }
    }
}

/// A dictionary message of a peer, borrowed for one call of a handler.
#[derive(Debug, Clone, Copy)]
pub(super) struct Message<'event> {
    pointer: NonNull<c_void>,
    event: PhantomData<&'event Opaque>,
}

impl<'event> Message<'event> {
    /// The number of entries of the message.
    pub(super) fn entry_count(self) -> usize {
        // SAFETY: the message is a live dictionary for `'event`.
        unsafe { xpc_dictionary_get_count(self.pointer.as_ptr()) }
    }

    /// The data value of `key`. `None` when the message has no such key or
    /// when its value is not data. The bytes are those of the message and
    /// live as long as it.
    pub(super) fn data(self, key: &CStr) -> Option<&'event [u8]> {
        let mut length: usize = 0;
        // SAFETY: the message is a live dictionary for `'event`, `key` is
        // a NUL-terminated string, and `length` is valid for a write.
        let bytes: *const c_void = unsafe {
            xpc_dictionary_get_data(self.pointer.as_ptr(), key.as_ptr(), &raw mut length)
        };
        if bytes.is_null() {
            return None;
        }
        if length == 0 {
            return Some(&[]);
        }
        // SAFETY: XPC returned a pointer that is not null to `length`
        // bytes of the message. The message is immutable and lives for
        // `'event`, and `u8` has no alignment requirement.
        Some(unsafe { std::slice::from_raw_parts(bytes.cast::<u8>(), length) })
    }

    /// Makes the reply dictionary of the message. `None` when the peer
    /// expects no reply.
    pub(super) fn create_reply(self) -> Option<Dictionary> {
        // SAFETY: the message is a live dictionary for `'event`. The
        // function returns a retained dictionary or null.
        let reply: XpcObject = unsafe { xpc_dictionary_create_reply(self.pointer.as_ptr()) };
        Object::from_owned(reply).map(Dictionary)
    }
}

/// One event of a connection.
#[derive(Debug)]
pub(super) enum Event<'event> {
    /// A new peer connection, for a listener.
    Peer(Connection),
    /// A dictionary message of the peer.
    Message(Message<'event>),
    /// The connection is invalid: the platform refused the registration
    /// of a listener, or the connection was canceled or closed.
    Invalid,
    /// Each other event.
    Other,
}

/// Reads the event that XPC gave to a handler.
///
/// # Safety
///
/// `event` must be the argument of the running event handler: null or a
/// pointer to an XPC object that lives for `'event`.
unsafe fn read_event<'event>(event: XpcObject) -> Event<'event> {
    let Some(pointer) = NonNull::new(event) else {
        return Event::Other;
    };
    if std::ptr::eq(
        event.cast::<Opaque>(),
        &raw const _xpc_error_connection_invalid,
    ) {
        return Event::Invalid;
    }
    // SAFETY: the caller states that `event` is a live XPC object.
    let kind: *const Opaque = unsafe { xpc_get_type(event) };
    if std::ptr::eq(kind, &raw const _xpc_type_dictionary) {
        return Event::Message(Message {
            pointer,
            event: PhantomData,
        });
    }
    if std::ptr::eq(kind, &raw const _xpc_type_connection) {
        // SAFETY: the caller states that `event` is a live XPC object.
        // The connection is kept after the handler returns, so it gets
        // its own reference.
        return match unsafe { Object::retain(event) } {
            Some(object) => Event::Peer(Connection(object)),
            None => Event::Other,
        };
    }
    Event::Other
}

/// Makes the block of an event handler.
///
/// The handler runs on the target queue of its connection, which is not
/// the thread that makes it, so it must be `Send` and `Sync`. A panic of
/// the handler is caught: unwinding into XPC is not defined.
pub(super) fn handler_block<F>(handler: F) -> RcBlock<dyn Fn(XpcObject)>
where
    F: Fn(Event<'_>) + Send + Sync + 'static,
{
    RcBlock::new(move |event: XpcObject| {
        // SAFETY: XPC calls the block with the event of the handler,
        // which lives for this call. `read_event` gives a value with a
        // lifetime that ends in this closure.
        let event: Event<'_> = unsafe { read_event(event) };
        // A caught panic leaves the lock of the service poisoned, and the
        // service then refuses each request.
        let _caught: Result<(), Box<dyn std::any::Any + Send>> =
            catch_unwind(AssertUnwindSafe(|| handler(event)));
    })
}

/// One owned reference to a compiled code requirement
/// (`SecRequirementRef`).
#[derive(Debug)]
pub(super) struct Requirement(NonNull<c_void>);

// SAFETY: a `SecRequirementRef` is an immutable Core Foundation object
// with atomic reference counting. This file only reads it.
unsafe impl Send for Requirement {}
// SAFETY: see `Send`.
unsafe impl Sync for Requirement {}

impl Requirement {
    /// Compiles the requirement text.
    ///
    /// # Errors
    ///
    /// Returns the status of the Security framework when it refuses the
    /// text, and `-1` when the platform gives no string object.
    pub(super) fn compile(text: &str) -> Result<Self, i32> {
        let length: isize = isize::try_from(text.len()).map_err(|_| -1)?;
        // SAFETY: `text` is valid for a read of `length` bytes of UTF-8.
        // A null allocator is the default allocator. The function copies
        // the bytes and returns a retained string or null.
        let string: *const c_void = unsafe {
            CFStringCreateWithBytes(
                std::ptr::null(),
                text.as_ptr(),
                length,
                CF_STRING_ENCODING_UTF8,
                0,
            )
        };
        if string.is_null() {
            return Err(-1);
        }
        let mut requirement: *mut c_void = std::ptr::null_mut();
        // SAFETY: `string` is a live `CFStringRef`, and `requirement` is
        // valid for a write of one pointer. On success the function
        // writes a retained requirement.
        let status: i32 = unsafe {
            SecRequirementCreateWithString(string, SEC_CS_DEFAULT_FLAGS, &raw mut requirement)
        };
        // SAFETY: `string` is the retained string of this function, and
        // this is its one release.
        unsafe { CFRelease(string) };
        match NonNull::new(requirement) {
            Some(requirement) if status == 0 => Ok(Self(requirement)),
            Some(requirement) => {
                // SAFETY: the function wrote a retained object and also
                // reported a failure. This is the one release of it.
                unsafe { CFRelease(requirement.as_ptr()) };
                Err(status)
            }
            None if status == 0 => Err(-1),
            None => Err(status),
        }
    }

    /// Checks that the code of the process that sent `message` is valid
    /// and satisfies the requirement.
    ///
    /// # Errors
    ///
    /// Returns the status of the Security framework: `errSecCSReqFailed`
    /// when the code does not satisfy the requirement, `errSecCSUnsigned`
    /// when it has no signature, or another status.
    pub(super) fn check(&self, message: Message<'_>) -> Result<(), i32> {
        let mut code: *mut c_void = std::ptr::null_mut();
        // SAFETY: `message` is a live dictionary that a connection
        // received, and `code` is valid for a write of one pointer. On
        // success the function writes a retained code object.
        let status: i32 = unsafe {
            SecCodeCreateWithXPCMessage(
                message.pointer.as_ptr(),
                SEC_CS_DEFAULT_FLAGS,
                &raw mut code,
            )
        };
        let Some(code) = NonNull::new(code) else {
            return Err(if status == 0 { -1 } else { status });
        };
        let validity: i32 = if status == 0 {
            // SAFETY: `code` is a live code object, and the requirement
            // is live.
            unsafe { SecCodeCheckValidity(code.as_ptr(), SEC_CS_DEFAULT_FLAGS, self.0.as_ptr()) }
        } else {
            status
        };
        // SAFETY: `code` is the retained object of this function, and
        // this is its one release.
        unsafe { CFRelease(code.as_ptr()) };
        if validity == 0 { Ok(()) } else { Err(validity) }
    }
}

impl Drop for Requirement {
    fn drop(&mut self) {
        // SAFETY: `self` owns one reference to a live object, and this is
        // its one release.
        unsafe { CFRelease(self.0.as_ptr()) };
    }
}

/// The client side of a connection, for the tests of the transport.
#[cfg(test)]
pub(super) mod client {
    use std::ffi::CStr;

    use super::{
        Connection, Dictionary, Event, Message, Object, XpcObject, handler_block,
        xpc_connection_create_from_endpoint, xpc_connection_send_message_with_reply_sync,
        xpc_dictionary_create_empty, xpc_dictionary_set_int64, xpc_endpoint_create,
    };

    /// The reply of the listener to one request of the client.
    #[derive(Debug, PartialEq, Eq)]
    pub(in super::super) enum Answer {
        /// A dictionary. The value is the data of the response key, when
        /// the dictionary has it.
        Dictionary(Option<Vec<u8>>),
        /// XPC gave an error object in place of a reply.
        Error,
    }

    impl Connection {
        /// Connects to an anonymous listener of this process.
        pub(in super::super) fn connect_to(listener: &Connection) -> Option<Self> {
            // SAFETY: the listener is live. The function returns a
            // retained endpoint.
            let endpoint: XpcObject = unsafe { xpc_endpoint_create(listener.0.as_ptr()) };
            let endpoint: Object = Object::from_owned(endpoint)?;
            // SAFETY: the endpoint is live. The function returns a
            // retained connection.
            let connection: XpcObject =
                unsafe { xpc_connection_create_from_endpoint(endpoint.as_ptr()) };
            let connection: Self = Object::from_owned(connection).map(Self)?;
            connection.set_event_handler(&handler_block(|_: Event<'_>| {}));
            connection.resume();
            Some(connection)
        }

        /// Sends `request` and waits for the reply.
        pub(in super::super) fn call(&self, request: &Dictionary, response_key: &CStr) -> Answer {
            // SAFETY: the connection and the dictionary are live. The
            // function returns a retained reply or error object.
            let reply: XpcObject = unsafe {
                xpc_connection_send_message_with_reply_sync(self.0.as_ptr(), request.0.as_ptr())
            };
            let Some(reply) = Object::from_owned(reply) else {
                return Answer::Error;
            };
            // SAFETY: `reply` is a live XPC object for this function.
            match unsafe { super::read_event(reply.as_ptr()) } {
                Event::Message(message) => {
                    let message: Message<'_> = message;
                    Answer::Dictionary(message.data(response_key).map(<[u8]>::to_vec))
                }
                _ => Answer::Error,
            }
        }
    }

    impl Dictionary {
        /// Makes an empty dictionary.
        pub(in super::super) fn empty() -> Option<Self> {
            // SAFETY: the function has no argument and returns a retained
            // dictionary.
            let dictionary: XpcObject = unsafe { xpc_dictionary_create_empty() };
            Object::from_owned(dictionary).map(Self)
        }

        /// Sets an integer value of `key`.
        pub(in super::super) fn set_integer(&mut self, key: &CStr, value: i64) {
            // SAFETY: the dictionary is live, this process has the only
            // reference that changes it, and `key` is a NUL-terminated
            // string.
            unsafe { xpc_dictionary_set_int64(self.0.as_ptr(), key.as_ptr(), value) };
        }
    }
}
