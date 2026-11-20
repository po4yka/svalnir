//! The dialog center of the agent (owner decision of 2026-11-20): a system
//! dialog for the urgent kinds only, through `CFUserNotification`.
//!
//! The User Notifications framework does not deliver for a launchd agent
//! (Apple Developer Forums threads 804854 and 728836). A launchd agent can
//! use `CFUserNotification`, which shows a dialog, not a banner. So this
//! center shows a dialog only for the three urgent kinds
//! ([`NoticeKind::is_urgent`]); it does not show the other kinds, and the
//! service does not queue them ([`NotificationCenter::presents`]).
//!
//! The native call is `CFUserNotificationDisplayNotice`. The Apple
//! reference states that it "returns immediately" and does not wait for a
//! response, and it states no thread requirement. The worker thread of
//! [`super::NotificationService`] calls it, so the controller and the
//! coordinator never wait for it. The dialog closes after
//! [`DIALOG_TIMEOUT_SECONDS`] or when the user dismisses it. A return value
//! that is not 0 is a failed post: the worker counts it and does not try
//! again.
//!
//! The text of a dialog is the name of the product, the title of the
//! notice, and one sentence for the kind. It has no path, no process
//! argument, no process name, no environment value, and no secret.
// TODO(npochaev): a banner through a nested application of the bundle,
// after the first release (owner decision of 2026-11-20).

use super::{CenterAuthorization, Notice, NoticeKind, NotificationCenter, PostError};

/// The time after which a dialog closes when the user does not dismiss it.
pub const DIALOG_TIMEOUT_SECONDS: f64 = 60.0;

/// The capability sentence of [`DialogCenter`] for the status record and
/// `svalnir doctor`.
pub const DIALOG_DETAIL: &str = "Dialog for urgent notices, no banner: the agent shows a system dialog for critical memory pressure, an exhausted incident budget, and an automatic operation that did not complete, and the dialog closes after 60 s.";

/// The text of one dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialogText {
    /// The header: the name of the product and the title of the notice.
    pub header: String,
    /// One sentence.
    pub message: String,
}

/// The text of the dialog of `notice`, or `None` for a kind that is not
/// urgent.
#[must_use]
pub fn dialog_text(notice: &Notice) -> Option<DialogText> {
    let message: &str = match notice.kind {
        NoticeKind::MemoryPressureCritical => {
            "Open Svalnir and see Memory for the footprint of each application."
        }
        NoticeKind::IncidentBudgetExhausted => {
            "The guard does no more automatic work until the incident ends or you rearm it in Automation."
        }
        NoticeKind::AutomaticOperationNotCompleted => {
            "Open Svalnir and see History for the result of each target."
        }
        NoticeKind::GuardActing
        | NoticeKind::StopSettled
        | NoticeKind::ManualOperationNotCompleted => return None,
    };
    Some(DialogText {
        header: format!("Svalnir: {}", notice.title),
        message: message.to_owned(),
    })
}

/// Why the native call showed no dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayError {
    /// A text did not become a native string.
    NotAString,
    /// `CFUserNotificationDisplayNotice` returned this code, not 0.
    Code(i32),
}

/// The native call that shows one dialog. A test uses a fake; the agent
/// uses [`CoreFoundationDialog`].
pub trait DialogDisplay: Send {
    /// Shows `text` and returns at once.
    ///
    /// # Errors
    ///
    /// Returns a [`DisplayError`] when the call showed no dialog.
    fn show(&mut self, text: &DialogText) -> Result<(), DisplayError>;
}

/// The center that shows a dialog for the urgent kinds.
#[derive(Debug)]
pub struct DialogCenter<D> {
    display: D,
}

impl<D: DialogDisplay> DialogCenter<D> {
    /// The center of `display`.
    #[must_use]
    pub const fn new(display: D) -> Self {
        Self { display }
    }
}

impl<D: DialogDisplay> NotificationCenter for DialogCenter<D> {
    fn authorization(&mut self) -> (CenterAuthorization, String) {
        // A dialog of `CFUserNotification` needs no authorization and asks
        // the user for none.
        (CenterAuthorization::Authorized, DIALOG_DETAIL.to_owned())
    }

    fn presents(&self, kind: NoticeKind) -> bool {
        kind.is_urgent()
    }

    fn post(&mut self, notice: &Notice) -> Result<(), PostError> {
        let Some(text) = dialog_text(notice) else {
            return Err(PostError::Failed(
                "the dialog center shows only the urgent kinds".to_owned(),
            ));
        };
        self.display.show(&text).map_err(|error| {
            PostError::Failed(match error {
                DisplayError::NotAString => {
                    "the text of the dialog did not become a native string".to_owned()
                }
                DisplayError::Code(code) => {
                    format!("CFUserNotificationDisplayNotice returned {code}")
                }
            })
        })
    }
}

/// The dialog of Core Foundation: `CFUserNotificationDisplayNotice` with
/// the note alert level and [`DIALOG_TIMEOUT_SECONDS`].
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, Default)]
pub struct CoreFoundationDialog;

#[cfg(target_os = "macos")]
fn native_string(
    text: &str,
) -> Option<objc2_core_foundation::CFRetained<objc2_core_foundation::CFString>> {
    use objc2_core_foundation::{CFIndex, CFString, CFStringBuiltInEncodings};
    let length: CFIndex = CFIndex::try_from(text.len()).ok()?;
    // SAFETY: `text.as_ptr()` points to `text.len()` bytes of valid UTF-8
    // that live for the duration of the call; `CFStringCreateWithBytes`
    // copies them and keeps no pointer. `None` selects the default
    // allocator, which the function permits. The result is owned
    // (`CFRetained`), so its drop releases it.
    unsafe {
        CFString::with_bytes(
            None,
            text.as_ptr(),
            length,
            CFStringBuiltInEncodings::EncodingUTF8.0,
            false,
        )
    }
}

#[cfg(target_os = "macos")]
impl DialogDisplay for CoreFoundationDialog {
    fn show(&mut self, text: &DialogText) -> Result<(), DisplayError> {
        use objc2_core_foundation::{CFUserNotification, kCFUserNotificationNoteAlertLevel};
        let header = native_string(&text.header).ok_or(DisplayError::NotAString)?;
        let message = native_string(&text.message).ok_or(DisplayError::NotAString)?;
        // No icon, no sound, no localization, and the default button
        // title ("OK"). The call sends the request and returns; the
        // strings are released when they go out of scope.
        let code: i32 = CFUserNotification::display_notice(
            DIALOG_TIMEOUT_SECONDS,
            kCFUserNotificationNoteAlertLevel,
            None,
            None,
            None,
            Some(&header),
            Some(&message),
            None,
        );
        if code == 0 {
            Ok(())
        } else {
            Err(DisplayError::Code(code))
        }
    }
}

#[cfg(test)]
mod tests;
