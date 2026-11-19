//! Tests of the catalog of hard protections.

use super::super::{
    ControlPlaneProcess, ProtectionContext, ProtectionFact, SESSION_BUNDLE_IDENTIFIERS,
    hard_protection,
};
use super::{USER, application_association, process};
use crate::file::LosslessPath;
use crate::id::ApplicationInstanceId;
use crate::process::{AttributionMethod, Pid, ProcessAssociation, ProcessIdentity, Uid};

/// A context in which the control plane is known and has no process of a
/// fixture.
fn context(control_plane: &[ControlPlaneProcess]) -> ProtectionContext<'_> {
    ProtectionContext {
        principal: USER,
        control_plane: Some(control_plane),
    }
}

/// An ordinary application process of the user.
fn member() -> ProcessIdentity {
    process("Editor", "pg_editor", application_association("Editor"))
}

fn with_path(path: &str) -> ProcessIdentity {
    let mut process: ProcessIdentity = member();
    process.executable.as_mut().unwrap().path = LosslessPath::from_bytes(path).unwrap();
    process
}

fn with_bundle(bundle_identifier: &str) -> ProcessIdentity {
    let mut process: ProcessIdentity = member();
    process.association = ProcessAssociation::Application {
        instance_id: ApplicationInstanceId::new("app_bundle").unwrap(),
        bundle_identifier: bundle_identifier.to_owned(),
        attribution: AttributionMethod::LaunchServices,
    };
    process
}

#[test]
fn an_ordinary_application_of_the_user_is_not_protected() {
    assert_eq!(
        hard_protection(&[member()], &context(&[])),
        ProtectionFact::NotProtected
    );
    // A tool below `/usr/local/` is not a part of the operating system.
    assert_eq!(
        hard_protection(&[with_path("/usr/local/bin/tool")], &context(&[])),
        ProtectionFact::NotProtected
    );
    // A directory whose name only starts with `local` is below `/usr/`.
    assert_eq!(
        hard_protection(&[with_path("/usr/localx/bin/tool")], &context(&[])),
        ProtectionFact::Protected
    );
}

#[test]
fn a_process_of_a_different_user_or_of_root_is_protected() {
    let mut other: ProcessIdentity = member();
    other.uid = Uid::new(USER.get() + 1);
    assert_eq!(
        hard_protection(&[other], &context(&[])),
        ProtectionFact::Protected
    );

    let mut root: ProcessIdentity = member();
    root.uid = Uid::new(0);
    let as_root = ProtectionContext {
        principal: Uid::new(0),
        control_plane: Some(&[]),
    };
    assert_eq!(
        hard_protection(&[root], &as_root),
        ProtectionFact::Protected
    );
}

#[test]
fn launchd_and_a_system_executable_are_protected() {
    let mut launchd: ProcessIdentity = member();
    launchd.pid = Pid::new(1).unwrap();
    assert_eq!(
        hard_protection(&[launchd], &context(&[])),
        ProtectionFact::Protected
    );
    for path in [
        "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
        "/usr/libexec/secd",
        "/bin/zsh",
        "/sbin/launchd",
        "/Library/Apple/usr/libexec/oah/runtime",
        // The default volume format ignores case.
        "/system/Library/CoreServices/Dock.app/Contents/MacOS/Dock",
        "/USR/bin/true",
    ] {
        assert_eq!(
            hard_protection(&[with_path(path)], &context(&[])),
            ProtectionFact::Protected,
            "{path}"
        );
    }
}

#[test]
fn a_session_application_and_each_svalnir_component_are_protected() {
    for bundle_identifier in SESSION_BUNDLE_IDENTIFIERS {
        assert_eq!(
            hard_protection(&[with_bundle(bundle_identifier)], &context(&[])),
            ProtectionFact::Protected,
            "{bundle_identifier}"
        );
    }
    for bundle_identifier in [
        "COM.APPLE.FINDER",
        "dev.po4yka.svalnir",
        "dev.po4yka.svalnir.gui",
    ] {
        assert_eq!(
            hard_protection(&[with_bundle(bundle_identifier)], &context(&[])),
            ProtectionFact::Protected,
            "{bundle_identifier}"
        );
    }
    // A prefix of the text is not a component of Svalnir.
    assert_eq!(
        hard_protection(&[with_bundle("dev.po4yka.svalnirx.tool")], &context(&[])),
        ProtectionFact::NotProtected
    );
    for path in [
        "/Users/me/bin/svalnir",
        "/Applications/Svalnir.app/Contents/MacOS/svalnir-agent",
        "/Applications/Svalnir.app/Contents/MacOS/Svalnir",
    ] {
        assert_eq!(
            hard_protection(&[with_path(path)], &context(&[])),
            ProtectionFact::Protected,
            "{path}"
        );
    }
}

#[test]
fn an_unverified_bundle_claim_still_protects() {
    let mut claimed: ProcessIdentity = with_bundle("com.apple.dock");
    // A launchd-job method cannot establish an application membership.
    if let ProcessAssociation::Application { attribution, .. } = &mut claimed.association {
        *attribution = AttributionMethod::LaunchdJob;
    }
    assert!(claimed.association.verified_membership().is_none());
    assert_eq!(
        hard_protection(&[claimed], &context(&[])),
        ProtectionFact::Protected
    );
}

#[test]
fn the_evaluating_process_and_its_ancestors_are_protected_by_pid_and_start_time() {
    let terminal: ProcessIdentity = member();
    let control_plane = [ControlPlaneProcess {
        pid: terminal.pid,
        start_time: terminal.start_time,
    }];
    assert_eq!(
        hard_protection(std::slice::from_ref(&terminal), &context(&control_plane)),
        ProtectionFact::Protected
    );

    // A new process that got the PID of an ancestor that exited is not the
    // ancestor.
    let reused = [ControlPlaneProcess {
        pid: terminal.pid,
        start_time: crate::process::ProcessStartTime::new(terminal.start_time.get() + 1),
    }];
    assert_eq!(
        hard_protection(&[terminal], &context(&reused)),
        ProtectionFact::NotProtected
    );
}

#[test]
fn missing_evidence_is_unknown_and_not_unprotected() {
    // No member.
    assert_eq!(hard_protection(&[], &context(&[])), ProtectionFact::Unknown);

    // No executable evidence.
    let mut no_executable: ProcessIdentity = member();
    no_executable.executable = None;
    assert_eq!(
        hard_protection(&[member(), no_executable.clone()], &context(&[])),
        ProtectionFact::Unknown
    );

    // A path that the catalog cannot classify.
    for path in [
        "/Applications/../System/tool",
        "relative/tool",
        "//usr/bin/tool",
        "/./Applications/tool",
        "/Applications/tool/",
        "/",
    ] {
        assert_eq!(
            hard_protection(&[with_path(path)], &context(&[])),
            ProtectionFact::Unknown,
            "{path}"
        );
    }

    // The control plane is not known.
    let unknown_control_plane = ProtectionContext {
        principal: USER,
        control_plane: None,
    };
    assert_eq!(
        hard_protection(&[member()], &unknown_control_plane),
        ProtectionFact::Unknown
    );

    // A protected member decides before a member with missing evidence.
    assert_eq!(
        hard_protection(&[no_executable, with_path("/bin/zsh")], &context(&[])),
        ProtectionFact::Protected
    );
    assert_eq!(
        hard_protection(&[with_path("/bin/zsh")], &unknown_control_plane),
        ProtectionFact::Protected
    );
}

mod explanation {
    use super::super::super::{
        ControlPlaneProcess, HardProtectionEntry, HardProtectionExplanation, ProtectionContext,
        ProtectionMember, ProtectionUnknownCause, explain_hard_protection, hard_protection,
    };
    use super::{USER, context, member, with_bundle, with_path};
    use crate::process::{Pid, ProcessIdentity, Uid};

    fn entry(
        processes: &[ProcessIdentity],
        context: &ProtectionContext<'_>,
    ) -> HardProtectionEntry {
        let explanation: HardProtectionExplanation = explain_hard_protection(processes, context);
        assert_eq!(explanation.fact(), hard_protection(processes, context));
        match explanation {
            HardProtectionExplanation::Protected { entry, .. } => entry,
            other => panic!("not protected: {other:?}"),
        }
    }

    #[test]
    fn each_entry_of_the_catalog_is_the_reason_of_its_match() {
        let mut other: ProcessIdentity = member();
        other.uid = Uid::new(USER.get() + 1);
        assert_eq!(
            entry(&[other], &context(&[])),
            HardProtectionEntry::DifferentOwner
        );

        let mut root: ProcessIdentity = member();
        root.uid = Uid::new(0);
        let as_root = ProtectionContext {
            principal: Uid::new(0),
            control_plane: Some(&[]),
        };
        assert_eq!(entry(&[root], &as_root), HardProtectionEntry::RootOwner);

        let mut launchd: ProcessIdentity = member();
        launchd.pid = Pid::new(1).unwrap();
        assert_eq!(
            entry(&[launchd], &context(&[])),
            HardProtectionEntry::Launchd
        );

        assert_eq!(
            entry(&[with_bundle("com.apple.finder")], &context(&[])),
            HardProtectionEntry::SessionApplication
        );
        assert_eq!(
            entry(&[with_bundle("dev.svalnir.gui")], &context(&[])),
            HardProtectionEntry::ControlPlaneBundle
        );
        assert_eq!(
            entry(&[with_path("/usr/libexec/secd")], &context(&[])),
            HardProtectionEntry::SystemLocation
        );
        assert_eq!(
            entry(
                &[with_path("/Applications/X.app/Contents/MacOS/svalnir-gui")],
                &context(&[])
            ),
            HardProtectionEntry::ControlPlaneExecutable
        );
        let process: ProcessIdentity = member();
        let control_plane = [ControlPlaneProcess {
            pid: process.pid,
            start_time: process.start_time,
        }];
        assert_eq!(
            entry(&[process], &context(&control_plane)),
            HardProtectionEntry::ControlPlaneProcess
        );
    }

    #[test]
    fn the_explanation_names_the_first_protected_member() {
        let ordinary: ProcessIdentity = member();
        let mut system: ProcessIdentity = with_path("/usr/libexec/secd");
        system.pid = Pid::new(777).unwrap();
        let explanation = explain_hard_protection(&[ordinary, system.clone()], &context(&[]));
        assert_eq!(
            explanation,
            HardProtectionExplanation::Protected {
                member: ProtectionMember {
                    pid: system.pid,
                    start_time: system.start_time,
                },
                entry: HardProtectionEntry::SystemLocation,
            }
        );
    }

    #[test]
    fn an_unknown_result_names_its_cause() {
        let unknown = |processes: &[ProcessIdentity], context: &ProtectionContext<'_>| {
            let explanation = explain_hard_protection(processes, context);
            assert_eq!(explanation.fact(), hard_protection(processes, context));
            match explanation {
                HardProtectionExplanation::Unknown { cause, .. } => cause,
                other => panic!("not unknown: {other:?}"),
            }
        };
        assert_eq!(
            unknown(&[], &context(&[])),
            ProtectionUnknownCause::NoMember
        );
        let mut no_executable: ProcessIdentity = member();
        no_executable.executable = None;
        assert_eq!(
            unknown(&[no_executable], &context(&[])),
            ProtectionUnknownCause::NoExecutableEvidence
        );
        assert_eq!(
            unknown(&[with_path("/Applications/../usr/bin/x")], &context(&[])),
            ProtectionUnknownCause::PathNotClassified
        );
        let no_control_plane = ProtectionContext {
            principal: USER,
            control_plane: None,
        };
        assert_eq!(
            unknown(&[member()], &no_control_plane),
            ProtectionUnknownCause::ControlPlaneNotKnown
        );
        // A protected member decides also when another member is unknown.
        let mut no_executable: ProcessIdentity = member();
        no_executable.executable = None;
        assert_eq!(
            explain_hard_protection(
                &[no_executable, with_path("/usr/libexec/secd")],
                &context(&[])
            )
            .fact(),
            crate::policy::ProtectionFact::Protected
        );
        assert_eq!(
            explain_hard_protection(&[member()], &context(&[])),
            HardProtectionExplanation::NotProtected
        );
    }
}
