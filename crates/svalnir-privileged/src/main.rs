//! Svalnir privileged helper.
//!
//! The binary starts the service of the library `svalnir_privileged`
//! through its transport interface. It registers nothing and installs
//! nothing: the platform gives the listener of the Mach service only to
//! the process that the launch daemon definition of the product started.
//! Each other start ends with an error.

use std::process::ExitCode;

#[cfg(target_os = "macos")]
fn run() -> Result<(), String> {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use svalnir_core::quantity::Nanoseconds;
    use svalnir_privileged::executor::FsEvictor;
    use svalnir_privileged::request::{CodeIdentity, SupportedProtocols};
    use svalnir_privileged::service::{HelperService, SystemClock, UnavailableStore};
    use svalnir_privileged::transport::xpc::XpcTransport;
    use svalnir_privileged::transport::{
        AGENT_SIGNING_IDENTIFIER, MACH_SERVICE_NAME, PeerPolicy, Transport as _,
    };
    use svalnir_privileged::validation::{HelperConfig, HelperState, MAX_RECORD_CAPACITY};

    /// The longest validity of a request: 60 s.
    const MAX_VALIDITY: Nanoseconds = Nanoseconds::new(60_000_000_000);
    /// The retention of a settled step: 1 h.
    const RETENTION: Nanoseconds = Nanoseconds::new(3_600_000_000_000);
    /// The team identifier in the settings of a build with no signing
    /// identity. No peer has it: the policy of such a build verifies no
    /// peer.
    const NO_TEAM: &str = "unsigned";

    let policy: PeerPolicy = PeerPolicy::compiled();
    let agent: CodeIdentity = match policy.identity() {
        Some(identity) => identity.clone(),
        None => CodeIdentity::new(AGENT_SIGNING_IDENTIFIER, NO_TEAM)
            .map_err(|error| error.to_string())?,
    };
    let config: HelperConfig = HelperConfig {
        protocols: SupportedProtocols::CURRENT,
        agent,
        max_validity: MAX_VALIDITY,
        record_capacity: MAX_RECORD_CAPACITY,
        principal_quota: MAX_RECORD_CAPACITY / 4,
        retention: RETENTION,
    };
    // TODO(npochaev): load the privilege grants from root-owned storage
    // when the administrative enrollment flow is specified. With no grant,
    // the helper refuses each eviction request.
    let state: HelperState =
        HelperState::new(config, Vec::new()).map_err(|error| error.to_string())?;
    let clock: SystemClock = SystemClock::new().map_err(|error| error.to_string())?;
    let service = HelperService::new(
        state,
        BTreeMap::new(),
        UnavailableStore,
        FsEvictor::new(),
        clock,
    );
    XpcTransport::mach_service(MACH_SERVICE_NAME, policy)
        .serve(Arc::new(service))
        .map_err(|error| error.to_string())
}

#[cfg(not(target_os = "macos"))]
fn run() -> Result<(), String> {
    use svalnir_privileged as _;

    Err("the privileged helper has a transport only on macOS".to_owned())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("svalnir-privileged: {error}. The helper runs no operation.");
            ExitCode::FAILURE
        }
    }
}
