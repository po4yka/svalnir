//! The fixture of the service, executor, and transport tests.
//!
//! Each file that a test changes is in a temporary directory that the test
//! made. No test installs a service, needs elevated rights, or signals a
//! process.

use std::collections::BTreeMap;
use std::fs;
use std::num::NonZeroU32;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use svalnir_core::action::{ActionClass, Durability, FileObjectType, StepState, WorkCharge};
use svalnir_core::authority::{Generation, PrivilegeGrant, PrivilegeGrantRef};
use svalnir_core::digest::ContentDigest;
use svalnir_core::file::{DeviceNumber, FileObjectEvidence, InodeNumber, LosslessPath};
use svalnir_core::id::{
    BootId, ClockDomainId, OperationId, PlanId, PrivilegeGrantId, RequestId, RootId, RuleId,
    RuleRevisionId, StepId, TargetId,
};
use svalnir_core::process::Uid;
use svalnir_core::quantity::{Bytes, EntryCount, Nanoseconds};
use svalnir_core::rule::RuleRef;
use svalnir_core::time::{MonotonicNanos, WallTime};
use tempfile::TempDir;

use crate::executor::FsEvictor;
use crate::request::{
    CodeIdentity, EntryTarget, EvictEntries, HelperOperation, HelperRequest, PROTOCOL_MAJOR,
    PROTOCOL_MINOR, ProtocolVersion, QueryStepStatus, RequestValidity, StepCorrelation,
    SupportedProtocols,
};
use crate::response::{
    EntryReport, HelperResponse, RefusalReport, Rejection, ResponseBody, StepReport,
    decode_response,
};
use crate::service::{ClockSource, ClockUnavailable, HelperService, RecordStore, StoreError};
use crate::transport::fake::FakePeer;
use crate::transport::{Reply, RequestHandler as _};
use crate::validation::{
    ApprovedRoot, ConsumedRequest, GrantLimits, HelperClock, HelperConfig, HelperGrant,
    HelperState, RateCeiling, StepKey,
};

/// The user of the fixture grant and of the fixture peer.
pub(crate) const USER: u32 = 501;
/// A user with no grant.
pub(crate) const OTHER_USER: u32 = 502;
/// The login session of the fixture peer.
pub(crate) const SESSION: u32 = 100_001;
/// A second login session of the same user.
pub(crate) const OTHER_SESSION: u32 = 100_002;
/// The monotonic time of the fixture clock.
pub(crate) const NOW: u64 = 1_000;
/// The monotonic time at which a fixture request was made.
pub(crate) const ISSUED: u64 = NOW - 100;
/// The monotonic time at which a fixture request expires.
pub(crate) const EXPIRES: u64 = NOW + 100;
/// The bound of one fixture entry, in bytes.
pub(crate) const ENTRY_BYTES: u64 = 1 << 20;

pub(crate) fn wall(seconds: i64) -> WallTime {
    WallTime::from_unix(seconds, 0).unwrap()
}

pub(crate) fn charge(bytes: u64, items: u64) -> WorkCharge {
    WorkCharge::new(Bytes::new(bytes), EntryCount::new(items))
}

pub(crate) fn rule() -> RuleRef {
    RuleRef {
        id: RuleId::new("svalnir.helper-temporary").unwrap(),
        revision: RuleRevisionId::new("rev-1").unwrap(),
    }
}

pub(crate) fn agent_code() -> CodeIdentity {
    CodeIdentity::new("dev.po4yka.svalnir.agent", "TEAM123456").unwrap()
}

pub(crate) fn session(audit_session: u32) -> NonZeroU32 {
    NonZeroU32::new(audit_session).unwrap()
}

/// The agent of the fixture user in the fixture login session, verified.
pub(crate) fn peer() -> FakePeer {
    FakePeer::verified(agent_code(), USER, session(SESSION))
}

pub(crate) fn clock_at(monotonic: u64) -> HelperClock {
    HelperClock {
        wall: wall(1_000),
        monotonic: MonotonicNanos::new(monotonic),
        clock_domain: ClockDomainId::new("macos.clock_monotonic_raw").unwrap(),
        boot_id: BootId::new("boot_1").unwrap(),
    }
}

/// A temporary directory with one approved root in it.
pub(crate) struct Fixture {
    /// The owner of the temporary directory. `Drop` removes it.
    _directory: TempDir,
    /// The path of the approved root, with no symbolic link in it.
    pub(crate) root: PathBuf,
    /// A directory beside the root. No grant has it.
    pub(crate) outside: PathBuf,
}

impl Fixture {
    pub(crate) fn new() -> Self {
        let directory: TempDir = tempfile::tempdir().unwrap();
        // The record of a root has the path with no symbolic link. On
        // macOS the temporary directory is below `/var`, which is one.
        let base: PathBuf = fs::canonicalize(directory.path()).unwrap();
        let root: PathBuf = base.join("root");
        let outside: PathBuf = base.join("outside");
        make_directory(&root);
        make_directory(&outside);
        Self {
            _directory: directory,
            root,
            outside,
        }
    }

    /// Makes a file below the root and returns its path.
    pub(crate) fn file(&self, relative: &str) -> PathBuf {
        let path: PathBuf = self.root.join(relative);
        if let Some(parent) = path.parent() {
            make_directories(&self.root, parent);
        }
        fs::write(&path, b"regenerable").unwrap();
        path
    }

    /// The record of the root.
    pub(crate) fn approved_root(&self) -> ApprovedRoot {
        ApprovedRoot::new(
            RootId::new("root-a").unwrap(),
            &LosslessPath::from_path(&self.root).unwrap(),
            vec![rule()],
        )
        .unwrap()
    }

    /// The state of a helper with one grant of [`USER`] for the root.
    pub(crate) fn state(&self) -> HelperState {
        let grant: PrivilegeGrant = PrivilegeGrant {
            grant_id: PrivilegeGrantId::new("grant-1").unwrap(),
            generation: Generation::new(3),
            principal: Uid::new(USER),
            action_classes: vec![ActionClass::EvictRegenerableData],
            roots: vec![RootId::new("root-a").unwrap()],
            ceiling: charge(16 * ENTRY_BYTES, 16),
            allow_volatile_journal_on_critical: false,
            approved_at: wall(0),
            expires_at: Some(wall(2_000)),
            revoked: false,
        };
        let limits: GrantLimits = GrantLimits {
            max_targets: 8,
            rate: RateCeiling {
                window: Nanoseconds::new(400),
                max_requests: 16,
                work: charge(64 * ENTRY_BYTES, 64),
            },
        };
        let config: HelperConfig = HelperConfig {
            protocols: SupportedProtocols::CURRENT,
            agent: agent_code(),
            max_validity: Nanoseconds::new(500),
            record_capacity: 32,
            principal_quota: 16,
            retention: Nanoseconds::new(1_000),
        };
        let record: HelperGrant =
            HelperGrant::new(grant, vec![self.approved_root()], limits).unwrap();
        HelperState::new(config, vec![record]).unwrap()
    }

    /// The entry of a request for the object that is at `relative` now.
    pub(crate) fn entry(&self, relative: &str) -> EntryTarget {
        entry_of(&self.root.join(relative), relative)
    }
}

/// Makes one directory that only its owner can write to. The mode does not
/// depend on the file mode mask of the developer.
pub(crate) fn make_directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn make_directories(root: &Path, path: &Path) {
    let relative: &Path = path.strip_prefix(root).unwrap();
    let mut current: PathBuf = root.to_path_buf();
    for name in relative.components() {
        current.push(name);
        if !current.exists() {
            make_directory(&current);
        }
    }
}

/// The type and the native identifiers of the object at `path`, as an
/// agent observes them.
pub(crate) fn observed(path: &Path) -> (FileObjectType, FileObjectEvidence) {
    let metadata: fs::Metadata = fs::symlink_metadata(path).unwrap();
    let object_type: FileObjectType = if metadata.file_type().is_symlink() {
        FileObjectType::SymbolicLink
    } else if metadata.is_dir() {
        FileObjectType::Directory
    } else {
        FileObjectType::RegularFile
    };
    let evidence: FileObjectEvidence = FileObjectEvidence {
        device: DeviceNumber::new(i32::try_from(metadata.dev()).unwrap()),
        inode: InodeNumber::new(metadata.ino()),
    };
    (object_type, evidence)
}

/// The entry of a request for the object at `path`, with the entry path
/// `relative`.
pub(crate) fn entry_of(path: &Path, relative: &str) -> EntryTarget {
    let (object_type, evidence): (FileObjectType, FileObjectEvidence) = observed(path);
    EntryTarget {
        relative_entry: LosslessPath::from_bytes(relative).unwrap(),
        object_type,
        object: Some(evidence),
        charge: charge(ENTRY_BYTES, 1),
    }
}

/// An entry for a name that has no object. The identifiers are those of
/// an object that was there at an earlier time.
pub(crate) fn entry_of_absent(relative: &str) -> EntryTarget {
    EntryTarget {
        relative_entry: LosslessPath::from_bytes(relative).unwrap(),
        object_type: FileObjectType::RegularFile,
        object: Some(FileObjectEvidence {
            device: DeviceNumber::new(1),
            inode: InodeNumber::new(1),
        }),
        charge: charge(ENTRY_BYTES, 1),
    }
}

/// Puts a new file at `path` in place of the object that is there. The
/// new file exists before the old object goes, so the two have different
/// native identifiers.
pub(crate) fn replace_with_new_file(path: &Path) {
    let staged: PathBuf = path.with_extension("staged");
    fs::write(&staged, b"not the planned object").unwrap();
    fs::rename(&staged, path).unwrap();
}

pub(crate) fn correlation(step: &str) -> StepCorrelation {
    StepCorrelation {
        plan_id: PlanId::new("plan-1").unwrap(),
        plan_digest: ContentDigest::of_bytes(b"plan-1"),
        operation_id: OperationId::new("operation-1").unwrap(),
        step_id: StepId::new(step).unwrap(),
    }
}

pub(crate) fn step_key(step: &str) -> StepKey {
    StepKey {
        principal: Uid::new(USER),
        operation_id: OperationId::new("operation-1").unwrap(),
        step_id: StepId::new(step).unwrap(),
    }
}

/// An eviction request of `step` for `entries`, which the fixture state
/// accepts.
pub(crate) fn request(step: &str, entries: Vec<EntryTarget>) -> HelperRequest {
    HelperRequest {
        protocol: ProtocolVersion {
            major: PROTOCOL_MAJOR,
            minor: PROTOCOL_MINOR,
        },
        request_id: RequestId::new(format!("request-{step}")).unwrap(),
        correlation: correlation(step),
        validity: RequestValidity {
            clock_domain: ClockDomainId::new("macos.clock_monotonic_raw").unwrap(),
            boot_id: BootId::new("boot_1").unwrap(),
            issued_at: MonotonicNanos::new(ISSUED),
            expires_at: MonotonicNanos::new(EXPIRES),
        },
        operation: HelperOperation::EvictEntries(EvictEntries {
            grant: PrivilegeGrantRef {
                grant_id: PrivilegeGrantId::new("grant-1").unwrap(),
                generation: Generation::new(3),
            },
            root_id: RootId::new("root-a").unwrap(),
            rule: rule(),
            entries,
        }),
    }
}

/// A status query of `step`.
pub(crate) fn query(step: &str) -> HelperRequest {
    HelperRequest {
        request_id: RequestId::new(format!("query-{step}")).unwrap(),
        operation: HelperOperation::QueryStepStatus(QueryStepStatus {}),
        ..request(step, Vec::new())
    }
}

pub(crate) fn encode(request: &HelperRequest) -> Vec<u8> {
    serde_json::to_vec(request).unwrap()
}

/// What a clock hook gets: the number of the reading, from zero. Reading
/// zero is the admission of a request, and reading `n` is the gate before
/// entry `n - 1` of the same request.
pub(crate) type ClockHook = Box<dyn FnMut(u64) + Send>;

/// A clock that a test controls.
pub(crate) struct TestClock {
    monotonic: AtomicU64,
    step: u64,
    readings: AtomicU64,
    unavailable: AtomicBool,
    hook: Mutex<Option<ClockHook>>,
}

impl TestClock {
    /// A clock that stays at [`NOW`].
    pub(crate) fn fixed() -> Self {
        Self::advancing(0)
    }

    /// A clock that starts at [`NOW`] and goes `step` forward after each
    /// reading.
    pub(crate) fn advancing(step: u64) -> Self {
        Self {
            monotonic: AtomicU64::new(NOW),
            step,
            readings: AtomicU64::new(0),
            unavailable: AtomicBool::new(false),
            hook: Mutex::new(None),
        }
    }

    /// Calls `hook` at each reading, before the reading returns.
    pub(crate) fn with_hook(self, hook: ClockHook) -> Self {
        *self.hook.lock().unwrap() = Some(hook);
        self
    }

    pub(crate) fn set_unavailable(&self) {
        self.unavailable.store(true, Ordering::SeqCst);
    }

    pub(crate) fn restart_readings(&self) {
        self.readings.store(0, Ordering::SeqCst);
    }
}

impl ClockSource for TestClock {
    fn now(&self) -> Result<HelperClock, ClockUnavailable> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(ClockUnavailable);
        }
        let reading: u64 = self.readings.fetch_add(1, Ordering::SeqCst);
        if let Some(hook) = self.hook.lock().unwrap().as_mut() {
            hook(reading);
        }
        Ok(clock_at(
            self.monotonic.fetch_add(self.step, Ordering::SeqCst),
        ))
    }
}

impl ClockSource for Arc<TestClock> {
    fn now(&self) -> Result<HelperClock, ClockUnavailable> {
        self.as_ref().now()
    }
}

/// What a [`MemoryStore`] received.
#[derive(Debug, Default)]
pub(crate) struct StoreLog {
    /// The consumed steps, in the sequence of the writes.
    pub(crate) consumed: Vec<StepKey>,
    /// The results, in the sequence of the writes.
    pub(crate) results: Vec<(StepKey, StepState, Option<usize>)>,
    /// The removed steps.
    pub(crate) removed: Vec<StepKey>,
    /// Whether a write of a consumed step fails.
    pub(crate) fail_consumed: bool,
    /// Whether a write of a result fails.
    pub(crate) fail_result: bool,
}

/// A record store in memory, with failures that a test sets. It is not
/// durable: it states durability for the tests of the service only.
#[derive(Debug, Clone, Default)]
pub(crate) struct MemoryStore {
    pub(crate) log: Arc<Mutex<StoreLog>>,
}

impl RecordStore for MemoryStore {
    fn write_consumed(&mut self, request: &ConsumedRequest) -> Result<(), StoreError> {
        let mut log = self.log.lock().unwrap();
        if log.fail_consumed {
            return Err(StoreError);
        }
        log.consumed.push(request.key.clone());
        Ok(())
    }

    fn write_result(
        &mut self,
        key: &StepKey,
        state: &StepState,
        entries: Option<&[EntryReport]>,
    ) -> Result<(), StoreError> {
        let mut log = self.log.lock().unwrap();
        if log.fail_result {
            return Err(StoreError);
        }
        log.results.push((
            key.clone(),
            state.clone(),
            entries.map(<[EntryReport]>::len),
        ));
        Ok(())
    }

    fn remove(&mut self, key: &StepKey) -> Result<(), StoreError> {
        self.log.lock().unwrap().removed.push(key.clone());
        Ok(())
    }
}

/// The service of the fixture, with the filesystem executor.
pub(crate) type TestService = HelperService<MemoryStore, FsEvictor, Arc<TestClock>>;

/// A service with the fixture state, and the handles that a test reads.
pub(crate) struct Harness {
    pub(crate) fixture: Fixture,
    pub(crate) service: TestService,
    pub(crate) store: Arc<Mutex<StoreLog>>,
    pub(crate) clock: Arc<TestClock>,
}

impl Harness {
    pub(crate) fn new() -> Self {
        Self::with_clock(TestClock::fixed())
    }

    pub(crate) fn with_clock(clock: TestClock) -> Self {
        let fixture: Fixture = Fixture::new();
        let store: MemoryStore = MemoryStore::default();
        let log: Arc<Mutex<StoreLog>> = Arc::clone(&store.log);
        let clock: Arc<TestClock> = Arc::new(clock);
        let service: TestService = HelperService::new(
            fixture.state(),
            BTreeMap::new(),
            store,
            FsEvictor::new(),
            Arc::clone(&clock),
        );
        Self {
            fixture,
            service,
            store: log,
            clock,
        }
    }

    /// Sends the bytes of one request frame as `peer` and decodes the
    /// reply. Each exchange starts a new sequence of clock readings.
    pub(crate) fn send_bytes(&self, peer: &FakePeer, bytes: &[u8]) -> (HelperResponse, Reply) {
        self.clock.restart_readings();
        let reply: Reply = self.service.handle(&peer.facts(), bytes);
        (decode_response(&reply.payload).unwrap(), reply)
    }

    /// Sends one request as the fixture peer.
    pub(crate) fn send(&self, request: &HelperRequest) -> HelperResponse {
        self.send_bytes(&peer(), &encode(request)).0
    }

    /// The number of consumed steps in the state of the helper.
    pub(crate) fn consumed(&self) -> usize {
        self.service
            .with_state(|state: &HelperState| state.consumed().len())
            .unwrap()
    }
}

/// The step report of a response.
pub(crate) fn step_of(response: &HelperResponse) -> &StepReport {
    match &response.body {
        ResponseBody::Step(step) => step,
        other => panic!("the response is not a step report: {other:?}"),
    }
}

/// The refusal of a response.
pub(crate) fn refusal_of(response: &HelperResponse) -> &RefusalReport {
    match &response.body {
        ResponseBody::Refused(refusal) => refusal,
        other => panic!("the response is not a refusal: {other:?}"),
    }
}

/// The rejection of a response.
pub(crate) fn rejection_of(response: &HelperResponse) -> &Rejection {
    match &response.body {
        ResponseBody::Rejected(rejection) => rejection,
        other => panic!("the response is not a rejection: {other:?}"),
    }
}

/// The entry reports of a step report.
pub(crate) fn entries_of(step: &StepReport) -> &[EntryReport] {
    step.entries.as_deref().expect("the report has entries")
}

/// Checks that each entry report agrees with the target result rules of
/// `svalnir-core`, and that the reports are in the sequence of the
/// request.
pub(crate) fn assert_reports_agree(entries: &[EntryReport]) {
    for (position, entry) in entries.iter().enumerate() {
        assert_eq!(usize::try_from(entry.index).unwrap(), position);
        let target: TargetId = TargetId::new(format!("target-{position}")).unwrap();
        if let Err(error) = entry.to_target_result(target, Durability::Durable) {
            panic!("entry {position} does not agree with the contract: {error}: {entry:?}");
        }
    }
}
