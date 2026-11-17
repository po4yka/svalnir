//! Tests of the path comparison. The first test compares it with the path
//! comparison of the policy module, through the public cleanup evaluation
//! of that module.

use super::{USER, clock_at};
use crate::config::{ConfigPath, ValidatedConfig, parse_and_validate};
use crate::file::LosslessPath;
use crate::id::{RuleId, TargetId, VolumeId};
use crate::plan::paths::{PathSet, is_canonical, is_canonical_relative, joins_to};
use crate::policy::{
    ActivityFact, AssumedGrants, CleanupCandidate, CleanupFacts, DiskGuardState, DiskSnapshot,
    EvaluationContext, GrantBasis, OwnerFact, ProtectionFact, ReasonDetail, RebuildCost,
    RuleReadiness, evaluate_disk_guard, plan_cleanup,
};
use crate::quantity::{Bytes, EntryCount, Nanoseconds};

/// The `[protections].excluded_paths` list of the comparison.
const EXCLUDED: [&str; 5] = [
    "~/Documents",
    "~/Library/Mobile Documents/Notes",
    "/Volumes/Work/keep",
    "/Volumes/Ünïcode/data",
    "/opt//tools/",
];

fn candidate_paths() -> Vec<Vec<u8>> {
    let texts: [&str; 30] = [
        "/",
        "/Users",
        "/Users/a",
        "/Users/a/",
        "/Users/a/Documents",
        "/Users/a/documents/Taxes",
        "/USERS/A/DOCUMENTS",
        "/Users/a/Documents2",
        "/Users/a/Doc",
        "/Users/b/Documents",
        "/Users/a/Library",
        "/Users/a/Library/Caches",
        "/Users/a/Library/Mobile Documents",
        "/Users/a/Library/Mobile Documents/Notes/x",
        "/Users/a/Library/Mobile Documents/Other",
        "/Users/a/Документы",
        "/Users/a/Library/Кэш",
        "/Volumes",
        "/Volumes/Work",
        "/Volumes/Work/keep",
        "/Volumes/Work/keeper",
        "/Volumes/Work/KEEP/deep/er",
        "/Volumes/ünïcode/DATA/x",
        "/Volumes/Unicode/data",
        "/opt/tools/bin",
        "/opt/tool",
        "/Users/a/../a/Documents",
        "/Users/./a/Library/Caches",
        "Users/a/Documents",
        "//Users//a//Documents//",
    ];
    let mut paths: Vec<Vec<u8>> = texts.iter().map(|text| text.as_bytes().to_vec()).collect();
    // Paths that are not UTF-8.
    paths.push(b"/Users/a/Docu\xffments".to_vec());
    paths.push(b"/Volumes/Work/KEEP\xff".to_vec());
    paths.push(b"/Volumes/Work/\xff/x".to_vec());
    paths
}

fn config() -> ValidatedConfig {
    let list: Vec<String> = EXCLUDED.iter().map(|path| format!("\"{path}\"")).collect();
    // The disk guard has no exclusion of its own, so each excluded path of
    // the policy evaluation comes from the `[protections]` table.
    let text: String = format!(
        "schema_version = 1\n\n[protections]\nexcluded_paths = [{}]\n\n\
         [disk_guard.exclusions]\npaths = []\n",
        list.join(", ")
    );
    let validation = parse_and_validate(&text);
    assert!(
        validation.findings().is_empty(),
        "the test configuration has findings: {:?}",
        validation.findings()
    );
    validation.config().unwrap().clone()
}

fn candidate(index: usize, path: &[u8]) -> CleanupCandidate {
    CleanupCandidate {
        target_id: TargetId::new(format!("target_{index}")).unwrap(),
        rule_id: RuleId::new("svalnir.expired-temporary").unwrap(),
        volume_id: VolumeId::new("volume_none").unwrap(),
        path: LosslessPath::from_bytes(path).unwrap(),
        work_bytes: Some(Bytes::new(1)),
        item_count: Some(EntryCount::new(1)),
        estimated_reclaimable_bytes: None,
        facts: CleanupFacts {
            rule_readiness: RuleReadiness::Ready,
            hard_protection: ProtectionFact::NotProtected,
            protected_classes: Vec::new(),
            owner: OwnerFact::RequestingUser,
            activity: ActivityFact::Inactive {
                inactive_for: Nanoseconds::new(1),
            },
            rebuild_cost: RebuildCost::Low,
        },
    }
}

#[test]
fn the_comparison_is_the_one_of_the_policy_module() {
    let config: ValidatedConfig = config();
    assert_eq!(config.disk_guard().exclusions.paths, []);
    let clock = clock_at(1_000);
    let paths: Vec<Vec<u8>> = candidate_paths();
    let snapshot: DiskSnapshot = DiskSnapshot {
        volumes: Vec::new(),
        candidates: paths
            .iter()
            .enumerate()
            .map(|(index, path)| candidate(index, path))
            .collect(),
        rule_allowances: Vec::new(),
    };
    let homes: [Option<&str>; 7] = [
        Some("/Users/a"),
        Some("/users/A"),
        None,
        Some("Users/a"),
        Some("/Users/a/"),
        Some("/Users/../Users/a"),
        Some("/"),
    ];
    for home in homes {
        let home: Option<LosslessPath> = home.map(|home| LosslessPath::from_bytes(home).unwrap());
        let context: EvaluationContext<'_> = EvaluationContext {
            config: &config,
            clock: &clock,
            grants: AssumedGrants::none(GrantBasis::Hypothetical),
            principal: USER,
            home_directory: home.as_ref(),
        };
        let evaluation =
            evaluate_disk_guard(&context, &DiskGuardState::default(), &snapshot).unwrap();
        let policy = plan_cleanup(&context, &evaluation, &snapshot);
        assert_eq!(policy.decisions.len(), paths.len());

        let set: PathSet =
            PathSet::resolve(config.protections().excluded_paths.iter(), home.as_ref());
        for (index, bytes) in paths.iter().enumerate() {
            let target_id: String = format!("target_{index}");
            let decision = policy
                .decisions
                .iter()
                .find(|decision| decision.target_id.as_str() == target_id)
                .unwrap();
            let has = |detail: ReasonDetail| {
                decision
                    .reasons
                    .iter()
                    .any(|explanation| explanation.detail == detail)
            };
            let path: LosslessPath = LosslessPath::from_bytes(bytes.clone()).unwrap();
            let label: String = format!("{} with the home {home:?}", path.display_label());
            assert_eq!(
                set.overlaps(&path),
                has(ReasonDetail::ExcludedPath),
                "{label}"
            );
            assert_eq!(
                set.unresolved,
                has(ReasonDetail::HomeDirectoryUnknown),
                "{label}"
            );
            assert_eq!(
                !is_canonical(&path),
                has(ReasonDetail::PathNotCanonical),
                "{label}"
            );
        }
    }
}

fn path(text: &str) -> LosslessPath {
    LosslessPath::from_bytes(text).unwrap()
}

#[test]
fn a_list_covers_its_entries_and_what_is_inside_them() {
    let list: [ConfigPath; 2] = [
        ConfigPath::parse("/Applications/Keep.app").unwrap(),
        ConfigPath::parse("~/bin").unwrap(),
    ];
    let home: LosslessPath = path("/Users/a");
    let set: PathSet = PathSet::resolve(list.iter(), Some(&home));
    assert!(!set.unresolved);
    for covered in [
        "/Applications/Keep.app",
        "/Applications/keep.APP/Contents/MacOS/Keep",
        "/Users/a/bin/tool",
        "/Applications/Kéép.app/x",
    ] {
        assert!(set.covers(&path(covered)), "{covered}");
    }
    for open in [
        // A parent of an entry is not inside the entry.
        "/Applications",
        "/Applications/Keep.app2/x",
        "/Users/b/bin/tool",
        "/Users/a/binary",
    ] {
        assert!(!set.covers(&path(open)), "{open}");
    }
    // `overlaps` also finds a parent of an entry.
    assert!(set.overlaps(&path("/Applications")));
    assert!(!set.overlaps(&path("/Applications/Other.app")));
}

#[test]
fn a_relative_list_compares_relative_entries() {
    let set: PathSet = PathSet::of_relative(&[path("Build/Products"), path("keep")]);
    assert!(!set.unresolved);
    for overlapping in ["keep", "KEEP/x", "Build", "build/products/Debug", "kéép"] {
        assert!(set.overlaps(&path(overlapping)), "{overlapping}");
    }
    for separate in ["Build/Intermediates", "keeper", "Index/keep"] {
        assert!(!set.overlaps(&path(separate)), "{separate}");
    }
    assert!(!PathSet::of_relative(&[]).overlaps(&path("anything")));
}

#[test]
fn a_path_is_its_root_and_then_its_relative_entry_byte_for_byte() {
    for (full, root, relative, agrees) in [
        (
            "/Users/a/Library/Caches/x",
            "/Users/a/Library/Caches",
            "x",
            true,
        ),
        (
            "/Users/a/Library/Caches/x",
            "/Users/a",
            "Library/Caches/x",
            true,
        ),
        ("/x", "/", "x", true),
        // The same last component below a different root.
        (
            "/Users/a/Library/Caches/x",
            "/Users/a/Documents",
            "x",
            false,
        ),
        // A component between the root and the entry.
        ("/a/b/c", "/a", "c", false),
        ("/a/c", "/a/b", "c", false),
        // No case is folded.
        (
            "/Users/a/Library/Caches/x",
            "/Users/a/Library/Caches",
            "X",
            false,
        ),
        (
            "/Users/a/Library/Caches/x",
            "/users/a/library/caches",
            "x",
            false,
        ),
        (
            "/Users/a/Library/Caches/x",
            "/Users/a/Library/Caches",
            "y",
            false,
        ),
        (
            "/Users/a/Library/Caches",
            "/Users/a/Library",
            "Caches/x",
            false,
        ),
    ] {
        assert_eq!(
            joins_to(&path(full), &path(root), &path(relative)),
            agrees,
            "{full}, {root}, and {relative}"
        );
    }
    for (relative, canonical) in [
        ("x", true),
        ("a/b/c", true),
        ("/x", false),
        ("a//b", false),
        ("a/", false),
        ("./a", false),
        ("a/../b", false),
        ("..", false),
    ] {
        assert_eq!(
            is_canonical_relative(&path(relative)),
            canonical,
            "{relative}"
        );
    }
}
