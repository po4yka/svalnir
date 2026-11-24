//! Reads the `[[cleanup.caches.locations]]` tables: a cache location that
//! the user gives to a reviewed rule (`docs/POLICY_SPEC.md` section 3,
//! `docs/CLEANUP_RULES.md` section 4, "Configured cache locations").
//!
//! The configuration of Svalnir reads no environment variable and runs no
//! tool of a producer, so a cache that `CARGO_HOME`, `UV_CACHE_DIR`, or a
//! similar variable moves is not found. The user names the location here.
//! The validation checks the grammar only: the rule, the shape of the path,
//! and the bounds. The checks of a root (the owner, the filesystem, the
//! protected locations, the marker of the producer, and a Git work tree) run
//! at each discovery.

use std::collections::BTreeSet;

use super::finding::FindingCode;
use super::path::{ConfigPath, PathBase};
use super::reader::{Context, Read, TableReader};
use super::schema::CacheLocation;

/// The largest number of `[[cleanup.caches.locations]]` tables.
pub const MAX_CACHE_LOCATIONS: usize = 64;

/// The largest number of locations of one clear rule.
const MAX_CLEAR_LOCATIONS: usize = 16;

/// The rules that support a configured location, each with the largest
/// number of locations. A rule with an owner operation acts on one scope
/// root, so it has one location, which takes the place of its default root;
/// a clear rule has its default roots and each configured root.
///
/// `mise.installs` and the clear rules `nuget.http-cache` and
/// `swiftpm.cache` are not in the list: no fixed variable or argument of
/// their command names the location, or the producer has no variable for it.
pub const CACHE_LOCATION_RULES: [(&str, usize); 22] = [
    ("cargo.registry-cache", MAX_CLEAR_LOCATIONS),
    ("gradle.caches", MAX_CLEAR_LOCATIONS),
    ("maven.repository", MAX_CLEAR_LOCATIONS),
    ("rubygems.cache", MAX_CLEAR_LOCATIONS),
    ("deno.remote", MAX_CLEAR_LOCATIONS),
    ("deno.npm", MAX_CLEAR_LOCATIONS),
    ("deno.gen", MAX_CLEAR_LOCATIONS),
    ("nuget.packages", MAX_CLEAR_LOCATIONS),
    ("zig.global-cache", MAX_CLEAR_LOCATIONS),
    ("hex.packages", MAX_CLEAR_LOCATIONS),
    ("rebar3.hex", MAX_CLEAR_LOCATIONS),
    ("bun.cache", MAX_CLEAR_LOCATIONS),
    ("yarn.berry-cache", MAX_CLEAR_LOCATIONS),
    ("mise.cache", 1),
    ("uv.cache", 1),
    ("pnpm.content-store", 1),
    ("go.build-cache", 1),
    ("go.module-cache", 1),
    ("homebrew.cleanup", 1),
    ("npm.content-cache", 1),
    ("yarn.cache", 1),
    ("pip.cache", 1),
];

/// Why `path` is not a location, or `None`: the root `/` and the home
/// directory itself are not.
fn path_problem(path: &ConfigPath) -> Option<&'static str> {
    if path.components().next().is_none() {
        return Some(match path.base() {
            PathBase::Root => "must not be the root directory",
            PathBase::Home => "must not be the home directory itself",
        });
    }
    None
}

/// The value of a required key, or a finding.
fn required<'a>(
    context: &mut Context,
    read: Read<(String, &'a str)>,
    path: &str,
) -> Option<(String, &'a str)> {
    match read {
        Read::Valid(value) => Some(value),
        Read::Absent => {
            context.report(FindingCode::MissingKey, path, "the key is required");
            None
        }
        Read::Invalid => None,
    }
}

/// Reads `locations` of `[cleanup.caches]`. A table with a finding is left
/// out, and the other tables are read.
pub(super) fn read_locations(
    context: &mut Context,
    table: &mut TableReader<'_>,
) -> Vec<CacheLocation> {
    let tables: Vec<TableReader<'_>> = table.table_array(context, "locations", MAX_CACHE_LOCATIONS);
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut locations: Vec<CacheLocation> = Vec::new();
    for mut entry in tables {
        let rule_key: String = entry.key_path("rule");
        let path_key: String = entry.key_path("path");
        let rule: Read<(String, &str)> = entry.text(context, "rule");
        let path: Read<(String, &str)> = entry.text(context, "path");
        entry.finish(context);
        let rule: Option<(String, &str)> = required(context, rule, &rule_key);
        let path: Option<(String, &str)> = required(context, path, &path_key);
        let (Some((_, rule_text)), Some((_, path_text))) = (rule, path) else {
            continue;
        };
        let Some((id, limit)) = CACHE_LOCATION_RULES
            .iter()
            .find(|(id, _)| *id == rule_text)
            .copied()
        else {
            context.report(
                FindingCode::UnknownValue,
                &rule_key,
                "must be a rule that supports a configured cache location",
            );
            continue;
        };
        let parsed: ConfigPath = match ConfigPath::parse(path_text) {
            Ok(parsed) => parsed,
            Err(error) => {
                context.report(FindingCode::InvalidPath, &path_key, error.to_string());
                continue;
            }
        };
        if let Some(problem) = path_problem(&parsed) {
            context.report(FindingCode::InvalidPath, &path_key, problem);
            continue;
        }
        if !seen.insert((id.to_owned(), parsed.to_string().to_ascii_lowercase())) {
            context.report(
                FindingCode::DuplicateIdentifier,
                &path_key,
                "an earlier table gives this rule the same location",
            );
            continue;
        }
        if locations.iter().filter(|known| known.rule == id).count() >= limit {
            context.report(
                FindingCode::TooManyEntries,
                &rule_key,
                format!("this rule accepts at most {limit} location(s)"),
            );
            continue;
        }
        locations.push(CacheLocation {
            rule: id.to_owned(),
            path: parsed,
        });
    }
    locations
}
