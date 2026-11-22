//! Reads the `[[cleanup.projects.layouts]]` tables: the layouts of
//! `project.dependency-directory` that the user supplies
//! (`docs/POLICY_SPEC.md` section 3, `docs/CLEANUP_RULES.md` section 12).
//!
//! A layout is a parameter of the reviewed rule. The validation accepts only
//! a plain relative directory of one or two names, one or more project
//! markers, and bounded lists, so that a layout cannot name a path outside a
//! project, a version-control directory, or a protected location of the
//! home directory. The checks of the rule apply to each unit of a layout
//! unchanged.

use std::collections::BTreeSet;
use std::time::Duration;

use super::finding::FindingCode;
use super::reader::{Context, Read, TableReader};
use super::schema::{
    BUILT_IN_LAYOUT_NAMES, KEPT_OUT_LAYOUT_NAMES, MAX_LAYOUT_ENTRIES, MAX_QUIET_PERIOD,
    MAX_USER_LAYOUTS, MIN_QUIET_PERIOD, PROTECTED_HOME_NAMES, SKIPPED_DIRECTORY_NAMES, UserLayout,
};

/// The largest length of one name, in bytes: the name limit of APFS.
const MAX_NAME_BYTES: usize = 255;

/// The largest number of components of `directory`.
const MAX_DIRECTORY_COMPONENTS: usize = 2;

/// The largest number of components of a protected path.
const MAX_PROTECTED_COMPONENTS: usize = 4;

/// Whether a name of the document is one of `names`, with the case of ASCII
/// letters ignored: a volume that ignores case finds `.GIT` as `.git`.
fn is_one_of(name: &str, names: &[&str]) -> bool {
    names.iter().any(|known| known.eq_ignore_ascii_case(name))
}

/// Why `name` is not a plain name of a directory entry, or `None`. With
/// `pattern`, `*` and `?` are permitted.
fn name_problem(name: &str, pattern: bool) -> Option<&'static str> {
    if name.is_empty() || name == "." || name == ".." {
        return Some("a component is empty, `.`, or `..`");
    }
    if name.len() > MAX_NAME_BYTES {
        return Some("a component is longer than 255 bytes");
    }
    if name.chars().any(char::is_control) {
        return Some("a component has a control character");
    }
    if name.contains(['\\', '[', ']']) {
        return Some("a component has `\\`, `[`, or `]`");
    }
    if name.starts_with('~') {
        return Some("the path must be relative to the project directory, with no `~`");
    }
    if !pattern && name.contains(['*', '?']) {
        return Some(
            "a component is a pattern; only a marker or a protected path can have `*` or `?`",
        );
    }
    None
}

/// Reads `directory`. `None` when it is absent or has a finding.
fn read_directory(
    context: &mut Context,
    table: &mut TableReader<'_>,
    seen: &mut BTreeSet<String>,
) -> Option<String> {
    let read = table.text(context, "directory");
    let (path, text) = table.require(context, "directory", read)?;
    let report = |context: &mut Context, message: &str| {
        context.report(FindingCode::InvalidPath, &path, message);
    };
    if text.starts_with('/') {
        report(context, "must be relative to the project directory");
        return None;
    }
    let components: Vec<&str> = text.split('/').collect();
    if components.len() > MAX_DIRECTORY_COMPONENTS {
        report(
            context,
            "must be one name, or two names with `/` between them",
        );
        return None;
    }
    for component in &components {
        if let Some(problem) = name_problem(component, false) {
            report(context, problem);
            return None;
        }
        if is_one_of(component, &SKIPPED_DIRECTORY_NAMES) {
            report(
                context,
                "names a version-control or cache directory that the walk does not enter",
            );
            return None;
        }
        if is_one_of(component, &PROTECTED_HOME_NAMES) {
            report(context, "names a protected location of the home directory");
            return None;
        }
    }
    // The first name decides the overlap: a layout of the configuration
    // that starts with the directory of a built-in layout, or with the
    // first name of a built-in directory of two names, would have units in
    // or around the units of that layout.
    let first: &str = components.first().copied().unwrap_or(text);
    if is_one_of(first, &BUILT_IN_LAYOUT_NAMES) {
        report(
            context,
            "starts with the directory of a built-in layout; a layout of the configuration cannot overlap it",
        );
        return None;
    }
    if is_one_of(first, &KEPT_OUT_LAYOUT_NAMES) {
        report(
            context,
            "names a directory that the rule keeps out, because a removal can lose data that no tool makes again",
        );
        return None;
    }
    if !seen.insert(text.to_ascii_lowercase()) {
        context.report(
            FindingCode::DuplicateIdentifier,
            &path,
            "an earlier layout has the same `directory`",
        );
        return None;
    }
    Some(text.to_owned())
}

/// Reads a list of names or paths. `None` when the list has a finding.
fn read_entries(
    context: &mut Context,
    read: Read<Vec<(String, &str)>>,
    path: &str,
    check: impl Fn(&str) -> Option<&'static str>,
) -> Option<Vec<String>> {
    let entries: Vec<(String, &str)> = match read {
        Read::Absent => Vec::new(),
        Read::Invalid => return None,
        Read::Valid(entries) => entries,
    };
    if entries.len() > MAX_LAYOUT_ENTRIES {
        context.report(
            FindingCode::TooManyEntries,
            path,
            format!("must have no more than {MAX_LAYOUT_ENTRIES} entries"),
        );
        return None;
    }
    let mut accepted: Vec<String> = Vec::with_capacity(entries.len());
    let mut complete: bool = true;
    for (entry_path, text) in entries {
        if let Some(problem) = check(text) {
            context.report(FindingCode::InvalidPath, &entry_path, problem);
            complete = false;
        } else {
            accepted.push(text.to_owned());
        }
    }
    complete.then_some(accepted)
}

/// Why `marker` is not a project marker, or `None`.
fn marker_problem(marker: &str) -> Option<&'static str> {
    if marker.contains('/') {
        return Some("a marker is one name in the project directory, with no `/`");
    }
    if let Some(problem) = name_problem(marker, true) {
        return Some(problem);
    }
    // A pattern with no specific literal part, such as `*`, `*.*`, `a*`, or
    // `*e`, matches almost each file, so the layout would be a name alone.
    if marker.contains(['*', '?']) && !has_specific_literal(marker) {
        return Some(
            "a pattern marker must have a literal part of two or more characters that is not only `.`",
        );
    }
    if is_one_of(marker, &SKIPPED_DIRECTORY_NAMES) {
        return Some("a version-control or cache name is not a project marker");
    }
    None
}

/// Whether `pattern` has a run of two or more bytes with no `*` and no
/// `?` that is not only `.`, for example `.csproj` of `*.csproj`.
fn has_specific_literal(pattern: &str) -> bool {
    pattern
        .split(['*', '?'])
        .any(|literal| literal.len() >= 2 && literal.bytes().any(|byte| byte != b'.'))
}

/// Why `path` is not a protected path, or `None`.
fn protected_problem(path: &str) -> Option<&'static str> {
    if path.starts_with('/') {
        return Some("a protected path must be relative to the unit");
    }
    let components: Vec<&str> = path.split('/').collect();
    if components.len() > MAX_PROTECTED_COMPONENTS {
        return Some("a protected path has more than 4 components");
    }
    components
        .iter()
        .find_map(|component| name_problem(component, true))
}

/// Reads one layout. `None` when a required key is absent or a key has a
/// finding.
fn read_layout(
    context: &mut Context,
    mut table: TableReader<'_>,
    seen: &mut BTreeSet<String>,
) -> Option<UserLayout> {
    let directory: Option<String> = read_directory(context, &mut table, seen);

    let markers_path: String = table.key_path("markers");
    let markers_read = table.text_list(context, "markers");
    let markers: Option<Vec<String>> = match markers_read {
        Read::Absent => {
            context.report(
                FindingCode::MissingKey,
                &markers_path,
                "the key is required",
            );
            None
        }
        read => read_entries(context, read, &markers_path, marker_problem),
    };
    let markers: Option<Vec<String>> = match markers {
        Some(markers) if markers.is_empty() => {
            context.report(
                FindingCode::InvalidPath,
                &markers_path,
                "must name one or more project markers; a name alone is not sufficient",
            );
            None
        }
        other => other,
    };

    let inner_marker: Option<Option<String>> = match table.text(context, "inner_marker") {
        Read::Absent => Some(None),
        Read::Invalid => None,
        Read::Valid((path, text)) => {
            let problem: Option<&'static str> = if text.contains('/') {
                Some("the inner marker is one name in the unit, with no `/`")
            } else {
                name_problem(text, false)
            };
            if let Some(problem) = problem {
                context.report(FindingCode::InvalidPath, &path, problem);
                None
            } else {
                Some(Some(text.to_owned()))
            }
        }
    };

    let protected_path: String = table.key_path("protected");
    let protected_read = table.text_list(context, "protected");
    let protected: Option<Vec<String>> =
        read_entries(context, protected_read, &protected_path, protected_problem);

    let quiet_path: String = table.key_path("quiet_period");
    let quiet_period: Option<Option<Duration>> = match table.duration(context, "quiet_period") {
        Read::Absent => Some(None),
        Read::Invalid => None,
        Read::Valid(period) if !(MIN_QUIET_PERIOD..=MAX_QUIET_PERIOD).contains(&period) => {
            context.report(
                FindingCode::OutOfRange,
                &quiet_path,
                "must be from 1h to 90d",
            );
            None
        }
        Read::Valid(period) => Some(Some(period)),
    };
    table.finish(context);

    Some(UserLayout {
        directory: directory?,
        markers: markers?,
        inner_marker: inner_marker?,
        protected: protected?,
        quiet_period: quiet_period?,
    })
}

/// Reads the `layouts` array of tables of `[cleanup.projects]`, at most
/// [`MAX_USER_LAYOUTS`] tables.
pub(super) fn read_layouts(context: &mut Context, table: &mut TableReader<'_>) -> Vec<UserLayout> {
    let tables: Vec<TableReader<'_>> = table.table_array(context, "layouts", MAX_USER_LAYOUTS);
    let mut seen: BTreeSet<String> = BTreeSet::new();
    tables
        .into_iter()
        .filter_map(|layout| read_layout(context, layout, &mut seen))
        .collect()
}
