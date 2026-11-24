//! Reads the `[[cleanup.projects.layouts]]` tables: the layouts of
//! `project.dependency-directory` that the user supplies
//! (`docs/POLICY_SPEC.md` section 3, `docs/CLEANUP_RULES.md` section 12).
//!
//! A layout is a parameter of the reviewed rule. The validation accepts only
//! a plain relative directory of one to three names, whose first name can
//! be a pattern, one or more project markers, and bounded lists, so that a
//! layout cannot name a path outside a project, a version-control or cache
//! directory, a name that the rule keeps out, or a protected location of
//! the home directory. The checks of the rule apply to each unit of a
//! layout unchanged.

use std::collections::BTreeSet;
use std::time::Duration;

use super::finding::FindingCode;
use super::path::{ConfigPath, PathBase};
use super::reader::{Context, Read, TableReader};
use super::schema::{
    KEPT_OUT_LAYOUT_NAMES, MAX_CLAUDE_CONFIG_DIRS, MAX_LAYOUT_DIRECTORY_NAMES, MAX_LAYOUT_ENTRIES,
    MAX_MARKER_COMPONENTS, MAX_QUIET_PERIOD, MAX_SEARCH_ROOTS, MAX_USER_LAYOUTS, MIN_QUIET_PERIOD,
    PROTECTED_HOME_NAMES, SKIPPED_DIRECTORY_NAMES, UserLayout,
};

/// The largest length of one name, in bytes: the name limit of APFS.
const MAX_NAME_BYTES: usize = 255;

/// The largest number of components of a search root.
const MAX_SEARCH_ROOT_COMPONENTS: usize = 16;

/// The largest number of components of a protected path.
const MAX_PROTECTED_COMPONENTS: usize = 4;

/// Whether a name of the document is one of `names`, with the case of ASCII
/// letters ignored: a volume that ignores case finds `.GIT` as `.git`.
fn is_one_of(name: &str, names: &[&str]) -> bool {
    names.iter().any(|known| known.eq_ignore_ascii_case(name))
}

/// Whether `name` matches `pattern`: `*` matches each sequence of bytes,
/// also an empty one, `?` matches one byte, and each other byte matches
/// itself. With `fold`, the case of ASCII letters is ignored.
///
/// The project rule compares a marker and the first name of a layout with
/// the case kept. The validation compares a pattern with the names that it
/// refuses with the case ignored, so that it fails closed on a volume that
/// ignores case.
#[must_use]
pub fn glob_matches(pattern: &[u8], name: &[u8], fold: bool) -> bool {
    let same = |left: u8, right: u8| {
        if fold {
            left.eq_ignore_ascii_case(&right)
        } else {
            left == right
        }
    };
    let (mut at_pattern, mut at_name): (usize, usize) = (0, 0);
    // The position after the last `*`, and the name position that it
    // matched up to.
    let mut star: Option<(usize, usize)> = None;
    while at_name < name.len() {
        match (pattern.get(at_pattern), name.get(at_name)) {
            (Some(b'*'), _) => {
                at_pattern += 1;
                star = Some((at_pattern, at_name));
            }
            (Some(&byte), Some(&found)) if byte == b'?' || same(byte, found) => {
                at_pattern += 1;
                at_name += 1;
            }
            _ => match star {
                Some((after, matched)) => {
                    at_pattern = after;
                    at_name = matched + 1;
                    star = Some((after, matched + 1));
                }
                None => return false,
            },
        }
    }
    pattern
        .get(at_pattern..)
        .is_some_and(|rest| rest.iter().all(|byte| *byte == b'*'))
}

/// Whether `text` is a pattern: it has `*` or `?`.
fn is_pattern(text: &str) -> bool {
    text.contains(['*', '?'])
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
    if components.len() > MAX_LAYOUT_DIRECTORY_NAMES {
        report(
            context,
            "must be one, two, or three names with `/` between them",
        );
        return None;
    }
    let first: &str = components.first().copied().unwrap_or(text);
    for (index, component) in components.iter().enumerate() {
        // Only the first name can be a pattern.
        if let Some(problem) = name_problem(component, index == 0) {
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
        // A name that the rule keeps out is refused at each position, so
        // that `infra/.terraform` cannot take all of `.terraform`.
        if is_one_of(component, &KEPT_OUT_LAYOUT_NAMES) {
            report(
                context,
                "names a directory that the rule keeps out, because a removal can lose data that no tool makes again",
            );
            return None;
        }
    }
    if let Some(problem) = pattern_name_problem(first) {
        report(context, problem);
        return None;
    }
    // A first name of a layout of the table is permitted: the layouts of
    // the table come first, and a unit that is, holds, or is in an earlier
    // unit is refused (`overlaps_unit`). The names that the rule keeps out
    // stay refused above.
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

/// Why the pattern `first`, the first name of a `directory`, is not
/// accepted, or `None` for a name that is not a pattern.
///
/// A pattern with no specific literal part, such as `*` or `*.*`, matches
/// almost each name. A pattern that can match a name of the skip list, a
/// name that the rule keeps out, or a protected name of the home directory
/// would make such a directory a unit. The comparisons ignore the case of
/// ASCII letters.
fn pattern_name_problem(first: &str) -> Option<&'static str> {
    if !is_pattern(first) {
        return None;
    }
    if !has_specific_literal(first) {
        return Some(
            "a pattern name must have a literal part of two or more characters that is not only `.`",
        );
    }
    let matches = |names: &[&str]| {
        names
            .iter()
            .any(|name| glob_matches(first.as_bytes(), name.as_bytes(), true))
    };
    if matches(&SKIPPED_DIRECTORY_NAMES)
        || matches(&KEPT_OUT_LAYOUT_NAMES)
        || matches(&PROTECTED_HOME_NAMES)
    {
        return Some(
            "a pattern name can match a version-control or cache directory, a name that the rule keeps out, or a protected location",
        );
    }
    None
}

/// Why `marker` is not a project marker, or `None`.
///
/// A marker is a path relative to the directory that holds the first name
/// of `directory`, of at most [`MAX_MARKER_COMPONENTS`] names. A marker
/// that ends with `/` is a directory. A marker of one name can be a
/// pattern; a marker of more names has no pattern.
fn marker_problem(marker: &str) -> Option<&'static str> {
    let path: &str = marker.strip_suffix('/').unwrap_or(marker);
    if path.starts_with('/') {
        return Some("a marker must be relative to the project directory");
    }
    let components: Vec<&str> = path.split('/').collect();
    if components.len() > MAX_MARKER_COMPONENTS {
        return Some("a marker has more than 4 names");
    }
    let single: bool = components.len() == 1;
    if let Some(problem) = components
        .iter()
        .find_map(|component| name_problem(component, single))
    {
        return Some(if !single && is_pattern(path) {
            "a marker of more than one name has no pattern"
        } else {
            problem
        });
    }
    // A pattern with no specific literal part, such as `*`, `*.*`, `a*`, or
    // `*e`, matches almost each file, so the layout would be a name alone.
    if is_pattern(path) && !has_specific_literal(path) {
        return Some(
            "a pattern marker must have a literal part of two or more characters that is not only `.`",
        );
    }
    if components
        .iter()
        .any(|component| is_one_of(component, &SKIPPED_DIRECTORY_NAMES))
    {
        return Some("a version-control or cache name is not a project marker");
    }
    None
}

/// Whether the first name of `marker` can be the first name of
/// `directory`, so that the marker is the unit or is in it. Either name can
/// be a pattern; the comparison ignores the case of ASCII letters. When
/// both are patterns, the answer is always yes.
fn marker_is_in_unit(directory: &str, marker: &str) -> bool {
    let first = |text: &str| text.split('/').next().unwrap_or(text).to_owned();
    let (unit, marker): (String, String) = (first(directory), first(marker));
    // Two patterns can match one name although neither matches the other
    // as text, for example `gen-*` and `*-out` for `gen-x-out`.
    if is_pattern(&unit) && is_pattern(&marker) {
        return true;
    }
    glob_matches(unit.as_bytes(), marker.as_bytes(), true)
        || glob_matches(marker.as_bytes(), unit.as_bytes(), true)
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
    // A marker in the unit itself would make the name of the directory
    // sufficient, for example `build/` for the directory `build`.
    let markers: Option<Vec<String>> = match (&directory, markers) {
        (Some(directory), Some(markers))
            if markers
                .iter()
                .any(|marker| marker_is_in_unit(directory, marker)) =>
        {
            context.report(
                FindingCode::InvalidPath,
                &markers_path,
                "a marker must not be in the directory of the layout; a name alone is not sufficient",
            );
            None
        }
        (_, markers) => markers,
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

/// Reads `search_roots` of `[cleanup.projects]`: plain relative paths below
/// the home directory, at most [`MAX_SEARCH_ROOTS`]. `None` when the key is
/// absent or has a finding.
pub(super) fn read_search_roots(
    context: &mut Context,
    table: &mut TableReader<'_>,
) -> Option<Vec<String>> {
    let Read::Valid(items) = table.text_list(context, "search_roots") else {
        return None;
    };
    if items.len() > MAX_SEARCH_ROOTS {
        context.report(
            FindingCode::TooManyEntries,
            &table.key_path("search_roots"),
            format!("must have no more than {MAX_SEARCH_ROOTS} entries"),
        );
        return None;
    }
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut roots: Vec<String> = Vec::with_capacity(items.len());
    let mut complete: bool = true;
    for (item_path, text) in items {
        let problem: Option<&'static str> = if text.starts_with('/') {
            Some("must be relative to the home directory")
        } else if text.split('/').count() > MAX_SEARCH_ROOT_COMPONENTS {
            Some("must have no more than 16 components")
        } else {
            text.split('/')
                .find_map(|component| name_problem(component, false))
        };
        if let Some(problem) = problem {
            context.report(FindingCode::InvalidPath, &item_path, problem);
            complete = false;
            continue;
        }
        if !seen.insert(text.to_ascii_lowercase()) {
            context.report(
                FindingCode::DuplicateIdentifier,
                &item_path,
                "an earlier search root has the same path",
            );
            complete = false;
            continue;
        }
        roots.push(text.to_owned());
    }
    complete.then_some(roots)
}

/// Reads `claude_config_dirs` of `[cleanup.projects]`: absolute paths, at
/// most [`MAX_CLAUDE_CONFIG_DIRS`]. `None` when the key is absent or has a
/// finding.
pub(super) fn read_claude_config_dirs(
    context: &mut Context,
    table: &mut TableReader<'_>,
) -> Option<Vec<ConfigPath>> {
    let Read::Valid(items) = table.text_list(context, "claude_config_dirs") else {
        return None;
    };
    if items.len() > MAX_CLAUDE_CONFIG_DIRS {
        context.report(
            FindingCode::TooManyEntries,
            &table.key_path("claude_config_dirs"),
            format!("must have no more than {MAX_CLAUDE_CONFIG_DIRS} entries"),
        );
        return None;
    }
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut dirs: Vec<ConfigPath> = Vec::with_capacity(items.len());
    let mut complete: bool = true;
    for (item_path, text) in items {
        let parsed: ConfigPath = match ConfigPath::parse(text) {
            Ok(parsed) if parsed.base() == PathBase::Root => parsed,
            Ok(_) => {
                context.report(FindingCode::InvalidPath, &item_path, "must start with `/`");
                complete = false;
                continue;
            }
            Err(error) => {
                context.report(FindingCode::InvalidPath, &item_path, error.to_string());
                complete = false;
                continue;
            }
        };
        if !seen.insert(parsed.to_string().to_ascii_lowercase()) {
            context.report(
                FindingCode::DuplicateIdentifier,
                &item_path,
                "an earlier entry has the same path",
            );
            complete = false;
            continue;
        }
        dirs.push(parsed);
    }
    complete.then_some(dirs)
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
