//! A reader for the `info.plist` of a `DerivedData` project directory.
//!
//! The reader accepts one form only: an XML property list whose root is a
//! dictionary with scalar values. A binary property list, a nested
//! container, a comment, or an entity other than the five XML entities is
//! not accepted, and the caller then does not recognize the layout.

use std::path::PathBuf;

use svalnir_core::time::WallTime;

/// The largest number of keys of the dictionary.
const MAX_KEYS: usize = 64;

/// The two values of `info.plist` that the rule uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProjectInfo {
    /// `WorkspacePath`: the project, the workspace, or the package that
    /// the data belongs to.
    pub(super) workspace_path: PathBuf,
    /// `LastAccessedDate`.
    pub(super) last_accessed: WallTime,
}

/// The text with the five XML entities decoded. `None` for another `&`.
fn decode_entities(text: &str) -> Option<String> {
    const ENTITIES: [(&str, char); 5] = [
        ("&amp;", '&'),
        ("&lt;", '<'),
        ("&gt;", '>'),
        ("&quot;", '"'),
        ("&apos;", '\''),
    ];
    let mut decoded: String = String::with_capacity(text.len());
    let mut rest: &str = text;
    while let Some(index) = rest.find('&') {
        let (plain, entity) = rest.split_at(index);
        decoded.push_str(plain);
        let (name, character) = ENTITIES.iter().find(|(name, _)| entity.starts_with(name))?;
        decoded.push(*character);
        rest = entity.get(name.len()..)?;
    }
    decoded.push_str(rest);
    Some(decoded)
}

/// The content of the element `<name>...</name>` at the start of `text`,
/// and the text after the element.
fn element<'a>(text: &'a str, name: &str) -> Option<(&'a str, &'a str)> {
    let rest: &str = text
        .strip_prefix('<')?
        .strip_prefix(name)?
        .strip_prefix('>')?;
    let close: String = format!("</{name}>");
    let end: usize = rest.find(&close)?;
    let content: &str = rest.get(..end)?;
    if content.contains('<') {
        return None;
    }
    Some((content, rest.get(end.checked_add(close.len())?..)?))
}

/// The scalar value element at the start of `text`: its name, its
/// content, and the text after it.
fn scalar(text: &str) -> Option<(&'static str, &str, &str)> {
    for empty in ["<true/>", "<false/>"] {
        if let Some(rest) = text.strip_prefix(empty) {
            return Some(("boolean", "", rest));
        }
    }
    ["string", "date", "integer", "real", "data"]
        .into_iter()
        .find_map(|name| element(text, name).map(|(content, rest)| (name, content, rest)))
}

/// Reads `WorkspacePath` and `LastAccessedDate` from the bytes of an
/// `info.plist`. `None` when the file does not have the accepted form or
/// does not have the two values one time each.
pub(super) fn parse_project_info(bytes: &[u8]) -> Option<ProjectInfo> {
    let text: &str = std::str::from_utf8(bytes).ok()?;
    // Before the root: an XML declaration and a document type, each
    // optional, and white space.
    let mut prolog: &str = text.trim_start();
    for (open, close) in [("<?xml", "?>"), ("<!DOCTYPE", ">")] {
        if let Some(rest) = prolog.strip_prefix(open) {
            let end: usize = rest.find(close)?.checked_add(close.len())?;
            prolog = rest.get(end..)?.trim_start();
        }
    }
    let attributes: &str = prolog.strip_prefix("<plist")?;
    if !attributes.starts_with(|first: char| first == '>' || first.is_ascii_whitespace()) {
        return None;
    }
    let after_tag: &str = attributes.get(attributes.find('>')?.checked_add(1)?..)?;
    let mut rest: &str = after_tag.trim_start().strip_prefix("<dict>")?;
    let mut workspace_path: Option<PathBuf> = None;
    let mut last_accessed: Option<WallTime> = None;
    let mut keys: Vec<String> = Vec::new();
    loop {
        rest = rest.trim_start();
        if let Some(after_dict) = rest.strip_prefix("</dict>") {
            let tail: &str = after_dict.trim_start().strip_prefix("</plist>")?;
            if !tail.trim().is_empty() {
                return None;
            }
            break;
        }
        let (key, after_key) = element(rest, "key")?;
        let key: String = decode_entities(key)?;
        if keys.len() >= MAX_KEYS || keys.contains(&key) {
            return None;
        }
        let (kind, content, after_value) = scalar(after_key.trim_start())?;
        match (key.as_str(), kind) {
            ("WorkspacePath", "string") => {
                workspace_path = Some(PathBuf::from(decode_entities(content)?));
            }
            ("LastAccessedDate", "date") => last_accessed = Some(content.trim().parse().ok()?),
            // The two values have one type each.
            ("WorkspacePath" | "LastAccessedDate", _) => return None,
            _ => {}
        }
        keys.push(key);
        rest = after_value;
    }
    Some(ProjectInfo {
        workspace_path: workspace_path?,
        last_accessed: last_accessed?,
    })
}
