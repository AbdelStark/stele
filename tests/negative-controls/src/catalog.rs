//! RFC-0002 §§6–7 — catalog parsing and execution-backed coverage.
use std::collections::BTreeSet;

/// A single control id; catalog ranges expand to individual entries.
#[derive(Debug)]
pub struct Entry<'a> {
    /// Numeric suffix of NC-xxxx.
    pub id: u16,
    /// Binding named in the catalog.
    pub binding: &'a str,
    /// Governing RFC section.
    pub rfc: &'a str,
    /// Intended one-value mutation.
    pub tamper: &'a str,
    /// Exact error name for implemented controls; may be empty for planned rows.
    pub expected_error: &'a str,
    /// Whether the catalog claims this control is implemented.
    pub done: bool,
}

/// A malformed or ambiguous catalog entry.
#[derive(Debug, PartialEq, Eq)]
pub struct CatalogError {
    /// One-based source line, or zero for an empty catalog.
    pub line: usize,
    /// Stable reason for rejection.
    pub reason: &'static str,
}

fn number(text: &str) -> Option<u16> {
    if text.len() == 4 && text.bytes().all(|b| b.is_ascii_digit()) {
        text.parse().ok()
    } else {
        None
    }
}

/// Parse the six-column catalog; reject duplicate ids and unsupported statuses.
pub fn parse(text: &str) -> Result<Vec<Entry<'_>>, CatalogError> {
    let mut entries = Vec::new();
    let mut ids = BTreeSet::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.starts_with("NC-") {
            return Err(CatalogError {
                line: index + 1,
                reason: "row must start with a pipe",
            });
        }
        if !line.starts_with('|')
            || line == "| NC-id | Binding | RFC § | Tamper | Expected error | Status |"
            || (line.contains('-') && line.chars().all(|c| matches!(c, '|' | '-' | ':' | ' ')))
        {
            continue;
        }
        let error = |reason| CatalogError {
            line: index + 1,
            reason,
        };
        if line.len() < 2 || !line.ends_with('|') {
            return Err(error("unterminated row"));
        }
        let cells: Vec<_> = line[1..line.len() - 1].split('|').map(str::trim).collect();
        if cells.len() != 6 || cells[1..4].iter().any(|cell| cell.is_empty()) {
            return Err(error("expected six columns with binding, RFC, and tamper"));
        }
        let done = match cells[5] {
            "todo" => false,
            "done" => true,
            _ => return Err(error("unknown status")),
        };
        let expected_error = cells[4].trim_matches('`');
        if done && expected_error.is_empty() {
            return Err(error("implemented control needs an expected error"));
        }
        let suffix = cells[0].strip_prefix("NC-").ok_or(error("invalid id"))?;
        let (start, end) = suffix.split_once('–').unwrap_or((suffix, suffix));
        let start = number(start).ok_or(error("invalid range start"))?;
        let end = number(end).ok_or(error("invalid range end"))?;
        if start > end {
            return Err(error("reversed range"));
        }
        for id in start..=end {
            if !ids.insert(id) {
                return Err(error("duplicate id"));
            }
            entries.push(Entry {
                id,
                binding: cells[1],
                rfc: cells[2],
                tamper: cells[3],
                expected_error,
                done,
            });
        }
    }
    if entries.is_empty() {
        return Err(CatalogError {
            line: 0,
            reason: "empty catalog",
        });
    }
    Ok(entries)
}

/// An executable control, registered explicitly rather than inferred from a filename.
pub struct RegisteredControl {
    /// Id matched against the catalog.
    pub id: u16,
    /// Error name matched against the catalog before execution.
    pub expected_error: &'static str,
    /// Runs honest acceptance and exact rejection through `check_control`.
    pub run: fn() -> Result<(), String>,
}

/// Execute every registration before crediting coverage. Planned rows remain gaps.
/// A `done` row without a successful registered control is an error, not coverage.
pub fn report(entries: &[Entry<'_>], controls: &[RegisteredControl]) -> Result<String, String> {
    let mut passed = BTreeSet::new();
    for control in controls {
        let entry = entries
            .iter()
            .find(|entry| entry.id == control.id)
            .ok_or_else(|| format!("NC-{:04}: registration missing from catalog", control.id))?;
        if !entry.done
            || entry.expected_error != control.expected_error
            || !passed.insert(control.id)
        {
            return Err(format!(
                "NC-{:04}: registration disagrees with catalog or is duplicated",
                control.id
            ));
        }
        (control.run)().map_err(|error| format!("NC-{:04}: {error}", control.id))?;
    }
    let mut bindings = BTreeSet::new();
    let mut covered = BTreeSet::new();
    let mut output = String::new();
    for entry in entries {
        let accepted_control = passed.contains(&entry.id);
        if entry.done && !accepted_control {
            return Err(format!(
                "NC-{:04}: done without an executable control",
                entry.id
            ));
        }
        bindings.insert(entry.binding);
        if accepted_control {
            covered.insert(entry.binding);
        }
        output.push_str(&format!(
            "NC-{:04} | {} | {} | {}\n",
            entry.id,
            entry.binding,
            entry.rfc,
            if accepted_control {
                "passed"
            } else {
                "MISSING"
            }
        ));
    }
    output.push_str(&format!(
        "Catalog coverage: {}/{} bindings; {}/{} controls.\n",
        covered.len(),
        bindings.len(),
        passed.len(),
        entries.len()
    ));
    Ok(output)
}
