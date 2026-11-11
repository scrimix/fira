//! The canonical sprint/task model. Both the Markdown side and the Fira side
//! convert to these types, and every diff is computed between two of them.

use chrono::NaiveDate;
use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Todo,
    InProgress,
    Done,
}

impl Status {
    /// The status marker written at the start of a task heading.
    pub fn marker(self) -> &'static str {
        match self {
            Status::Todo => "⬜",
            Status::InProgress => "🚧",
            Status::Done => "✅",
        }
    }

    /// A canonical marker at the start of `s` (an optional U+FE0F
    /// variation selector after it included): its byte length and status.
    pub fn from_marker_prefix(s: &str) -> Option<(usize, Status)> {
        for st in [Status::Todo, Status::InProgress, Status::Done] {
            if let Some(rest) = s.strip_prefix(st.marker()) {
                let vs = if rest.starts_with('\u{FE0F}') { '\u{FE0F}'.len_utf8() } else { 0 };
                return Some((st.marker().len() + vs, st));
            }
        }
        None
    }

    pub fn fira(self) -> &'static str {
        match self {
            Status::Todo => "todo",
            Status::InProgress => "in_progress",
            Status::Done => "done",
        }
    }

    /// `backlog` is deprecated: it reads as `todo`, and the CLI never
    /// writes it.
    pub fn from_fira(s: &str) -> Status {
        match s {
            "in_progress" => Status::InProgress,
            "done" => Status::Done,
            _ => Status::Todo,
        }
    }

    pub fn label(self) -> &'static str {
        self.fira()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Subtask {
    pub title: String,
    pub done: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Task {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub status: Status,
    pub sprint: Option<Uuid>,
    /// Sorted, deduplicated tag titles.
    pub tags: Vec<String>,
    pub assignee: Option<Uuid>,
    pub estimate_min: Option<i32>,
    pub subtasks: Vec<Subtask>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Sprint {
    pub id: Uuid,
    pub title: String,
    pub dates: Option<(NaiveDate, NaiveDate)>,
    pub track: Option<String>,
    pub tags: Vec<String>,
    pub assignee: Option<Uuid>,
}

pub fn normalize_tags(mut tags: Vec<String>) -> Vec<String> {
    tags.retain(|t| !t.trim().is_empty());
    for t in tags.iter_mut() {
        *t = t.trim().to_string();
    }
    tags.sort();
    tags.dedup();
    tags
}

/// Trim blank lines at both ends and trailing whitespace; normalise CRLF.
/// Leading indentation of the first line is kept (it can be meaningful,
/// e.g. an indented code block).
pub fn normalize_text(s: &str) -> String {
    let s = s.replace("\r\n", "\n");
    let mut lines: Vec<&str> = s.split('\n').collect();
    while lines.first().is_some_and(|l| l.trim().is_empty()) {
        lines.remove(0);
    }
    while lines.last().is_some_and(|l| l.trim().is_empty()) {
        lines.pop();
    }
    lines
        .iter()
        .map(|l| l.trim_end())
        .collect::<Vec<_>>()
        .join("\n")
}

/// `4h`, `30m`, `1h30m`, `1.5h`, `90m`.
pub fn parse_estimate(s: &str) -> Result<i32, String> {
    let s = s.trim().to_ascii_lowercase();
    let err = || {
        format!("invalid estimate {s:?}; use hours and minutes like 4h, 30m or 1h30m")
    };
    if s.is_empty() {
        return Err(err());
    }
    let mut total = 0f64;
    let mut num = String::new();
    let mut saw_unit = false;
    for c in s.chars() {
        match c {
            '0'..='9' | '.' => num.push(c),
            'h' | 'm' | 'd' => {
                let n: f64 = num.parse().map_err(|_| err())?;
                total += match c {
                    'h' => n * 60.0,
                    'd' => n * 8.0 * 60.0,
                    _ => n,
                };
                num.clear();
                saw_unit = true;
            }
            _ => return Err(err()),
        }
    }
    if !num.is_empty() || !saw_unit {
        return Err(err());
    }
    Ok(total.round() as i32)
}

pub fn format_estimate(min: i32) -> String {
    let (h, m) = (min / 60, min % 60);
    match (h, m) {
        (0, m) => format!("{m}m"),
        (h, 0) => format!("{h}h"),
        (h, m) => format!("{h}h{m}m"),
    }
}

pub fn slug(title: &str) -> String {
    let mut out = String::new();
    let mut dash = false;
    for c in title.chars() {
        if c.is_alphanumeric() {
            out.extend(c.to_lowercase());
            dash = false;
        } else if !dash && !out.is_empty() {
            out.push('-');
            dash = true;
        }
        if out.chars().count() >= 60 {
            break;
        }
    }
    let out = out.trim_end_matches('-').to_string();
    if out.is_empty() {
        "untitled".into()
    } else {
        out
    }
}

/// Sprint spans follow Fira: `[starts_on, ends_on)`, both Mondays.
pub fn validate_dates(start: NaiveDate, end: NaiveDate) -> Result<(), String> {
    use chrono::Datelike;
    if end <= start {
        return Err(format!("ends_on {end} must be after starts_on {start}"));
    }
    for (name, d) in [("starts_on", start), ("ends_on", end)] {
        if d.weekday() != chrono::Weekday::Mon {
            return Err(format!(
                "{name} {d} is a {:?}; sprint dates are Mondays (the range is end-exclusive, so a two-week sprint starting 2026-11-09 ends on 2026-11-23)",
                d.weekday()
            ));
        }
    }
    Ok(())
}

pub fn format_dates(d: Option<(NaiveDate, NaiveDate)>) -> Option<String> {
    d.map(|(a, b)| format!("{a} → {b}"))
}

/// Closest known word within edit distance 2, for "did you mean".
pub fn suggest<'a>(word: &str, known: &[&'a str]) -> Option<&'a str> {
    fn dist(a: &str, b: &str) -> usize {
        let a: Vec<char> = a.chars().collect();
        let b: Vec<char> = b.chars().collect();
        let mut prev: Vec<usize> = (0..=b.len()).collect();
        for i in 1..=a.len() {
            let mut cur = vec![i; b.len() + 1];
            for j in 1..=b.len() {
                let cost = usize::from(a[i - 1] != b[j - 1]);
                cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
            }
            prev = cur;
        }
        prev[b.len()]
    }
    known
        .iter()
        .map(|k| (dist(word, k), *k))
        .filter(|(d, _)| *d <= 2)
        .min()
        .map(|(_, k)| k)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimates_round_trip() {
        for (s, m) in [("4h", 240), ("30m", 30), ("1h30m", 90), ("1.5h", 90), ("90m", 90)] {
            assert_eq!(parse_estimate(s), Ok(m), "{s}");
        }
        assert_eq!(format_estimate(240), "4h");
        assert_eq!(format_estimate(90), "1h30m");
        assert_eq!(format_estimate(45), "45m");
        assert!(parse_estimate("4").is_err());
        assert!(parse_estimate("4x").is_err());
    }

    #[test]
    fn backlog_reads_as_todo() {
        assert_eq!(Status::from_fira("backlog"), Status::Todo);
    }

    #[test]
    fn slugs() {
        assert_eq!(slug("Login redirects to the wrong page!"), "login-redirects-to-the-wrong-page");
        assert_eq!(slug("  "), "untitled");
    }

    #[test]
    fn text_normalisation_keeps_inner_blank_lines() {
        assert_eq!(normalize_text("\n\n  a\n\n\nb  \n\n"), "  a\n\n\nb");
    }

    #[test]
    fn dates_must_be_mondays() {
        let d = |s: &str| s.parse::<NaiveDate>().unwrap();
        assert!(validate_dates(d("2026-11-09"), d("2026-11-23")).is_ok());
        assert!(validate_dates(d("2026-11-09"), d("2026-11-22")).is_err());
        assert!(validate_dates(d("2026-11-23"), d("2026-11-09")).is_err());
    }
}
