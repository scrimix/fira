//! Parsing sprint and single-task Markdown files.
//!
//! Parsing is lenient where editors are sloppy (blank lines around the
//! `task:` comment, `[ x ]` checkboxes) and strict where a mistake would
//! silently lose data (two `task:` comments, unknown keys, text after the
//! Subtasks list). Every parsed part keeps its byte range in the source so
//! that writes can replace exactly the bytes a change names and leave
//! everything else identical.
//!
//! The structure comes from a real CommonMark parser, so headings, lists
//! and comments inside fenced code blocks are content, not structure.

use std::ops::Range;
use std::path::PathBuf;

use chrono::NaiveDate;
use pulldown_cmark::{Event, HeadingLevel, LinkType, Options, Parser, Tag, TagEnd};
use uuid::Uuid;

use crate::model::{self, Status, Subtask};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DocKind {
    Sprint,
    Single,
}

#[derive(Debug, Clone)]
pub enum FrontValue {
    Scalar(String),
    List(Vec<String>),
}

#[derive(Debug, Clone)]
pub struct FrontLine {
    pub key: String,
    /// The whole line including its newline.
    pub range: Range<usize>,
    pub line: usize,
    pub value: FrontValue,
}

#[derive(Debug, Clone, Default)]
pub struct Frontmatter {
    /// Byte offset just after the opening `---\n`.
    pub body_start: usize,
    /// Byte offset of the closing `---` line.
    pub close_start: usize,
    /// Byte offset just after the closing `---\n`.
    pub end: usize,
    pub lines: Vec<FrontLine>,
    pub sprint_id: Option<Uuid>,
    pub dates: Option<(NaiveDate, NaiveDate)>,
    pub track: Option<String>,
    pub tags: Option<Vec<String>>,
    pub assignee: Option<String>,
}

impl Frontmatter {
    pub fn line_of(&self, key: &str) -> Option<&FrontLine> {
        self.lines.iter().find(|l| l.key == key)
    }
}

#[derive(Debug, Clone)]
pub struct Comment {
    /// The `<!-- … -->` text itself.
    pub range: Range<usize>,
    /// The comment's whole line including newline, when nothing else is
    /// on that line.
    pub own_line: Option<Range<usize>>,
    pub line: usize,
    pub id: Option<Uuid>,
    /// `None` = inherit; `Some(vec![])` = explicitly none (`tags=""`).
    pub tags: Option<Vec<String>>,
    /// `None` = inherit; `Some("")` = explicitly nobody.
    pub assignee: Option<String>,
    pub estimate: Option<i32>,
    /// Raw `key=value` tokens in source order, for `fmt`.
    pub raw: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct SubtaskSection {
    /// The `### Subtasks` line including newline.
    pub heading: Range<usize>,
    pub level: usize,
    /// The list itself (from the first item to the end of the last).
    pub list: Option<Range<usize>>,
    /// End of the section (start of the next heading or end of task).
    pub end: usize,
    pub items: Vec<Subtask>,
    /// Bullet of the first item, e.g. `- ` or `* `, reused on rewrite.
    pub bullet: String,
}

/// An inline link or image (`[a](dest)`, `![a](dest)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    /// The whole link.
    pub full: Range<usize>,
    /// The destination as written (without `<…>`).
    pub dest_range: Range<usize>,
    pub dest: String,
    pub image: bool,
}

#[derive(Debug, Clone)]
pub struct AttachmentItem {
    pub line: usize,
    pub link: Link,
}

/// The `### Attachments` section: a list of links, one per attachment.
#[derive(Debug, Clone)]
pub struct AttachmentSection {
    pub heading: Range<usize>,
    pub level: usize,
    pub list: Option<Range<usize>>,
    pub end: usize,
    pub items: Vec<AttachmentItem>,
    pub bullet: String,
}

#[derive(Debug, Clone)]
pub struct TaskBlock {
    /// From the start of the heading line to the next task heading or EOF.
    pub block: Range<usize>,
    pub line: usize,
    pub level: usize,
    /// End of the heading line, excluding the newline.
    pub heading_line_end: usize,
    /// Just after the heading line's newline.
    pub heading_end: usize,
    pub checkbox: Range<usize>,
    pub status: Status,
    pub checkbox_canonical: bool,
    pub title: String,
    pub title_range: Range<usize>,
    pub comment: Option<Comment>,
    /// End of the description region: the first of the Attachments and
    /// Subtasks headings, or the end of the task.
    pub desc_end: usize,
    pub description: String,
    /// Inline links and images in the description region.
    pub desc_links: Vec<Link>,
    pub subtasks: Option<SubtaskSection>,
    pub attachments: Option<AttachmentSection>,
}

impl TaskBlock {
    pub fn id(&self) -> Option<Uuid> {
        self.comment.as_ref().and_then(|c| c.id)
    }
}

#[derive(Debug, Clone)]
pub struct Doc {
    pub path: PathBuf,
    /// Path for messages (relative to the current directory when possible).
    pub display: String,
    pub text: String,
    pub kind: DocKind,
    pub front: Option<Frontmatter>,
    /// Sprint title: text, byte range of the text, line.
    pub title: Option<(String, Range<usize>, usize)>,
    pub tasks: Vec<TaskBlock>,
}

pub fn line_at(text: &str, offset: usize) -> usize {
    text[..offset.min(text.len())].matches('\n').count() + 1
}

fn line_bounds(text: &str, offset: usize) -> (usize, usize, usize) {
    let start = text[..offset].rfind('\n').map_or(0, |i| i + 1);
    let end = text[offset..].find('\n').map_or(text.len(), |i| offset + i);
    let next = if end < text.len() { end + 1 } else { end };
    (start, end, next)
}

pub const COMMENT_KEYS: &[&str] = &["id", "tags", "assignee", "estimate"];
pub const FRONT_KEYS: &[&str] = &["sprint_id", "starts_on", "ends_on", "track", "tags", "assignee"];

/// Errors are collected per file so one run reports everything at once.
pub struct Errors<'a> {
    pub display: &'a str,
    pub text: &'a str,
    pub list: Vec<String>,
}

impl Errors<'_> {
    fn at(&mut self, offset: usize, msg: impl std::fmt::Display) {
        let line = line_at(self.text, offset);
        self.list.push(format!("{}:{line}: {msg}", self.display));
    }
}

pub fn parse(path: PathBuf, display: String, text: String, kind: DocKind) -> Result<Doc, Vec<String>> {
    let mut errs = Errors { display: &display, text: &text, list: vec![] };
    let front = parse_frontmatter(&text, &mut errs);
    if kind == DocKind::Single
        && front.is_some() {
            errs.at(0, "a single task file has no frontmatter (single tasks inherit nothing); move the values into the task comment");
        }
    let body_start = front.as_ref().map_or(0, |f| f.end);
    let s = Structure::scan(&text, body_start);

    let mut title = None;
    // Task headings, in order.
    let mut heads: Vec<(usize, ParsedHeading)> = vec![];
    for (i, h) in s.headings.iter().enumerate() {
        let Some(ph) = parse_heading(&text, h) else { continue };
        if ph.checkbox.is_some() {
            heads.push((i, ph));
        } else if kind == DocKind::Sprint && h.level == 1 && title.is_none() && heads.is_empty() {
            title = Some((ph.title.clone(), ph.title_range.clone(), line_at(&text, h.line_start)));
        }
    }

    match kind {
        DocKind::Sprint => {
            if title.is_none() {
                errs.at(body_start, "a sprint file needs a `# Title` heading before its tasks");
            }
        }
        DocKind::Single => {
            if heads.len() != 1 {
                errs.at(
                    body_start,
                    format!(
                        "a single task file holds exactly one task heading (`# ⬜ Title`), found {}",
                        heads.len()
                    ),
                );
            } else {
                let first = &s.headings[heads[0].0];
                if !text[body_start..first.line_start].trim().is_empty() {
                    errs.at(body_start, "text before the task heading; a single task file starts with `# ⬜ Title`");
                }
            }
        }
    }

    let mut tasks = vec![];
    for (n, (hi, ph)) in heads.iter().enumerate() {
        let h = &s.headings[*hi];
        let block_end = heads
            .get(n + 1)
            .map_or(text.len(), |(nhi, _)| s.headings[*nhi].line_start);
        if let Some(t) = parse_task(&text, &s, *hi, ph, block_end, &mut errs) {
            tasks.push(t);
        }
        let _ = h;
    }

    // `task:` comments outside any task (e.g. in the sprint description).
    let first_task = tasks.first().map_or(text.len(), |t| t.block.start);
    for c in s.task_comments(&text, body_start, first_task) {
        errs.at(c.start, "a `task:` comment outside any task; it belongs on the line under a task heading");
    }

    if !errs.list.is_empty() {
        return Err(errs.list);
    }
    Ok(Doc { path, display, text, kind, front, title, tasks })
}

struct ParsedHeading {
    checkbox: Option<(Range<usize>, Status, bool)>,
    title: String,
    title_range: Range<usize>,
}

fn parse_heading(text: &str, h: &Heading) -> Option<ParsedHeading> {
    let line = &text[h.line_start..h.line_end];
    let hashes = line.len() - line.trim_start_matches('#').len();
    if hashes == 0 || hashes > 6 {
        return None; // setext heading: never a task
    }
    let after = &line[hashes..];
    if !after.is_empty() && !after.starts_with([' ', '\t']) {
        return None;
    }
    let content_off = hashes + (after.len() - after.trim_start().len());
    let mut content_end = line.trim_end().len();
    // Optional closing sequence: ` ###`.
    let trimmed = &line[..content_end];
    let without = trimmed.trim_end_matches('#');
    if without.len() < trimmed.len() && (without.ends_with([' ', '\t']) || without.len() <= content_off) {
        content_end = without.trim_end().len().max(content_off);
    }
    let content = &line[content_off..content_end.max(content_off)];
    let base = h.line_start + content_off;

    // Status marker: the canonical emoji, or a typed checkbox (`[ ]`,
    // `[~]`, `[x]`, and sloppy variants like `[ x ]`) that `fmt` turns
    // into the emoji. Emoji, because a checkbox in a heading renders as
    // literal brackets in every Markdown viewer.
    let mut checkbox = None;
    let mut title_start = 0;
    let marker: Option<(usize, Status, bool)> = if let Some((len, st)) = Status::from_marker_prefix(content) {
        Some((len, st, true))
    } else if content.starts_with('[') {
        content.find(']').and_then(|close| {
            let status = match content[1..close].trim() {
                "" => Some(Status::Todo),
                "x" | "X" => Some(Status::Done),
                "~" => Some(Status::InProgress),
                _ => None,
            };
            status.map(|st| (close + 1, st, false))
        })
    } else {
        None
    };
    if let Some((len, status, canonical)) = marker {
        let rest = &content[len..];
        if rest.starts_with([' ', '\t']) && !rest.trim().is_empty() {
            checkbox = Some((base..base + len, status, canonical));
            title_start = len + (rest.len() - rest.trim_start().len());
        }
    }
    let title = content[title_start..].trim_end().to_string();
    let title_range = base + title_start..base + title_start + title.len();
    Some(ParsedHeading { checkbox, title, title_range })
}

fn parse_task(
    text: &str,
    s: &Structure,
    hi: usize,
    ph: &ParsedHeading,
    block_end: usize,
    errs: &mut Errors,
) -> Option<TaskBlock> {
    let h = &s.headings[hi];
    let (checkbox, status, checkbox_canonical) = ph.checkbox.clone()?;
    let heading_end = h.line_next;
    let before = errs.list.len();

    // The single `task:` comment anywhere in the body.
    let found = s.task_comments(text, heading_end, block_end);
    let comment = match found.len() {
        0 => None,
        1 => parse_comment(text, found[0].clone(), errs),
        _ => {
            errs.at(
                found[1].start,
                format!(
                    "task \"{}\" has two `task:` comments (line {} and here); a copy-pasted block? Keep one",
                    ph.title,
                    line_at(text, found[0].start)
                ),
            );
            None
        }
    };

    // Headings inside this task, after its own heading.
    let inner: Vec<&Heading> = s.headings[hi + 1..]
        .iter()
        .take_while(|x| x.line_start < block_end)
        .collect();
    // The Subtasks and Attachments sections, in either order, come last.
    let special = |x: &Heading, name: &str| {
        x.level > h.level
            && parse_heading(text, x).is_some_and(|p| p.checkbox.is_none() && p.title.eq_ignore_ascii_case(name))
    };
    let first_special = inner.iter().position(|x| special(x, "subtasks") || special(x, "attachments"));

    let mut subtasks = None;
    let mut attachments = None;
    let desc_end = match first_special {
        None => block_end,
        Some(first) => {
            let mut seen: Vec<&str> = vec![];
            for (i, sh) in inner.iter().enumerate().skip(first) {
                let section_end = inner.get(i + 1).map_or(block_end, |n| n.line_start);
                let name = if special(sh, "subtasks") {
                    "Subtasks"
                } else if special(sh, "attachments") {
                    "Attachments"
                } else {
                    errs.at(
                        sh.line_start,
                        format!(
                            "a heading after the {} section; the Subtasks and Attachments sections must come last in a task, so move this above them",
                            seen.last().copied().unwrap_or("Subtasks")
                        ),
                    );
                    continue;
                };
                if seen.contains(&name) {
                    errs.at(sh.line_start, format!("a second {name} section in task \"{}\"; keep one", ph.title));
                    continue;
                }
                seen.push(name);
                if name == "Subtasks" {
                    subtasks = parse_subtasks(text, s, sh, section_end, comment.as_ref(), errs);
                } else {
                    attachments = parse_attachments(text, s, sh, section_end, comment.as_ref(), errs);
                }
            }
            inner[first].line_start
        }
    };

    // Description: the region minus the comment.
    let mut desc = String::new();
    match &comment {
        Some(c) if c.range.start >= heading_end && c.range.end <= desc_end => {
            let cut = c.own_line.clone().unwrap_or(c.range.clone());
            desc.push_str(&text[heading_end..cut.start]);
            desc.push_str(&text[cut.end..desc_end]);
        }
        _ => desc.push_str(&text[heading_end..desc_end]),
    }

    if errs.list.len() > before {
        return None;
    }
    Some(TaskBlock {
        block: h.line_start..block_end,
        line: line_at(text, h.line_start),
        level: h.level,
        heading_line_end: h.line_end,
        heading_end,
        checkbox,
        status,
        checkbox_canonical,
        title: ph.title.clone(),
        title_range: ph.title_range.clone(),
        comment,
        desc_end,
        description: model::normalize_text(&desc),
        desc_links: s.links.iter().filter(|l| l.full.start >= heading_end && l.full.end <= desc_end).cloned().collect(),
        subtasks,
        attachments,
    })
}

fn parse_attachments(
    text: &str,
    s: &Structure,
    sh: &Heading,
    end: usize,
    comment: Option<&Comment>,
    errs: &mut Errors,
) -> Option<AttachmentSection> {
    let list = s.lists.iter().find(|l| l.range.start >= sh.line_next && l.range.start < end);
    let blank_except_comment = |from: usize, to: usize| -> bool {
        let mut t = text[from..to].to_string();
        if let Some(c) = comment {
            if c.range.start >= from && c.range.end <= to {
                t = format!("{}{}", &text[from..c.range.start], &text[c.range.end..to]);
            }
        }
        t.trim().is_empty()
    };
    let shape = "every Attachments item is one link, like `- [layout.png](../assets/<task-id>/layout.png)`";
    let Some(list) = list else {
        if !blank_except_comment(sh.line_next, end) {
            errs.at(sh.line_start, format!("an Attachments heading must be followed by a list of links; {shape}"));
            return None;
        }
        return Some(AttachmentSection { heading: sh.line_start..sh.line_next, level: sh.level, list: None, end, items: vec![], bullet: "- ".into() });
    };
    if !blank_except_comment(sh.line_next, list.range.start) {
        errs.at(sh.line_next, "text between the Attachments heading and its list; move it above the Attachments heading");
    }
    let list_end = list.range.end.min(end);
    if !blank_except_comment(list_end, end) {
        errs.at(list_end, "text after the Attachments list; the Subtasks and Attachments sections must come last in a task, so move this above them");
    }
    let mut items = vec![];
    let mut bullet = String::from("- ");
    for (n, it) in list.items.iter().enumerate() {
        let (ls, le, _) = line_bounds(text, it.range.start);
        let first = text[it.range.start.max(ls)..le].trim_start();
        let marker_len = first.find(' ').unwrap_or(first.len());
        if n == 0 {
            bullet = format!("{} ", &first[..marker_len]);
        }
        let content = first[marker_len..].trim();
        let item_text = text[it.range.clone()].trim_end();
        let link = s.links.iter().find(|l| l.full.start >= it.range.start && l.full.end <= it.range.end);
        match link {
            Some(l) if !item_text.contains('\n') && it.checked.is_none() && content == &text[l.full.clone()] && !l.image => {
                items.push(AttachmentItem { line: line_at(text, it.range.start), link: l.clone() });
            }
            _ => errs.at(it.range.start, shape),
        }
    }
    let list_start = line_bounds(text, list.range.start).0;
    Some(AttachmentSection { heading: sh.line_start..sh.line_next, level: sh.level, list: Some(list_start..list_end), end, items, bullet })
}

/// Inline links and images in `md`, with the byte range of each
/// destination as written, so it can be rewritten in place. Reference
/// links and autolinks are left out: they have no inline destination.
pub fn inline_links(md: &str) -> Vec<Link> {
    let mut out = vec![];
    let parser = Parser::new_ext(md, Options::ENABLE_TASKLISTS | Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH).into_offset_iter();
    for (ev, r) in parser {
        let (link_type, dest, image) = match ev {
            Event::Start(Tag::Link { link_type, dest_url, .. }) => (link_type, dest_url, false),
            Event::Start(Tag::Image { link_type, dest_url, .. }) => (link_type, dest_url, true),
            _ => continue,
        };
        if link_type != LinkType::Inline || dest.is_empty() {
            continue;
        }
        let whole = &md[r.clone()];
        // The destination follows the last `](` whose remainder starts
        // with it (labels may contain brackets of their own).
        let mut found = None;
        for (i, _) in whole.match_indices("](").collect::<Vec<_>>().into_iter().rev() {
            let after = &whole[i + 2..];
            let ws = after.len() - after.trim_start().len();
            let rest = &after[ws..];
            let (skip, rest) = match rest.strip_prefix('<') {
                Some(r) => (1, r),
                None => (0, rest),
            };
            if rest.starts_with(dest.as_ref()) {
                let start = r.start + i + 2 + ws + skip;
                found = Some(start..start + dest.len());
                break;
            }
        }
        if let Some(dest_range) = found {
            out.push(Link { full: r, dest_range, dest: dest.to_string(), image });
        }
    }
    out
}

/// `md` with each inline link destination for which `f` returns a new
/// value replaced by it.
pub fn rewrite_link_dests(md: &str, f: impl Fn(&Link) -> Option<String>) -> String {
    let edits: Vec<crate::safety::Edit> = inline_links(md)
        .iter()
        .filter_map(|l| f(l).map(|d| crate::safety::Edit::replace(l.dest_range.clone(), d)))
        .collect();
    crate::safety::apply_edits(md, &edits).unwrap_or_else(|_| md.to_string())
}

fn parse_subtasks(
    text: &str,
    s: &Structure,
    sh: &Heading,
    end: usize,
    comment: Option<&Comment>,
    errs: &mut Errors,
) -> Option<SubtaskSection> {
    let list = s.lists.iter().find(|l| l.range.start >= sh.line_next && l.range.start < end);
    let blank_except_comment = |from: usize, to: usize| -> bool {
        let mut t = text[from..to].to_string();
        if let Some(c) = comment {
            if c.range.start >= from && c.range.end <= to {
                t = format!("{}{}", &text[from..c.range.start], &text[c.range.end..to]);
            }
        }
        t.trim().is_empty()
    };
    let Some(list) = list else {
        if !blank_except_comment(sh.line_next, end) {
            errs.at(sh.line_start, "a Subtasks heading must be followed by a checklist (`- [ ] …`)");
            return None;
        }
        return Some(SubtaskSection {
            heading: sh.line_start..sh.line_next,
            level: sh.level,
            list: None,
            end,
            items: vec![],
            bullet: "- ".into(),
        });
    };
    if !blank_except_comment(sh.line_next, list.range.start) {
        errs.at(sh.line_next, "text between the Subtasks heading and its checklist; move it above the Subtasks heading");
    }
    let list_end = list.range.end.min(end);
    if !blank_except_comment(list_end, end) {
        errs.at(list_end, "text after the Subtasks checklist; the Subtasks section must come last in a task, so move this above it");
    }
    let mut items = vec![];
    let mut bullet = String::from("- ");
    for (n, it) in list.items.iter().enumerate() {
        let (ls, le, _) = line_bounds(text, it.range.start);
        let first = &text[it.range.start.max(ls)..le];
        let Some(done) = it.checked else {
            errs.at(it.range.start, "every Subtasks item must be a checklist item like `- [ ] Title`");
            continue;
        };
        let item_text = text[it.range.clone()].trim_end();
        if item_text.contains('\n') {
            errs.at(it.range.start, "multi-line subtasks are not supported; keep each subtask on one line");
            continue;
        }
        let t = first.trim_start();
        let marker_len = t.find(' ').unwrap_or(t.len());
        if n == 0 {
            bullet = format!("{} ", &t[..marker_len]);
        }
        let rest = t[marker_len..].trim_start();
        let title = rest
            .find(']')
            .map(|i| rest[i + 1..].trim())
            .unwrap_or("")
            .to_string();
        if title.is_empty() {
            errs.at(it.range.start, "empty subtask title");
            continue;
        }
        items.push(Subtask { title, done });
    }
    let list_start = line_bounds(text, list.range.start).0;
    Some(SubtaskSection {
        heading: sh.line_start..sh.line_next,
        level: sh.level,
        list: Some(list_start..list_end),
        end,
        items,
        bullet,
    })
}

fn parse_comment(text: &str, range: Range<usize>, errs: &mut Errors) -> Option<Comment> {
    let raw_text = &text[range.clone()];
    let inner = raw_text
        .trim_start_matches("<!--")
        .trim_end_matches("-->")
        .trim();
    let body = inner.strip_prefix("task:").unwrap_or("").trim();
    let (ls, le, next) = line_bounds(text, range.start);
    let own_line = (text[ls..range.start].trim().is_empty() && text[range.end..le].trim().is_empty())
        .then_some(ls..next);
    let mut c = Comment {
        range: range.clone(),
        own_line,
        line: line_at(text, range.start),
        id: None,
        tags: None,
        assignee: None,
        estimate: None,
        raw: vec![],
    };
    let tokens = match tokenize(body) {
        Ok(t) => t,
        Err(e) => {
            errs.at(range.start, format!("in task comment: {e}"));
            return None;
        }
    };
    let mut ok = true;
    for (key, raw) in tokens {
        let items = match split_items(&raw) {
            Ok(i) => i,
            Err(e) => {
                errs.at(range.start, format!("in task comment, {key}: {e}"));
                ok = false;
                continue;
            }
        };
        if c.raw.iter().any(|(k, _)| *k == key) {
            errs.at(range.start, format!("key {key:?} appears twice in the task comment"));
            ok = false;
            continue;
        }
        let one = || -> Result<String, String> {
            match items.as_slice() {
                [v] => Ok(v.clone()),
                _ => Err(format!("{key} takes a single value")),
            }
        };
        let r: Result<(), String> = (|| {
            match key.as_str() {
                "id" => {
                    let v = one()?;
                    c.id = Some(v.parse().map_err(|_| {
                        format!("id {v:?} is not a UUID; never edit or invent `id=`, delete the key and run `task-cli fmt` to get a new one")
                    })?);
                }
                "tags" => c.tags = Some(model::normalize_tags(items.clone())),
                // `assignee=""` is an explicit "nobody", overriding the
                // sprint default; an absent key inherits it.
                "assignee" => c.assignee = Some(one()?),
                "estimate" => {
                    let v = one()?;
                    c.estimate = if v.is_empty() { None } else { Some(model::parse_estimate(&v)?) };
                }
                other => {
                    let hint = model::suggest(other, COMMENT_KEYS)
                        .map(|k| format!("; did you mean {k:?}"))
                        .unwrap_or_else(|| format!("; known keys: {}", COMMENT_KEYS.join(", ")));
                    return Err(format!("unknown key {other:?} in task comment{hint}"));
                }
            }
            Ok(())
        })();
        if let Err(e) = r {
            errs.at(range.start, e);
            ok = false;
        }
        c.raw.push((key, raw));
    }
    ok.then_some(c)
}

/// `a=b c="d e" f=g,"h i"` → [(a, b), (c, "d e" raw), …]. Values keep
/// their quotes here; `split_items` removes them.
fn tokenize(s: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = vec![];
    let mut chars = s.char_indices().peekable();
    while let Some(&(start, c)) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        let mut in_q = false;
        let mut end = s.len();
        while let Some(&(i, c)) = chars.peek() {
            if c == '"' {
                in_q = !in_q;
            } else if c == '\\' && in_q {
                chars.next();
            } else if c.is_whitespace() && !in_q {
                end = i;
                break;
            }
            chars.next();
        }
        if in_q {
            return Err("unclosed quote".into());
        }
        let tok = &s[start..end];
        let Some((k, v)) = tok.split_once('=') else {
            return Err(format!("expected key=value, found {tok:?}"));
        };
        out.push((k.to_string(), v.to_string()));
    }
    Ok(out)
}

fn split_items(raw: &str) -> Result<Vec<String>, String> {
    let mut items = vec![];
    let mut cur = String::new();
    let mut in_q = false;
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => in_q = !in_q,
            '\\' if in_q => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            ',' if !in_q => items.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    if in_q {
        return Err("unclosed quote".into());
    }
    items.push(cur);
    Ok(items)
}

pub fn quote_item(s: &str) -> String {
    if s.is_empty() || s.chars().any(|c| c.is_whitespace() || matches!(c, ',' | '"' | '=' | '\\')) || s.contains("--") {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        s.to_string()
    }
}

/// Canonical comment text from raw `key=value` pairs: `id` first, then the
/// other known keys in fixed order.
pub fn format_comment_raw(pairs: &[(String, String)]) -> String {
    let mut out = String::from("<!-- task:");
    for key in COMMENT_KEYS {
        if let Some((_, v)) = pairs.iter().find(|(k, _)| k == key) {
            out.push_str(&format!(" {key}={v}"));
        }
    }
    out.push_str(" -->");
    out
}

pub fn format_list_value(items: &[String]) -> String {
    if items.is_empty() {
        "\"\"".into()
    } else {
        items.iter().map(|i| quote_item(i)).collect::<Vec<_>>().join(",")
    }
}

// ---- frontmatter ----

fn parse_frontmatter(text: &str, errs: &mut Errors) -> Option<Frontmatter> {
    let first_end = text.find('\n')?;
    if text[..first_end].trim_end() != "---" {
        return None;
    }
    let body_start = first_end + 1;
    let mut pos = body_start;
    let mut close = None;
    while pos < text.len() {
        let end = text[pos..].find('\n').map_or(text.len(), |i| pos + i);
        if text[pos..end].trim_end() == "---" {
            close = Some((pos, if end < text.len() { end + 1 } else { end }));
            break;
        }
        pos = end + 1;
    }
    let Some((close_start, end)) = close else {
        errs.at(0, "frontmatter starts with `---` but has no closing `---` line");
        return None;
    };
    let mut fm = Frontmatter { body_start, close_start, end, ..Default::default() };
    let mut pos = body_start;
    while pos < close_start {
        let le = text[pos..].find('\n').map_or(text.len(), |i| pos + i);
        let next = (le + 1).min(text.len());
        let line = &text[pos..le];
        let t = line.trim();
        if !t.is_empty() && !t.starts_with('#') {
            match t.split_once(':') {
                None => errs.at(pos, format!("expected `key: value` in frontmatter, found {t:?}")),
                Some((k, v)) => {
                    let key = k.trim().to_string();
                    let v = v.trim();
                    let value = if v.starts_with('[') {
                        if !v.ends_with(']') {
                            errs.at(pos, format!("{key}: a list is written on one line, like [a, b]"));
                            FrontValue::List(vec![])
                        } else {
                            match split_items(&v[1..v.len() - 1]) {
                                Ok(items) => FrontValue::List(
                                    items.into_iter().map(|i| unquote_scalar(i.trim())).filter(|i| !i.is_empty()).collect(),
                                ),
                                Err(e) => {
                                    errs.at(pos, format!("{key}: {e}"));
                                    FrontValue::List(vec![])
                                }
                            }
                        }
                    } else {
                        FrontValue::Scalar(unquote_scalar(v))
                    };
                    if !FRONT_KEYS.contains(&key.as_str()) {
                        let hint = model::suggest(&key, FRONT_KEYS)
                            .map(|k| format!("; did you mean {k:?}"))
                            .unwrap_or_else(|| format!("; known keys: {}", FRONT_KEYS.join(", ")));
                        errs.at(pos, format!("unknown frontmatter key {key:?}{hint}"));
                    } else if fm.lines.iter().any(|l| l.key == key) {
                        errs.at(pos, format!("frontmatter key {key:?} appears twice"));
                    }
                    fm.lines.push(FrontLine { key, range: pos..next, line: line_at(text, pos), value });
                }
            }
        }
        pos = next;
    }

    let mut start = None;
    let mut end_d = None;
    for l in fm.lines.clone() {
        let scalar = match &l.value {
            FrontValue::Scalar(s) => Some(s.clone()),
            FrontValue::List(_) => None,
        };
        let need_scalar = |errs: &mut Errors| {
            if scalar.is_none() {
                errs.at(l.range.start, format!("{} takes a single value, not a list", l.key));
            }
        };
        match l.key.as_str() {
            "sprint_id" => {
                need_scalar(errs);
                if let Some(s) = &scalar {
                    match s.parse() {
                        Ok(id) => fm.sprint_id = Some(id),
                        Err(_) => errs.at(l.range.start, format!("sprint_id {s:?} is not a UUID; never edit or invent it, delete the line and run `task-cli fmt`")),
                    }
                }
            }
            "starts_on" | "ends_on" => {
                need_scalar(errs);
                if let Some(s) = scalar.as_ref().filter(|s| !s.is_empty()) {
                    match s.parse::<NaiveDate>() {
                        Ok(d) if l.key == "starts_on" => start = Some((d, l.range.start)),
                        Ok(d) => end_d = Some((d, l.range.start)),
                        Err(_) => errs.at(l.range.start, format!("{}: {s:?} is not a date like 2026-11-09", l.key)),
                    }
                }
            }
            "track" => {
                need_scalar(errs);
                fm.track = scalar.filter(|s| !s.is_empty());
            }
            "assignee" => {
                need_scalar(errs);
                fm.assignee = scalar.filter(|s| !s.is_empty());
            }
            "tags" => {
                fm.tags = Some(model::normalize_tags(match &l.value {
                    FrontValue::List(v) => v.clone(),
                    FrontValue::Scalar(s) if s.is_empty() => vec![],
                    FrontValue::Scalar(s) => vec![s.clone()],
                }));
            }
            _ => {}
        }
    }
    match (start, end_d) {
        (Some((a, _)), Some((b, at))) => match model::validate_dates(a, b) {
            Ok(()) => fm.dates = Some((a, b)),
            Err(e) => errs.at(at, e),
        },
        (None, None) => {}
        (Some((_, at)), None) | (None, Some((_, at))) => {
            errs.at(at, "set both starts_on and ends_on, or neither for an unscheduled sprint")
        }
    }
    Some(fm)
}

fn unquote_scalar(v: &str) -> String {
    let v = v.trim();
    if v.len() >= 2 && ((v.starts_with('"') && v.ends_with('"')) || (v.starts_with('\'') && v.ends_with('\''))) {
        v[1..v.len() - 1].replace("\\\"", "\"")
    } else {
        v.to_string()
    }
}

pub fn quote_front_scalar(v: &str) -> String {
    if v.is_empty()
        || v.contains(": ")
        || v.contains(" #")
        || v.starts_with(['"', '\'', '[', '{', '#', '-', ' '])
        || v.ends_with(' ')
        || v.contains(',')
    {
        format!("\"{}\"", v.replace('"', "\\\""))
    } else {
        v.to_string()
    }
}

pub fn format_front_list(items: &[String]) -> String {
    format!(
        "[{}]",
        items
            .iter()
            .map(|i| if i.contains([',', '[', ']', '"']) || i.trim() != i { format!("\"{}\"", i.replace('"', "\\\"")) } else { i.clone() })
            .collect::<Vec<_>>()
            .join(", ")
    )
}

// ---- CommonMark structure ----

#[derive(Debug)]
struct Heading {
    level: usize,
    line_start: usize,
    line_end: usize,
    line_next: usize,
}

#[derive(Debug)]
struct ListItem {
    range: Range<usize>,
    checked: Option<bool>,
}

#[derive(Debug)]
struct List {
    range: Range<usize>,
    items: Vec<ListItem>,
}

struct Structure {
    headings: Vec<Heading>,
    html: Vec<Range<usize>>,
    lists: Vec<List>,
    links: Vec<Link>,
}

impl Structure {
    fn scan(text: &str, offset: usize) -> Structure {
        let body = &text[offset..];
        let parser = Parser::new_ext(body, Options::ENABLE_TASKLISTS).into_offset_iter();
        let mut headings = vec![];
        let mut html = vec![];
        let mut lists: Vec<List> = vec![];
        let mut depth = 0usize;
        for (ev, r) in parser {
            let r = r.start + offset..r.end + offset;
            match ev {
                Event::Start(Tag::Heading { level, .. }) => {
                    let (ls, le, next) = line_bounds(text, r.start);
                    headings.push(Heading { level: heading_level(level), line_start: ls, line_end: le, line_next: next });
                }
                Event::Html(_) | Event::InlineHtml(_) => html.push(r),
                Event::Start(Tag::List(_)) => {
                    depth += 1;
                    if depth == 1 {
                        lists.push(List { range: r, items: vec![] });
                    }
                }
                Event::End(TagEnd::List(_)) => depth = depth.saturating_sub(1),
                Event::Start(Tag::Item) if depth == 1 => {
                    if let Some(l) = lists.last_mut() {
                        l.items.push(ListItem { range: r, checked: None });
                    }
                }
                Event::TaskListMarker(done) if depth == 1 => {
                    if let Some(it) = lists.last_mut().and_then(|l| l.items.last_mut()) {
                        if it.checked.is_none() {
                            it.checked = Some(done);
                        }
                    }
                }
                _ => {}
            }
        }
        // Adjacent HTML events (a multi-line comment comes as several).
        html.sort_by_key(|r| r.start);
        let mut merged: Vec<Range<usize>> = vec![];
        for r in html {
            match merged.last_mut() {
                Some(m) if r.start <= m.end => m.end = m.end.max(r.end),
                _ => merged.push(r),
            }
        }
        let links = inline_links(body)
            .into_iter()
            .map(|l| Link {
                full: l.full.start + offset..l.full.end + offset,
                dest_range: l.dest_range.start + offset..l.dest_range.end + offset,
                ..l
            })
            .collect();
        Structure { headings, html: merged, lists, links }
    }

    /// `<!-- task: … -->` comments inside [from, to), excluding code.
    fn task_comments(&self, text: &str, from: usize, to: usize) -> Vec<Range<usize>> {
        let mut out = vec![];
        for h in &self.html {
            if h.end <= from || h.start >= to {
                continue;
            }
            let (a, b) = (h.start.max(from), h.end.min(to));
            let mut pos = a;
            while let Some(i) = text[pos..b].find("<!--") {
                let start = pos + i;
                let Some(j) = text[start..b].find("-->") else { break };
                let end = start + j + 3;
                if text[start + 4..end - 3].trim_start().starts_with("task:") {
                    out.push(start..end);
                }
                pos = end;
            }
        }
        out
    }
}

fn heading_level(l: HeadingLevel) -> usize {
    match l {
        HeadingLevel::H1 => 1,
        HeadingLevel::H2 => 2,
        HeadingLevel::H3 => 3,
        HeadingLevel::H4 => 4,
        HeadingLevel::H5 => 5,
        HeadingLevel::H6 => 6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sprint(text: &str) -> Result<Doc, Vec<String>> {
        parse("x.md".into(), "x.md".into(), text.to_string(), DocKind::Sprint)
    }

    const ID: &str = "0b5a8c1e-2d3f-4a5b-8c7d-9e0f1a2b3c4d";

    #[test]
    fn parses_the_spec_example() {
        let text = format!(
            "---\nsprint_id: {ID}\nstarts_on: 2026-11-09\nends_on: 2026-11-23\ntrack: Platform\ntags: [frontend]\nassignee: rihard\n---\n\n# Initial scaffolding\n\nSprint description.\n\n## [ ] Application shell\n<!-- task: id={ID} tags=frontend,layout estimate=4h -->\n\nBuild the application shell.\n\n### Subtasks\n\n- [x] Navigation\n- [ ] Sidebar\n\n## [~] Routing\n"
        );
        let d = sprint(&text).unwrap();
        let fm = d.front.as_ref().unwrap();
        assert_eq!(fm.tags.as_deref(), Some(&["frontend".to_string()][..]));
        assert_eq!(fm.assignee.as_deref(), Some("rihard"));
        assert!(fm.dates.is_some());
        assert_eq!(d.title.as_ref().unwrap().0, "Initial scaffolding");
        assert_eq!(d.tasks.len(), 2);
        let t = &d.tasks[0];
        assert_eq!(t.title, "Application shell");
        assert_eq!(t.status, Status::Todo);
        assert_eq!(t.description, "Build the application shell.");
        let c = t.comment.as_ref().unwrap();
        assert_eq!(c.tags.as_deref().unwrap(), ["frontend", "layout"]);
        assert_eq!(c.estimate, Some(240));
        let subs = &t.subtasks.as_ref().unwrap().items;
        assert_eq!(subs.len(), 2);
        assert!(subs[0].done && !subs[1].done);
        assert_eq!(d.tasks[1].status, Status::InProgress);
        assert!(d.tasks[1].comment.is_none());
    }

    #[test]
    fn tolerant_of_wysiwyg_blank_lines_and_checkbox_variants() {
        let text = format!("# S\n\n## [ x ] Done thing\n\n\n<!-- task: id={ID} -->\n\nBody\n\n## [ ~ ] Doing\n\n## [X] Upper\n");
        let d = sprint(&text).unwrap();
        assert_eq!(d.tasks[0].status, Status::Done);
        assert!(!d.tasks[0].checkbox_canonical);
        assert_eq!(d.tasks[0].description, "Body");
        assert_eq!(d.tasks[0].id().unwrap().to_string(), ID);
        assert_eq!(d.tasks[1].status, Status::InProgress);
        assert_eq!(d.tasks[2].status, Status::Done);
    }

    #[test]
    fn comment_in_the_middle_of_the_description() {
        let text = format!("# S\n\n## [ ] T\n\nFirst\n\n<!-- task: id={ID} -->\n\nSecond\n");
        let d = sprint(&text).unwrap();
        assert_eq!(d.tasks[0].description, "First\n\n\nSecond");
    }

    #[test]
    fn fenced_code_is_content() {
        let text = "# S\n\n## [ ] T\n\n```md\n## [ ] Not a task\n<!-- task: id=nope -->\n### Subtasks\n- [ ] no\n```\n";
        let d = sprint(text).unwrap();
        assert_eq!(d.tasks.len(), 1);
        assert!(d.tasks[0].comment.is_none());
        assert!(d.tasks[0].subtasks.is_none());
        assert!(d.tasks[0].description.contains("## [ ] Not a task"));
    }

    #[test]
    fn two_comments_is_an_error() {
        let text = format!("# S\n\n## [ ] T\n<!-- task: id={ID} -->\n<!-- task: id={ID} -->\n");
        let e = sprint(&text).unwrap_err();
        assert!(e[0].contains("two `task:` comments"), "{e:?}");
    }

    #[test]
    fn unknown_key_suggests() {
        let e = sprint("# S\n\n## [ ] T\n<!-- task: tag=bug -->\n").unwrap_err();
        assert_eq!(e[0], "x.md:4: unknown key \"tag\" in task comment; did you mean \"tags\"");
    }

    #[test]
    fn quoted_values() {
        let d = sprint("# S\n\n## [ ] T\n<!-- task: tags=\"needs review\",bug assignee=\"Ann Lee\" -->\n").unwrap();
        let c = d.tasks[0].comment.as_ref().unwrap();
        assert_eq!(c.tags.as_deref().unwrap(), ["bug", "needs review"]);
        assert_eq!(c.assignee.as_deref(), Some("Ann Lee"));
    }

    #[test]
    fn single_task_file() {
        let text = "# [ ] Login redirects\n<!-- task: tags=bug -->\n\nAfter signing in.\n\n## Subtasks\n\n- [ ] Reproduce\n";
        let d = parse("s.md".into(), "s.md".into(), text.into(), DocKind::Single).unwrap();
        assert_eq!(d.tasks.len(), 1);
        assert_eq!(d.tasks[0].subtasks.as_ref().unwrap().items.len(), 1);
        assert_eq!(d.tasks[0].description, "After signing in.");
    }

    #[test]
    fn text_after_subtasks_is_an_error() {
        let e = sprint("# S\n\n## [ ] T\n\n### Subtasks\n\n- [ ] a\n\nTrailing notes\n").unwrap_err();
        assert!(e[0].contains("after the Subtasks checklist"), "{e:?}");
    }

    #[test]
    fn date_validation() {
        let e = sprint("---\nstarts_on: 2026-11-09\n---\n# S\n").unwrap_err();
        assert!(e[0].contains("both starts_on and ends_on"));
        let e = sprint("---\nstarts_on: 2026-11-10\nends_on: 2026-11-23\n---\n# S\n").unwrap_err();
        assert!(e[0].contains("Mondays"), "{e:?}");
    }

    #[test]
    fn attachments_section_in_either_order() {
        let a = format!("# S\n\n## [ ] T\n<!-- task: id={ID} -->\n\nBody ![x](../assets/{ID}/x.png)\n\n### Attachments\n\n- [x.png](../assets/{ID}/x.png)\n- [Spec](<../assets/{ID}/spec.pdf>)\n\n### Subtasks\n\n- [ ] one\n");
        let d = sprint(&a).unwrap();
        let t = &d.tasks[0];
        assert_eq!(t.description, format!("Body ![x](../assets/{ID}/x.png)"));
        assert_eq!(t.desc_links.len(), 1);
        assert!(t.desc_links[0].image);
        let items: Vec<&str> = t.attachments.as_ref().unwrap().items.iter().map(|i| i.link.dest.as_str()).collect();
        assert_eq!(items, [format!("../assets/{ID}/x.png"), format!("../assets/{ID}/spec.pdf")]);
        assert_eq!(&d.text[t.attachments.as_ref().unwrap().items[1].link.dest_range.clone()], format!("../assets/{ID}/spec.pdf"));
        assert_eq!(t.subtasks.as_ref().unwrap().items.len(), 1);
        // Subtasks first parses the same.
        let b = format!("# S\n\n## [ ] T\n\nBody\n\n### Subtasks\n\n- [ ] one\n\n### Attachments\n\n- [x.png](x.png)\n");
        let d = sprint(&b).unwrap();
        assert_eq!(d.tasks[0].description, "Body");
        assert_eq!(d.tasks[0].attachments.as_ref().unwrap().items.len(), 1);
    }

    #[test]
    fn attachment_section_errors() {
        let e = sprint("# S\n\n## [ ] T\n\n### Attachments\n\n- just text\n").unwrap_err();
        assert!(e[0].contains("every Attachments item is one link"), "{e:?}");
        let e = sprint("# S\n\n## [ ] T\n\n### Attachments\n\n- [a](a.png)\n\n### Notes\n").unwrap_err();
        assert!(e[0].contains("a heading after the Attachments section"), "{e:?}");
        let e = sprint("# S\n\n## [ ] T\n\n### Attachments\n\n- [a](a.png)\n\n### Attachments\n\n- [b](b.png)\n").unwrap_err();
        assert!(e[0].contains("a second Attachments section"), "{e:?}");
        let e = sprint("# S\n\n## [ ] T\n\n### Subtasks\n\n- [ ] a\n\nTrailing\n").unwrap_err();
        assert!(e[0].contains("after the Subtasks checklist"), "{e:?}");
    }

    #[test]
    fn plain_headings_between_tasks_are_description() {
        let d = sprint("# S\n\nIntro\n\n## [ ] A\n\n## Notes\n\ntext\n\n## [ ] B\n").unwrap();
        assert_eq!(d.tasks.len(), 2);
        assert_eq!(d.tasks[0].description, "## Notes\n\ntext");
    }
}
