//! Producing local text: `fmt` normalisation, surgical task and sprint
//! edits, block moves, and new files. Everything returns `Edit`s against
//! the text that was parsed, so unchanged bytes stay identical.

use uuid::Uuid;

use crate::doc::{self, Doc, DocKind, TaskBlock};
use crate::attachments;
use crate::model::{self, Attachment, Sprint, Subtask, Task};
use crate::safety::{apply_edits, Edit};

/// What a task inherits from its file: the sprint frontmatter's `tags` and
/// `assignee`, or nothing for a single task.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Defaults {
    pub tags: Vec<String>,
    pub assignee: Option<Uuid>,
}

/// How local names map to and from Fira users.
pub trait Names {
    fn resolve_user(&self, name: &str) -> Option<Uuid>;
    fn handle(&self, id: Uuid) -> String;
}

// ---- fmt ----

/// Structure-only normalisation: missing IDs, comment placement directly
/// under the heading, canonical checkboxes, canonical key order. Prose,
/// blank lines inside descriptions and wrapping are never touched.
pub fn fmt_edits(doc: &Doc, sprint_id: Option<(Uuid, bool)>, task_ids: &[(Uuid, bool)]) -> Vec<Edit> {
    let text = &doc.text;
    let mut edits = vec![];
    if doc.kind == DocKind::Sprint {
        if let Some((id, true)) = sprint_id {
            edits.push(sprint_id_edit(doc, id));
        }
    }
    for (t, &(id, new)) in doc.tasks.iter().zip(task_ids) {
        if !t.checkbox_canonical {
            edits.push(Edit::replace(t.checkbox.clone(), t.status.marker()));
        }
        match &t.comment {
            None => edits.push(insert_comment_under_heading(t, &format!("<!-- task: id={id} -->"))),
            Some(c) => {
                let mut raw = c.raw.clone();
                if new {
                    raw.insert(0, ("id".into(), id.to_string()));
                }
                let canonical = doc::format_comment_raw(&raw);
                if c.range.start == t.heading_end {
                    if text[c.range.clone()] != canonical {
                        edits.push(Edit::replace(c.range.clone(), canonical));
                    }
                } else if text[t.heading_end..c.range.start].trim().is_empty() {
                    // Only blank lines between heading and comment (what
                    // WYSIWYG editors leave): pull it up.
                    edits.push(Edit::replace(t.heading_end..c.range.end, canonical));
                } else {
                    // Somewhere inside the body: take it out (with one of
                    // the blank lines around it, so the gap doesn't grow)
                    // and put it under the heading.
                    let mut cut = c.own_line.clone().unwrap_or(c.range.clone());
                    if c.own_line.is_some() {
                        let before_blank = text[..cut.start].ends_with("\n\n");
                        let after_blank = text[cut.end..].starts_with('\n') || cut.end == text.len();
                        if before_blank && after_blank && cut.end < text.len() {
                            cut.end += 1;
                        }
                    }
                    edits.push(Edit::replace(cut, ""));
                    edits.push(insert_comment_under_heading(t, &canonical));
                }
            }
        }
    }
    edits
}

fn sprint_id_edit(doc: &Doc, id: Uuid) -> Edit {
    match &doc.front {
        Some(f) => Edit::insert(f.body_start, format!("sprint_id: {id}\n")),
        None => Edit::insert(0, format!("---\nsprint_id: {id}\n---\n\n")),
    }
}

fn insert_comment_under_heading(t: &TaskBlock, comment: &str) -> Edit {
    if t.heading_end == t.heading_line_end {
        Edit::insert(t.heading_end, format!("\n{comment}"))
    } else {
        Edit::insert(t.heading_end, format!("{comment}\n"))
    }
}

// ---- task comment under inheritance ----

/// The `key=value` pairs that make the comment express `target` under the
/// file's (new) defaults, changing only keys that need it. Returns `None`
/// when the current comment already does.
pub fn comment_for(
    t: Option<&TaskBlock>,
    id: Uuid,
    id_is_new: bool,
    target: &Task,
    defaults: &Defaults,
    names: &dyn Names,
) -> Option<String> {
    let c = t.and_then(|t| t.comment.as_ref());
    let mut raw: Vec<(String, String)> = c.map(|c| c.raw.clone()).unwrap_or_default();
    let mut changed = c.is_none() || id_is_new;
    let set = |raw: &mut Vec<(String, String)>, k: &str, v: Option<String>| {
        raw.retain(|(key, _)| key != k);
        if let Some(v) = v {
            raw.push((k.to_string(), v));
        }
    };
    if id_is_new || c.is_none() {
        set(&mut raw, "id", Some(id.to_string()));
    }

    let effective_tags = c.and_then(|c| c.tags.clone()).unwrap_or_else(|| defaults.tags.clone());
    if effective_tags != target.tags {
        changed = true;
        let v = (target.tags != defaults.tags).then(|| doc::format_list_value(&target.tags));
        set(&mut raw, "tags", v);
    }

    let effective_assignee = match c.and_then(|c| c.assignee.as_deref()) {
        Some("") => None,
        Some(name) => names.resolve_user(name),
        None => defaults.assignee,
    };
    if effective_assignee != target.assignee {
        changed = true;
        let v = if target.assignee == defaults.assignee {
            None
        } else {
            Some(match target.assignee {
                Some(u) => doc::quote_item(&names.handle(u)),
                None => "\"\"".into(),
            })
        };
        set(&mut raw, "assignee", v);
    }

    if c.and_then(|c| c.estimate) != target.estimate_min {
        changed = true;
        set(&mut raw, "estimate", target.estimate_min.map(model::format_estimate));
    }
    changed.then(|| doc::format_comment_raw(&raw))
}

// ---- task edits ----

fn names(a: &[Attachment]) -> Vec<&str> {
    a.iter().map(|a| a.name.as_str()).collect()
}

fn attachment_lines(bullet: &str, items: &[Attachment], prefix: &str) -> String {
    items.iter().map(|a| attachments::item_line(bullet, &a.name, prefix)).collect()
}

/// Edits that make block `b` express `target`, given what it expresses now
/// (`cur`). `comment` is the new comment text when it must change.
/// Descriptions are in local form; `att_prefix` is how this file links to
/// the task's attachment folder (`../assets/<id>/`).
pub fn task_edits(text: &str, b: &TaskBlock, cur: &Task, target: &Task, comment: Option<String>, att_prefix: &str) -> Vec<Edit> {
    let mut edits = vec![];
    if cur.status != target.status {
        edits.push(Edit::replace(b.checkbox.clone(), target.status.marker()));
    }
    if cur.title != target.title {
        edits.push(Edit::replace(b.title_range.clone(), one_line(&target.title)));
    }
    let desc_changed = cur.description != target.description;
    let subs_changed = cur.subtasks != target.subtasks;
    let sub_level = b.subtasks.as_ref().map_or(b.level + 1, |s| s.level);
    let mut subs_done = false;
    let atts_changed = names(&cur.attachments) != names(&target.attachments);
    let att_level = b.attachments.as_ref().map_or(sub_level, |s| s.level);
    let mut atts_done = false;
    // Removing a section at the end of the file also takes the blank
    // lines before it, but never into a rewritten description.
    let floor = if desc_changed { b.desc_end } else { b.heading_end };

    if desc_changed {
        let in_region = b
            .comment
            .as_ref()
            .filter(|c| c.range.start >= b.heading_end && c.range.end <= b.desc_end);
        let mut s = String::new();
        if b.heading_end == b.heading_line_end {
            s.push('\n');
        }
        let comment_text = match (&comment, in_region) {
            (Some(new), Some(_)) => Some(new.clone()),
            (Some(new), None) if b.comment.is_none() => Some(new.clone()),
            (None, Some(c)) => Some(text[c.range.clone()].to_string()),
            _ => None,
        };
        if let Some(ct) = &comment_text {
            s.push_str(ct);
            s.push('\n');
        }
        if !target.description.is_empty() {
            s.push('\n');
            s.push_str(&target.description);
            s.push('\n');
        }
        if b.attachments.is_none() && !target.attachments.is_empty() {
            s.push('\n');
            s.push_str(&attachments::section(att_level, &attachment_lines("- ", &target.attachments, att_prefix)));
            atts_done = true;
        }
        if b.subtasks.is_none() && !target.subtasks.is_empty() {
            s.push('\n');
            s.push_str(&subtasks_section(sub_level, "- ", &target.subtasks));
            subs_done = true;
        }
        let follows = b.desc_end < b.block.end || b.block.end < text.len();
        if follows {
            s.push('\n');
        }
        edits.push(Edit::replace(b.heading_end..b.desc_end, s));
        // A comment outside the description region (e.g. after the
        // subtasks) is rewritten where it is.
        if let (Some(new), Some(c)) = (&comment, &b.comment) {
            if in_region.is_none() {
                edits.push(Edit::replace(c.range.clone(), new.clone()));
            }
        }
    } else if let Some(ct) = &comment {
        match &b.comment {
            Some(c) => edits.push(Edit::replace(c.range.clone(), ct.clone())),
            None => edits.push(insert_comment_under_heading(b, ct)),
        }
    }

    if atts_changed && !atts_done {
        match &b.attachments {
            Some(sec) if target.attachments.is_empty() => edits.push(remove_section(text, sec.heading.start, sec.end, floor)),
            Some(sec) => {
                // Keep the lines (and labels) of files that stay, in their
                // order; append new ones.
                let mut lines: String = sec
                    .items
                    .iter()
                    .filter(|it| target.attachments.iter().any(|a| a.name == attachments::item_name(&it.link)))
                    .map(|it| {
                        let ls = text[..it.link.full.start].rfind('\n').map_or(0, |i| i + 1);
                        format!("{}\n", text[ls..line_end_incl(text, it.link.full.start)].trim_end())
                    })
                    .collect();
                let new: Vec<Attachment> = target
                    .attachments
                    .iter()
                    .filter(|a| !sec.items.iter().any(|it| attachments::item_name(&it.link) == a.name))
                    .cloned()
                    .collect();
                lines.push_str(&attachment_lines(&sec.bullet, &new, att_prefix));
                match &sec.list {
                    Some(list) => edits.push(replace_list(text, list, lines)),
                    None => edits.push(Edit::insert(sec.heading.end, format!("\n{lines}"))),
                }
            }
            None => {
                let sec = attachments::section(att_level, &attachment_lines("- ", &target.attachments, att_prefix));
                edits.push(attachments::insert_section(text, b, &sec));
            }
        }
    }

    if subs_changed && !subs_done {
        match &b.subtasks {
            Some(sec) if target.subtasks.is_empty() => edits.push(remove_section(text, sec.heading.start, sec.end, floor)),
            Some(sec) => {
                let items = subtask_lines(&sec.bullet, &target.subtasks);
                match &sec.list {
                    Some(list) => edits.push(replace_list(text, list, items)),
                    None => edits.push(Edit::insert(sec.heading.end, format!("\n{items}"))),
                }
            }
            None => {
                let region = &text[b.heading_end.min(b.block.end)..b.block.end];
                let p = if region.trim().is_empty() {
                    b.heading_line_end
                } else {
                    b.heading_end + region.trim_end().len()
                };
                let mut ins = format!("\n\n{}", subtasks_section(sub_level, "- ", &target.subtasks));
                ins.pop(); // keep the whitespace that followed p
                if p == text.len() {
                    ins.push('\n');
                }
                edits.push(Edit::insert(p, ins));
            }
        }
    }
    edits
}

/// Replace a list's items. The parser's list range can run on over the
/// blank line after it; stop at the end of the last item.
fn replace_list(text: &str, list: &std::ops::Range<usize>, mut items: String) -> Edit {
    let content = text[list.clone()].trim_end().len().max(1);
    let end = line_end_incl(text, list.start + content - 1);
    if end == text.len() && !text.ends_with('\n') {
        items.pop();
    }
    Edit::replace(list.start..end, items)
}

fn remove_section(text: &str, heading_start: usize, end: usize, floor: usize) -> Edit {
    let mut start = heading_start;
    if end == text.len() {
        while start > floor.max(1) && &text[start - 2..start] == "\n\n" {
            start -= 1;
        }
    }
    Edit::replace(start..end, "")
}

fn line_end_incl(text: &str, offset: usize) -> usize {
    text[offset..].find('\n').map_or(text.len(), |i| offset + i + 1)
}

fn one_line(s: &str) -> String {
    s.replace(['\n', '\r'], " ")
}

fn subtask_lines(bullet: &str, items: &[Subtask]) -> String {
    items
        .iter()
        .map(|s| format!("{bullet}{} {}\n", if s.done { "[x]" } else { "[ ]" }, one_line(&s.title)))
        .collect()
}

fn subtasks_section(level: usize, bullet: &str, items: &[Subtask]) -> String {
    format!("{} Subtasks\n\n{}", "#".repeat(level.min(6)), subtask_lines(bullet, items))
}

// ---- rendering new blocks and files ----

pub fn render_task(level: usize, id: Uuid, t: &Task, defaults: &Defaults, names: &dyn Names, att_prefix: &str) -> String {
    let comment = comment_for(None, id, true, t, defaults, names).unwrap_or_default();
    let mut s = format!("{} {} {}\n{comment}\n", "#".repeat(level), t.status.marker(), one_line(&t.title));
    if !t.description.is_empty() {
        s.push_str(&format!("\n{}\n", t.description));
    }
    if !t.attachments.is_empty() {
        s.push('\n');
        s.push_str(&attachments::section(level + 1, &attachment_lines("- ", &t.attachments, att_prefix)));
    }
    if !t.subtasks.is_empty() {
        s.push('\n');
        s.push_str(&subtasks_section(level + 1, "- ", &t.subtasks));
    }
    s
}

pub fn render_sprint_file(s: &Sprint, assignee_handle: Option<String>, tasks: &[String]) -> String {
    let mut out = String::from("---\n");
    out.push_str(&format!("sprint_id: {}\n", s.id));
    if let Some((a, b)) = s.dates {
        out.push_str(&format!("starts_on: {a}\nends_on: {b}\n"));
    }
    if let Some(t) = &s.track {
        out.push_str(&format!("track: {}\n", doc::quote_front_scalar(t)));
    }
    if !s.tags.is_empty() {
        out.push_str(&format!("tags: {}\n", doc::format_front_list(&s.tags)));
    }
    if let Some(a) = assignee_handle {
        out.push_str(&format!("assignee: {}\n", doc::quote_front_scalar(&a)));
    }
    out.push_str(&format!("---\n\n# {}\n", one_line(&s.title)));
    if !s.description.is_empty() {
        out.push_str(&format!("\n{}\n", s.description));
    }
    for t in tasks {
        out.push('\n');
        out.push_str(t);
    }
    out
}

/// Text to append `block` at the end of `text`, with one blank line between.
pub fn append(text: &str, block: &str) -> Edit {
    let sep = if text.is_empty() || text.ends_with("\n\n") {
        ""
    } else if text.ends_with('\n') {
        "\n"
    } else {
        "\n\n"
    };
    let mut b = block.to_string();
    if !b.ends_with('\n') {
        b.push('\n');
    }
    Edit::insert(text.len(), format!("{sep}{b}"))
}

/// Apply a task's own edits to its block alone and re-level its heading
/// (and Subtasks heading) for a different file type.
pub fn extract_block(text: &str, b: &TaskBlock, edits: &[Edit], to_level: usize) -> anyhow::Result<String> {
    let shifted: Vec<Edit> = edits
        .iter()
        .map(|e| Edit::replace(e.range.start - b.block.start..e.range.end - b.block.start, e.text.clone()))
        .collect();
    let mut block = apply_edits(&text[b.block.clone()], &shifted)?;
    let trimmed = block.trim_end().len();
    block.truncate(trimmed);
    block.push('\n');
    let parsed = doc::parse("block".into(), "block".into(), block.clone(), DocKind::Single)
        .map_err(|e| anyhow::anyhow!("internal error re-reading a moved task: {}", e.join("; ")))?;
    let t = &parsed.tasks[0];
    let mut relevel = vec![Edit::replace(0..t.level, "#".repeat(to_level))];
    if let Some(sec) = &t.subtasks {
        let hashes = sec.level;
        relevel.push(Edit::replace(sec.heading.start..sec.heading.start + hashes, "#".repeat((to_level + 1).min(6))));
    }
    if let Some(sec) = &t.attachments {
        let hashes = sec.level;
        relevel.push(Edit::replace(sec.heading.start..sec.heading.start + hashes, "#".repeat((to_level + 1).min(6))));
    }
    apply_edits(&block, &relevel)
}

// ---- sprint frontmatter ----

pub struct SprintWrite<'a> {
    pub cur: &'a Sprint,
    pub target: &'a Sprint,
    pub id_is_new: bool,
    /// Current raw assignee resolves to the target user.
    pub assignee_ok: bool,
}

pub fn sprint_edits(doc: &Doc, w: &SprintWrite, names: &dyn Names) -> Vec<Edit> {
    let mut edits = vec![];
    let mut set: Vec<(&str, Option<String>)> = vec![];
    if w.cur.dates != w.target.dates {
        set.push(("starts_on", w.target.dates.map(|d| d.0.to_string())));
        set.push(("ends_on", w.target.dates.map(|d| d.1.to_string())));
    }
    if w.cur.track != w.target.track {
        set.push(("track", w.target.track.as_deref().map(doc::quote_front_scalar)));
    }
    if w.cur.tags != w.target.tags {
        set.push(("tags", (!w.target.tags.is_empty()).then(|| doc::format_front_list(&w.target.tags))));
    }
    if w.cur.assignee != w.target.assignee || !w.assignee_ok {
        set.push(("assignee", w.target.assignee.map(|u| doc::quote_front_scalar(&names.handle(u)))));
    }
    if w.id_is_new {
        edits.push(sprint_id_edit(doc, w.target.id));
    }
    if !set.is_empty() {
        match &doc.front {
            None => {
                let mut fm = String::new();
                if w.id_is_new {
                    // The id edit above already opens a frontmatter block;
                    // fold everything into one.
                    edits.pop();
                    fm.push_str(&format!("sprint_id: {}\n", w.target.id));
                }
                for (k, v) in &set {
                    if let Some(v) = v {
                        fm.push_str(&format!("{k}: {v}\n"));
                    }
                }
                edits.push(Edit::insert(0, format!("---\n{fm}---\n\n")));
            }
            Some(f) => {
                for (k, v) in set {
                    match (f.line_of(k), v) {
                        (Some(l), Some(v)) => edits.push(Edit::replace(l.range.clone(), format!("{k}: {v}\n"))),
                        (Some(l), None) => edits.push(Edit::replace(l.range.clone(), "")),
                        (None, Some(v)) => edits.push(Edit::insert(f.close_start, format!("{k}: {v}\n"))),
                        (None, None) => {}
                    }
                }
            }
        }
    }
    if w.cur.title != w.target.title {
        if let Some((_, r, _)) = &doc.title {
            edits.push(Edit::replace(r.clone(), one_line(&w.target.title)));
        }
    }
    if w.cur.description != w.target.description {
        if let Some((r, _)) = &doc.description {
            edits.push(description_edit(&doc.text, r.clone(), &w.target.description));
        }
    }
    edits
}

/// Replace the sprint description region (title line to first task) with
/// `desc`, one blank line on each side.
fn description_edit(text: &str, r: std::ops::Range<usize>, desc: &str) -> Edit {
    let mut s = String::new();
    if !text[..r.start].ends_with('\n') {
        s.push('\n');
    }
    let follows = r.end < text.len();
    if !desc.is_empty() {
        s.push('\n');
        s.push_str(desc);
        s.push('\n');
    }
    if follows {
        s.push('\n');
    }
    Edit::replace(r, s)
}

/// Reorder the task blocks of a sprint file so the tasks in `want` come
/// in that order, each taking a slot one of them had; other blocks stay.
/// Blocks keep their bytes apart from the blank lines between them.
pub fn reorder_blocks(doc: &Doc, want: &[Uuid]) -> String {
    let ids: Vec<Uuid> = doc.tasks.iter().map(|t| t.id().unwrap_or_default()).collect();
    let order = model::permute_slots(&ids, want);
    if order == ids || doc.tasks.is_empty() {
        return doc.text.clone();
    }
    let text = &doc.text;
    let start = doc.tasks[0].block.start;
    let block = |id: Uuid| {
        let i = ids.iter().position(|x| *x == id).expect("permutation");
        text[doc.tasks[i].block.clone()].trim_end().to_string()
    };
    let mut out = text[..start].to_string();
    let body: Vec<String> = order.iter().map(|id| block(*id)).collect();
    out.push_str(&body.join("\n\n"));
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doc::parse;
    use crate::model::Status;

    struct N;
    impl Names for N {
        fn resolve_user(&self, name: &str) -> Option<Uuid> {
            (name == "ann").then_some(Uuid::from_u128(1))
        }
        fn handle(&self, _: Uuid) -> String {
            "ann".into()
        }
    }

    const ID: &str = "0b5a8c1e-2d3f-4a5b-8c7d-9e0f1a2b3c4d";

    fn sprint(text: &str) -> Doc {
        parse("x.md".into(), "x.md".into(), text.into(), DocKind::Sprint).unwrap()
    }

    fn fmt(text: &str) -> String {
        let d = sprint(text);
        let ids: Vec<(Uuid, bool)> = d
            .tasks
            .iter()
            .map(|t| t.id().map_or((Uuid::from_u128(7), true), |id| (id, false)))
            .collect();
        let sid = d.front.as_ref().and_then(|f| f.sprint_id).map_or((Uuid::from_u128(9), true), |i| (i, false));
        apply_edits(&d.text, &fmt_edits(&d, Some(sid), &ids)).unwrap()
    }

    #[test]
    fn fmt_inserts_ids_and_keeps_prose() {
        let src = "# S\n\nProse  with   odd spacing.\n\n\n## [ x ] A\n\nBody line\nwrapped here.\n\n## [ ] B\n<!-- task: estimate=2h tags=x -->\n";
        let out = fmt(src);
        assert_eq!(
            out,
            "---\nsprint_id: 00000000-0000-0000-0000-000000000009\n---\n\n# S\n\nProse  with   odd spacing.\n\n\n## ✅ A\n<!-- task: id=00000000-0000-0000-0000-000000000007 -->\n\nBody line\nwrapped here.\n\n## ⬜ B\n<!-- task: id=00000000-0000-0000-0000-000000000007 tags=x estimate=2h -->\n"
        );
        // Idempotent.
        assert_eq!(fmt(&out), out);
    }

    #[test]
    fn emoji_markers_are_canonical() {
        let src = format!("---\nsprint_id: {ID}\n---\n# S\n\n## ⬜ A\n<!-- task: id={ID} -->\n\n## 🚧 B\n<!-- task: id=00000000-0000-0000-0000-00000000000b -->\n\n## ✅\u{FE0F} C\n<!-- task: id=00000000-0000-0000-0000-00000000000c -->\n");
        let d = sprint(&src);
        let st: Vec<Status> = d.tasks.iter().map(|t| t.status).collect();
        assert_eq!(st, [Status::Todo, Status::InProgress, Status::Done]);
        assert!(d.tasks.iter().all(|t| t.checkbox_canonical));
        assert_eq!(d.tasks[2].title, "C");
        assert_eq!(fmt(&src), src, "fmt leaves emoji alone");
    }

    #[test]
    fn fmt_pulls_comment_up_from_wysiwyg_spacing() {
        let src = format!("---\nsprint_id: {ID}\n---\n# S\n\n## [ ] A\n\n\n<!-- task: id={ID} -->\n\nBody\n");
        let out = fmt(&src);
        assert!(out.contains(&format!("## ⬜ A\n<!-- task: id={ID} -->\n\nBody\n")), "{out}");
    }

    #[test]
    fn fmt_moves_comment_out_of_the_middle() {
        let src = format!("---\nsprint_id: {ID}\n---\n# S\n\n## [ ] A\n\nFirst\n\n<!-- task: id={ID} -->\n\nSecond\n");
        let out = fmt(&src);
        assert!(out.ends_with(&format!("## ⬜ A\n<!-- task: id={ID} -->\n\nFirst\n\nSecond\n")), "{out}");
    }

    fn task_of(d: &Doc, i: usize, defaults: &Defaults) -> Task {
        let b = &d.tasks[i];
        let c = b.comment.as_ref();
        Task {
            id: b.id().unwrap_or_default(),
            title: b.title.clone(),
            description: b.description.clone(),
            status: b.status,
            sprint: None,
            tags: c.and_then(|c| c.tags.clone()).unwrap_or(defaults.tags.clone()),
            assignee: match c.and_then(|c| c.assignee.as_deref()) {
                Some("") => None,
                Some(n) => N.resolve_user(n),
                None => defaults.assignee,
            },
            estimate_min: c.and_then(|c| c.estimate),
            subtasks: b.subtasks.as_ref().map(|s| s.items.clone()).unwrap_or_default(),
            attachments: b
                .attachments
                .as_ref()
                .map(|s| s.items.iter().map(|i| att(attachments::item_name(&i.link))).collect())
                .unwrap_or_default(),
        }
    }

    fn att(name: &str) -> Attachment {
        Attachment { name: name.into(), sha256: String::new(), size: 0 }
    }

    fn edit_task(src: &str, f: impl Fn(&mut Task), defaults: &Defaults) -> String {
        let d = sprint(src);
        let cur = task_of(&d, 0, defaults);
        let mut target = cur.clone();
        f(&mut target);
        let comment = comment_for(Some(&d.tasks[0]), cur.id, false, &target, defaults, &N);
        let edits = task_edits(&d.text, &d.tasks[0], &cur, &target, comment, &format!("../assets/{ID}/"));
        apply_edits(&d.text, &edits).unwrap()
    }

    #[test]
    fn status_and_subtask_edits_are_surgical() {
        let src = format!("# S\n\n## [ ] A\n<!-- task: id={ID} -->\n\nKeep   this\n\n### Subtasks\n\n* [ ] one\n* [ ] two\n\n## [ ] B\n");
        let out = edit_task(&src, |t| {
            t.status = Status::Done;
            t.subtasks[0].done = true;
        }, &Defaults::default());
        assert_eq!(out, format!("# S\n\n## ✅ A\n<!-- task: id={ID} -->\n\nKeep   this\n\n### Subtasks\n\n* [x] one\n* [ ] two\n\n## [ ] B\n"));
    }

    #[test]
    fn description_rewrite_keeps_comment_and_spacing() {
        let src = format!("# S\n\n## [ ] A\n<!-- task: id={ID} -->\n\nOld\n\n### Subtasks\n\n- [ ] one\n");
        let out = edit_task(&src, |t| t.description = "New\n\ntext".into(), &Defaults::default());
        assert_eq!(out, format!("# S\n\n## [ ] A\n<!-- task: id={ID} -->\n\nNew\n\ntext\n\n### Subtasks\n\n- [ ] one\n"));
    }

    #[test]
    fn adding_and_removing_subtasks() {
        let src = format!("# S\n\n## [ ] A\n<!-- task: id={ID} -->\n\nBody\n\n## [ ] B\n");
        let out = edit_task(&src, |t| t.subtasks = vec![Subtask { title: "x".into(), done: false }], &Defaults::default());
        assert_eq!(out, format!("# S\n\n## [ ] A\n<!-- task: id={ID} -->\n\nBody\n\n### Subtasks\n\n- [ ] x\n\n## [ ] B\n"));
        let back = edit_task(&out, |t| t.subtasks.clear(), &Defaults::default());
        assert_eq!(back, src);
    }

    #[test]
    fn inheritance_keeps_keys_clean() {
        let defaults = Defaults { tags: vec!["frontend".into()], assignee: None };
        let src = format!("# S\n\n## [ ] A\n<!-- task: id={ID} -->\n");
        // Same as the sprint: nothing to write.
        let d = sprint(&src);
        let cur = task_of(&d, 0, &defaults);
        assert!(comment_for(Some(&d.tasks[0]), cur.id, false, &cur, &defaults, &N).is_none());
        // Different from the sprint: explicit key.
        let out = edit_task(&src, |t| t.tags = vec!["bug".into()], &defaults);
        assert!(out.contains(&format!("<!-- task: id={ID} tags=bug -->")));
        // No tags while the sprint has some: explicit empty.
        let out = edit_task(&src, |t| t.tags = vec![], &defaults);
        assert!(out.contains("tags=\"\""), "{out}");
        // Back to the sprint's value: key dropped.
        let d2 = sprint(&out);
        let cur2 = task_of(&d2, 0, &defaults);
        let mut target = cur2.clone();
        target.tags = vec!["frontend".into()];
        let c = comment_for(Some(&d2.tasks[0]), cur2.id, false, &target, &defaults, &N).unwrap();
        assert_eq!(c, format!("<!-- task: id={ID} -->"));
    }

    #[test]
    fn sprint_level_change_pins_inheriting_task() {
        // The sprint's tags change from [a] to [b]; the task must keep [a].
        let old = Defaults { tags: vec!["a".into()], assignee: None };
        let new = Defaults { tags: vec!["b".into()], assignee: None };
        let src = format!("# S\n\n## [ ] A\n<!-- task: id={ID} -->\n");
        let d = sprint(&src);
        let cur = task_of(&d, 0, &old);
        let c = comment_for(Some(&d.tasks[0]), cur.id, false, &cur, &new, &N).unwrap();
        assert_eq!(c, format!("<!-- task: id={ID} tags=a -->"));
    }

    #[test]
    fn extract_relevels_for_single_file() {
        let src = format!("# S\n\n## [ ] A\n<!-- task: id={ID} -->\n\nBody\n\n### Subtasks\n\n- [ ] one\n\n## [ ] B\n");
        let d = sprint(&src);
        let out = extract_block(&d.text, &d.tasks[0], &[], 1).unwrap();
        assert_eq!(out, format!("# [ ] A\n<!-- task: id={ID} -->\n\nBody\n\n## Subtasks\n\n- [ ] one\n"));
    }

    #[test]
    fn attachment_section_add_change_remove() {
        let p = format!("../assets/{ID}/");
        let src = format!("# S\n\n## [ ] A\n<!-- task: id={ID} -->\n\nBody\n\n### Subtasks\n\n- [ ] one\n");
        // Added before Subtasks.
        let out = edit_task(&src, |t| t.attachments = vec![att("a.png")], &Defaults::default());
        assert_eq!(out, format!("# S\n\n## [ ] A\n<!-- task: id={ID} -->\n\nBody\n\n### Attachments\n\n- [a.png]({p}a.png)\n\n### Subtasks\n\n- [ ] one\n"));
        // Labels and order of kept items survive; new ones are appended.
        let custom = out.replace("- [a.png]", "- [The layout]");
        let out2 = edit_task(&custom, |t| t.attachments = vec![att("a.png"), att("b.pdf")], &Defaults::default());
        assert!(out2.contains(&format!("- [The layout]({p}a.png)\n- [b.pdf]({p}b.pdf)\n\n### Subtasks")), "{out2}");
        // Removed again: back to the original.
        assert_eq!(edit_task(&out, |t| t.attachments.clear(), &Defaults::default()), src);
        // With a description change in the same edit, and no other section.
        let plain = format!("# S\n\n## [ ] A\n<!-- task: id={ID} -->\n\nBody\n");
        let out3 = edit_task(&plain, |t| { t.description = "New".into(); t.attachments = vec![att("a.png")]; }, &Defaults::default());
        assert_eq!(out3, format!("# S\n\n## [ ] A\n<!-- task: id={ID} -->\n\nNew\n\n### Attachments\n\n- [a.png]({p}a.png)\n"));
        let out4 = edit_task(&plain, |t| t.attachments = vec![att("a.png")], &Defaults::default());
        assert_eq!(out4, out3.replace("New", "Body"));
    }

    #[test]
    fn rendered_task_parses_back() {
        let t = Task {
            id: Uuid::from_u128(5),
            title: "New".into(),
            description: "Desc".into(),
            status: Status::InProgress,
            sprint: None,
            tags: vec!["bug".into(), "needs review".into()],
            assignee: Some(Uuid::from_u128(1)),
            estimate_min: Some(90),
            subtasks: vec![Subtask { title: "s".into(), done: true }],
            attachments: vec![att("a.png")],
        };
        let r = render_task(2, t.id, &t, &Defaults::default(), &N, "../assets/x/");
        let d = sprint(&format!("# S\n\n{r}"));
        assert_eq!(task_of(&d, 0, &Defaults::default()), t);
    }
}
