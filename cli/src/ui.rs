//! Showing a comparison (text with optional colour, or JSON) and asking
//! the user per differing field, like `git add -p`.

use std::io::{BufRead, IsTerminal, Write};

use anyhow::{bail, Result};
use serde_json::{json, Value};

use crate::fira::Snapshot;
use crate::model::{self, Sprint, Task};
use crate::repo::Repo;
use crate::sync::{Comparison, DeletedChoice, Decisions, Entity, Field, Kind, Mode, Resolver, Side, State};

pub struct Style {
    pub color: bool,
}

impl Style {
    fn paint(&self, code: &str, s: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    fn bold(&self, s: &str) -> String {
        self.paint("1", s)
    }
    fn local(&self, s: &str) -> String {
        self.paint("32", s)
    }
    fn remote(&self, s: &str) -> String {
        self.paint("36", s)
    }
    fn dim(&self, s: &str) -> String {
        self.paint("2", s)
    }
    fn warn(&self, s: &str) -> String {
        self.paint("33", s)
    }
}

pub fn interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

pub fn color_ok() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

/// Values of one field on one side, ready to print.
enum Disp {
    Line(String),
    Lines(Vec<String>),
    Text(String),
}

fn none(s: &str) -> String {
    format!("({s})")
}

fn sprint_label(snap: &Snapshot, repo: &Repo, id: Option<uuid::Uuid>) -> String {
    match id {
        None => none("no sprint"),
        Some(id) => snap
            .sprints
            .iter()
            .find(|s| s.id == id)
            .map(|s| s.title.clone())
            .or_else(|| repo.sprint_doc(id).and_then(|d| repo.docs[d].title.as_ref().map(|t| t.0.clone())))
            .unwrap_or_else(|| id.to_string()),
    }
}

fn task_value(t: &Task, f: Field, r: &Resolver, repo: &Repo) -> Disp {
    match f {
        Field::Title => Disp::Line(t.title.clone()),
        Field::Status => Disp::Line(format!("{} {}", t.status.marker(), t.status.label())),
        Field::Sprint => Disp::Line(sprint_label(r.snap, repo, t.sprint)),
        Field::Tags => Disp::Line(if t.tags.is_empty() { none("none") } else { t.tags.join(", ") }),
        Field::Assignee => Disp::Line(t.assignee.map_or_else(|| none("nobody"), |u| r.handle_of(u))),
        Field::Estimate => Disp::Line(t.estimate_min.map_or_else(|| none("none"), model::format_estimate)),
        Field::Description => Disp::Text(t.description.clone()),
        Field::Subtasks => Disp::Lines(if t.subtasks.is_empty() {
            vec![none("none")]
        } else {
            t.subtasks.iter().map(|s| format!("{} {}", if s.done { "[x]" } else { "[ ]" }, s.title)).collect()
        }),
        Field::Dates | Field::Track => Disp::Line(String::new()),
    }
}

fn sprint_value(s: &Sprint, f: Field, r: &Resolver) -> Disp {
    match f {
        Field::Title => Disp::Line(s.title.clone()),
        Field::Dates => Disp::Line(model::format_dates(s.dates).unwrap_or_else(|| none("unscheduled"))),
        Field::Track => Disp::Line(s.track.clone().unwrap_or_else(|| none("no track"))),
        Field::Tags => Disp::Line(if s.tags.is_empty() { none("none") } else { s.tags.join(", ") }),
        Field::Assignee => Disp::Line(s.assignee.map_or_else(|| none("nobody"), |u| r.handle_of(u))),
        _ => Disp::Line(String::new()),
    }
}

fn values(e: &Entity, f: Field, r: &Resolver, repo: &Repo) -> (Disp, Disp) {
    match e.kind {
        Kind::Task => (
            task_value(e.local_task.as_ref().unwrap(), f, r, repo),
            task_value(e.remote_task.as_ref().unwrap(), f, r, repo),
        ),
        Kind::Sprint => (
            sprint_value(e.local_sprint.as_ref().unwrap(), f, r),
            sprint_value(e.remote_sprint.as_ref().unwrap(), f, r),
        ),
    }
}

/// One field, local vs Fira.
fn render_field(out: &mut String, st: &Style, indent: &str, name: &str, local_label: &str, l: Disp, rm: Disp) {
    let pad = format!("{name:<10}");
    let gap = " ".repeat(10);
    let ll = format!("{local_label}:");
    let w = ll.len().max(5);
    match (l, rm) {
        (Disp::Line(a), Disp::Line(b)) => {
            if a.chars().count() <= 24 && b.chars().count() <= 24 {
                out.push_str(&format!(
                    "{indent}{pad}{} {}   {} {}\n",
                    st.local(&format!("{ll:<w$}")),
                    st.local(&format!("{a:<24}")),
                    st.remote("fira:"),
                    st.remote(&b)
                ));
            } else {
                out.push_str(&format!("{indent}{pad}{} {}\n", st.local(&format!("{ll:<w$}")), st.local(&a)));
                out.push_str(&format!("{indent}{gap}{} {}\n", st.remote(&format!("{:<w$}", "fira:")), st.remote(&b)));
            }
        }
        (Disp::Lines(a), Disp::Lines(b)) => {
            for (i, line) in a.iter().enumerate() {
                let lab = if i == 0 { format!("{ll:<w$}") } else { " ".repeat(w) };
                let p = if i == 0 { pad.clone() } else { gap.clone() };
                out.push_str(&format!("{indent}{p}{} {}\n", st.local(&lab), st.local(line)));
            }
            for (i, line) in b.iter().enumerate() {
                let lab = if i == 0 { format!("{:<w$}", "fira:") } else { " ".repeat(w) };
                out.push_str(&format!("{indent}{gap}{} {}\n", st.remote(&lab), st.remote(line)));
            }
        }
        (Disp::Text(a), Disp::Text(b)) => {
            out.push_str(&format!("{indent}{name}   ({} {local_label}, {} fira)\n", st.local("+"), st.remote("-")));
            let diff = similar::TextDiff::from_lines(&b, &a);
            for group in diff.grouped_ops(2) {
                for op in group {
                    for change in diff.iter_changes(&op) {
                        let line = change.value().trim_end_matches('\n');
                        let s = match change.tag() {
                            similar::ChangeTag::Delete => st.remote(&format!("- {line}")),
                            similar::ChangeTag::Insert => st.local(&format!("+ {line}")),
                            similar::ChangeTag::Equal => st.dim(&format!("  {line}")),
                        };
                        out.push_str(&format!("{indent}  {s}\n"));
                    }
                }
                out.push_str(&format!("{indent}  {}\n", st.dim("…")));
            }
        }
        _ => {}
    }
}

fn location(repo: &Repo, e: &Entity) -> String {
    match (e.kind, e.task, e.doc) {
        (Kind::Task, Some(t), _) => format!("{}:{}", repo.docs[t.doc].display, repo.docs[t.doc].tasks[t.task].line),
        (_, _, Some(d)) => repo.docs[d].display.clone(),
        _ => "not in any file".into(),
    }
}

fn state_note(st: &Style, mode: Mode, e: &Entity) -> String {
    match e.state {
        State::InSync => st.dim("in sync"),
        State::Differs => String::new(),
        State::New => st.local(if mode == Mode::Publish { "new: will be created in Fira" } else { "new: not in Fira yet" }),
        State::DeletedInFira => st.warn("deleted in Fira, still in the repo"),
        State::NotInFira => st.dim("not in Fira (publish to create it); not touched"),
        State::OtherProject => st.warn("belongs to another Fira project; not touched"),
        State::NewLocal => st.remote(if mode == Mode::Import { "new: will be added locally" } else { "only in Fira" }),
    }
}

fn entity_values_for_new(e: &Entity, r: &Resolver, repo: &Repo) -> Vec<(Field, Disp)> {
    let mut out = vec![];
    match e.kind {
        Kind::Task => {
            let t = e.local_task.as_ref().or(e.remote_task.as_ref()).unwrap();
            for f in [Field::Status, Field::Sprint, Field::Tags, Field::Assignee, Field::Estimate, Field::Subtasks] {
                let empty = match f {
                    Field::Tags => t.tags.is_empty(),
                    Field::Assignee => t.assignee.is_none(),
                    Field::Estimate => t.estimate_min.is_none(),
                    Field::Subtasks => t.subtasks.is_empty(),
                    Field::Sprint => t.sprint.is_none(),
                    _ => false,
                };
                if !empty {
                    out.push((f, task_value(t, f, r, repo)));
                }
            }
        }
        Kind::Sprint => {
            let s = e.local_sprint.as_ref().or(e.remote_sprint.as_ref()).unwrap();
            for f in [Field::Dates, Field::Track, Field::Tags, Field::Assignee] {
                let empty = match f {
                    Field::Dates => s.dates.is_none(),
                    Field::Track => s.track.is_none(),
                    Field::Tags => s.tags.is_empty(),
                    _ => s.assignee.is_none(),
                };
                if !empty {
                    out.push((f, sprint_value(s, f, r)));
                }
            }
        }
    }
    out
}

pub fn render(repo: &Repo, cmp: &Comparison, st: &Style, local_label: &str, all: bool) -> String {
    let r = Resolver::new(&cmp.snap);
    let mut out = String::new();
    let mut shown = vec![false; cmp.entities.len()];
    let render_one = |out: &mut String, e: &Entity, indent: &str| {
        let what = if e.kind == Kind::Sprint { "sprint" } else { "task" };
        let head = format!("{indent}{what} {}", st.bold(&format!("\"{}\"", e.title())));
        let loc = st.dim(&format!("({})", location(repo, e)));
        let note = state_note(st, cmp.mode, e);
        out.push_str(&format!("{head}  {loc}  {note}\n"));
        let inner = format!("{indent}  ");
        match e.state {
            State::Differs => {
                for f in &e.fields {
                    let (l, rm) = values(e, f.field, &r, repo);
                    render_field(out, st, &inner, f.field.name(), local_label, l, rm);
                    if let Some(n) = &f.note {
                        out.push_str(&format!("{inner}{}\n", st.warn(&format!("  note: {n}"))));
                    }
                }
            }
            State::New | State::NewLocal if all || e.kind == Kind::Task => {
                for (f, d) in entity_values_for_new(e, &r, repo) {
                    if let Disp::Line(v) = d {
                        out.push_str(&format!("{inner}{:<10}{v}\n", f.name()));
                    } else if let Disp::Lines(v) = d {
                        for (i, line) in v.iter().enumerate() {
                            let n = if i == 0 { f.name() } else { "" };
                            out.push_str(&format!("{inner}{n:<10}{line}\n"));
                        }
                    }
                }
            }
            _ => {}
        }
    };
    for (i, e) in cmp.entities.iter().enumerate() {
        if e.kind != Kind::Sprint {
            continue;
        }
        shown[i] = true;
        render_one(&mut out, e, "");
        for (j, t) in cmp.entities.iter().enumerate() {
            if shown[j] || t.kind != Kind::Task {
                continue;
            }
            let belongs = match (t.doc, e.doc) {
                (Some(td), Some(sd)) => td == sd,
                (None, _) => t.remote_task.as_ref().is_some_and(|rt| rt.sprint == Some(e.id)),
                _ => false,
            };
            if belongs {
                shown[j] = true;
                if t.state == State::InSync && !all {
                    out.push_str(&format!("  task \"{}\"  {}\n", t.title(), st.dim("in sync")));
                } else {
                    render_one(&mut out, t, "  ");
                }
            }
        }
    }
    for (j, t) in cmp.entities.iter().enumerate() {
        if !shown[j] {
            render_one(&mut out, t, "");
        }
    }
    for n in &cmp.notices {
        out.push_str(&format!("{}\n", st.warn(n)));
    }
    out
}

pub fn render_json(repo: &Repo, cmp: &Comparison) -> Value {
    let r = Resolver::new(&cmp.snap);
    let val = |e: &Entity, f: Field, local: bool| -> Value {
        match e.kind {
            Kind::Task => {
                let t = if local { e.local_task.as_ref() } else { e.remote_task.as_ref() }.unwrap();
                match f {
                    Field::Title => json!(t.title),
                    Field::Status => json!(t.status),
                    Field::Sprint => json!(t.sprint),
                    Field::Tags => json!(t.tags),
                    Field::Assignee => json!(t.assignee.map(|u| r.handle_of(u))),
                    Field::Estimate => json!(t.estimate_min.map(model::format_estimate)),
                    Field::Description => json!(t.description),
                    Field::Subtasks => json!(t.subtasks),
                    _ => Value::Null,
                }
            }
            Kind::Sprint => {
                let s = if local { e.local_sprint.as_ref() } else { e.remote_sprint.as_ref() }.unwrap();
                match f {
                    Field::Title => json!(s.title),
                    Field::Dates => json!(s.dates.map(|(a, b)| json!({"starts_on": a, "ends_on": b}))),
                    Field::Track => json!(s.track),
                    Field::Tags => json!(s.tags),
                    Field::Assignee => json!(s.assignee.map(|u| r.handle_of(u))),
                    _ => Value::Null,
                }
            }
        }
    };
    let entities: Vec<Value> = cmp
        .entities
        .iter()
        .map(|e| {
            json!({
                "kind": if e.kind == Kind::Sprint { "sprint" } else { "task" },
                "id": e.id,
                "id_assigned": !e.id_new,
                "title": e.title(),
                "location": location(repo, e),
                "state": e.state,
                "fields": e.fields.iter().map(|f| json!({
                    "field": f.field,
                    "local": val(e, f.field, true),
                    "fira": val(e, f.field, false),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({ "in_sync": cmp.in_sync(), "entities": entities, "notices": cmp.notices })
}

/// Print through `$PAGER` (default `less -R`) when stdout is a terminal.
pub fn page(text: &str, no_pager: bool) {
    if no_pager || !std::io::stdout().is_terminal() || text.lines().count() < 20 {
        print!("{text}");
        return;
    }
    let pager = std::env::var("PAGER").ok().filter(|p| !p.trim().is_empty()).unwrap_or_else(|| "less -R".into());
    let mut parts = pager.split_whitespace();
    let Some(cmd) = parts.next() else {
        print!("{text}");
        return;
    };
    let child = std::process::Command::new(cmd)
        .args(parts)
        .env("LESS", std::env::var("LESS").unwrap_or_else(|_| "FRX".into()))
        .stdin(std::process::Stdio::piped())
        .spawn();
    match child {
        Ok(mut c) => {
            if let Some(mut stdin) = c.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            let _ = c.wait();
        }
        Err(_) => print!("{text}"),
    }
}

fn ask(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line)? == 0 {
        bail!("input closed; nothing was written");
    }
    Ok(line.trim().to_string())
}

pub struct Quit;

/// Ask per differing field. `Err(Quit)` = the user quit; nothing is written.
pub fn choose(repo: &Repo, cmp: &Comparison, st: &Style, local_label: &str) -> Result<Result<Decisions, Quit>> {
    let r = Resolver::new(&cmp.snap);
    let mut d = Decisions::default();
    let mut everything: Option<Side> = None;
    for e in &cmp.entities {
        if e.state == State::DeletedInFira {
            eprintln!(
                "\ntask {} ({}) was deleted in Fira but is still in the repo.",
                st.bold(&format!("\"{}\"", e.title())),
                location(repo, e)
            );
            loop {
                match ask("[r]ecreate in Fira (same id)  [d]elete locally  [s]kip  [q]uit > ")?.as_str() {
                    "r" => break d.deleted.insert(e.id, DeletedChoice::Recreate),
                    "d" => break d.deleted.insert(e.id, DeletedChoice::DeleteLocal),
                    "s" => break d.deleted.insert(e.id, DeletedChoice::Skip),
                    "q" => return Ok(Err(Quit)),
                    _ => eprintln!("There is no default here; pick r, d, s or q."),
                }
            };
            continue;
        }
        let mut entity_side: Option<Side> = None;
        for f in &e.fields {
            let bulk = everything.or(entity_side);
            if let Some(side) = bulk {
                let ok = if side == Side::Local { f.allow_local } else { f.allow_remote };
                if ok {
                    d.fields.insert((e.id, f.field), side);
                } else {
                    eprintln!("skipped {} of \"{}\": {}", f.field.name(), e.title(), f.note.clone().unwrap_or_default());
                }
                continue;
            }
            let what = if e.kind == Kind::Sprint { "sprint" } else { "task" };
            let mut block = format!("\n{what} {}  {}\n", st.bold(&format!("\"{}\"", e.title())), st.dim(&format!("({})", location(repo, e))));
            let (l, rm) = values(e, f.field, &r, repo);
            render_field(&mut block, st, "  ", f.field.name(), local_label, l, rm);
            if let Some(n) = &f.note {
                block.push_str(&format!("  {}\n", st.warn(&format!("note: {n}"))));
            }
            eprint!("{block}");
            let e_key = if e.kind == Kind::Sprint { "sprint" } else { "task" };
            let prompt = format!(
                "[l]ocal [r]emote  [t] {e_key}: all local  [T] {e_key}: all remote\n[L] everything local  [R] everything remote  [s]kip  [q]uit  [?] > "
            );
            loop {
                let a = ask(&prompt)?;
                let pick = |side: Side| -> bool {
                    let ok = if side == Side::Local { f.allow_local } else { f.allow_remote };
                    if !ok {
                        eprintln!("Not possible for this field: {}", f.note.clone().unwrap_or_default());
                    }
                    ok
                };
                match a.as_str() {
                    "l" if pick(Side::Local) => {
                        d.fields.insert((e.id, f.field), Side::Local);
                        break;
                    }
                    "r" if pick(Side::Remote) => {
                        d.fields.insert((e.id, f.field), Side::Remote);
                        break;
                    }
                    "t" | "T" | "L" | "R" => {
                        let side = if a == "t" || a == "L" { Side::Local } else { Side::Remote };
                        if a == "L" || a == "R" {
                            everything = Some(side);
                        } else {
                            entity_side = Some(side);
                        }
                        if pick(side) {
                            d.fields.insert((e.id, f.field), side);
                        }
                        break;
                    }
                    "s" => break,
                    "q" => return Ok(Err(Quit)),
                    "l" | "r" => {}
                    _ => eprintln!(
                        "l  use the local value for this field (written to Fira)\n\
                         r  use Fira's value for this field (written to the file)\n\
                         t/T  local/Fira for every remaining field of this {e_key}\n\
                         L/R  local/Fira for every remaining field of everything\n\
                         s  skip: leave this field different on both sides\n\
                         q  quit: write nothing"
                    ),
                }
            }
        }
    }
    Ok(Ok(d))
}

pub fn confirm(question: &str) -> Result<bool> {
    let a = ask(&format!("{question} [y/N] > "))?;
    Ok(matches!(a.as_str(), "y" | "Y" | "yes"))
}
