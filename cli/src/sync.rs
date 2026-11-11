//! The comparison between local documents and Fira, and the plan that
//! makes both sides agree once the user has chosen per field.
//!
//! Both sides are converted to the canonical model and matched by ID. No
//! sync state is stored anywhere, so nothing is pre-selected: for every
//! differing field the user picks local or remote, and the chosen value is
//! written to whichever side doesn't have it yet.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use anyhow::{bail, Result};
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;

use crate::doc::DocKind;
use crate::fira::{OpEnvelope, Precondition, RemoteSubtask, RemoteTask, Snapshot};
use crate::model::{self, Sprint, Status, Subtask, Task};
use crate::repo::{Repo, TaskRef, SINGLE_DIR, SPRINTS_DIR};
use crate::safety::{apply_edits, Edit};
use crate::write::{self, Defaults, Names};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Publish,
    Import,
    Diff,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    Title,
    Dates,
    Track,
    Tags,
    Assignee,
    Status,
    Description,
    Estimate,
    Subtasks,
    Sprint,
}

impl Field {
    pub fn name(self) -> &'static str {
        match self {
            Field::Title => "title",
            Field::Dates => "dates",
            Field::Track => "track",
            Field::Tags => "tags",
            Field::Assignee => "assignee",
            Field::Status => "status",
            Field::Description => "description",
            Field::Estimate => "estimate",
            Field::Subtasks => "subtasks",
            Field::Sprint => "sprint",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Local,
    Remote,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Sprint,
    Task,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeletedChoice {
    Recreate,
    DeleteLocal,
    Skip,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    InSync,
    Differs,
    /// Local only, never in Fira: publish creates it.
    New,
    /// Local only, deleted in Fira: ask.
    DeletedInFira,
    /// Local only, and the command doesn't create remote objects.
    NotInFira,
    /// Local only, but the id belongs to another Fira project.
    OtherProject,
    /// Remote only: import creates it locally.
    NewLocal,
}

#[derive(Debug, Clone)]
pub struct FieldDiff {
    pub field: Field,
    pub allow_local: bool,
    pub allow_remote: bool,
    /// Why a side can't be chosen.
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Entity {
    pub kind: Kind,
    pub id: Uuid,
    pub id_new: bool,
    /// Sprint: its doc. Task: the doc it is in.
    pub doc: Option<usize>,
    pub task: Option<TaskRef>,
    pub local_sprint: Option<Sprint>,
    pub remote_sprint: Option<Sprint>,
    pub local_task: Option<Task>,
    pub remote_task: Option<Task>,
    pub revision: Option<i64>,
    pub remote_subtasks: Vec<RemoteSubtask>,
    pub state: State,
    pub fields: Vec<FieldDiff>,
}

impl Entity {
    pub fn title(&self) -> &str {
        match self.kind {
            Kind::Sprint => self.local_sprint.as_ref().or(self.remote_sprint.as_ref()).map_or("", |s| &s.title),
            Kind::Task => self.local_task.as_ref().or(self.remote_task.as_ref()).map_or("", |t| &t.title),
        }
    }
}

pub struct Comparison {
    pub mode: Mode,
    pub snap: Snapshot,
    pub entities: Vec<Entity>,
    pub notices: Vec<String>,
    /// Destination doc for newly imported tasks (`import --into`).
    pub into: Option<usize>,
}

// ---- names ----

pub struct Resolver<'a> {
    pub snap: &'a Snapshot,
    handles: HashMap<Uuid, String>,
}

impl<'a> Resolver<'a> {
    pub fn new(snap: &'a Snapshot) -> Resolver<'a> {
        let people: Vec<crate::handles::Person> = snap
            .users
            .iter()
            .map(|u| crate::handles::Person { id: u.id, name: &u.name, member: u.member })
            .collect();
        Resolver { snap, handles: crate::handles::compute(&people) }
    }

    /// An assignee as written in a file: a handle like `maya.c` (see
    /// `handles.rs`), matched exactly, or a full email.
    pub fn user(&self, name: &str) -> Result<Uuid, String> {
        let users = &self.snap.users;
        let n = name.trim().to_lowercase();
        if n.contains('@') {
            return users
                .iter()
                .find(|u| u.email.eq_ignore_ascii_case(&n))
                .map(|u| u.id)
                .ok_or_else(|| format!("assignee {name:?} is not a member of project {}; {}", self.snap.project.title, self.member_list()));
        }
        // Members first: a former member can never take a member's handle.
        let mut by_member = users.iter().filter(|u| u.member).chain(users.iter().filter(|u| !u.member));
        if let Some(u) = by_member.find(|u| self.handles.get(&u.id).is_some_and(|h| *h == n)) {
            return Ok(u.id);
        }
        // No match: a rename, someone left, or a newcomer made a handle
        // longer. Suggest people with the same first name.
        let first = n.split('.').next().unwrap_or(&n);
        let similar: Vec<String> = users
            .iter()
            .filter(|u| u.member)
            .filter(|u| self.handles.get(&u.id).is_some_and(|h| h.split('.').next() == Some(first)))
            .map(|u| format!("{} ({})", self.handles[&u.id], u.name))
            .collect();
        let hint = if similar.is_empty() {
            self.member_list()
        } else {
            format!(
                "did you mean {}? (Handles grow when two members would share one; a rename or someone leaving the project changes them too.)",
                similar.join(" or ")
            )
        };
        Err(format!("assignee {name:?} matches no member of project {}; {hint}", self.snap.project.title))
    }

    fn member_list(&self) -> String {
        let mut m: Vec<String> = self
            .snap
            .users
            .iter()
            .filter(|u| u.member)
            .map(|u| format!("{} ({})", self.handles[&u.id], u.name))
            .collect();
        m.sort();
        if m.is_empty() {
            "the project has no members".into()
        } else {
            format!("members: {}", m.join(", "))
        }
    }

    pub fn is_active(&self, id: Uuid) -> bool {
        self.snap.users.iter().any(|u| u.id == id && u.active)
    }

    /// What files say for a user: their handle (`maya.c`).
    pub fn handle_of(&self, id: Uuid) -> String {
        self.handles.get(&id).cloned().unwrap_or_else(|| id.to_string())
    }

    pub fn tag_title(&self, id: Uuid) -> Option<String> {
        self.snap.tags.iter().find(|t| t.id == id).map(|t| t.title.clone())
    }

    pub fn track_title(&self, id: Uuid) -> Option<String> {
        self.snap.tracks.iter().find(|t| t.id == id).map(|t| t.title.clone())
    }

    /// Tags and tracks must already exist in Fira, spelled exactly. They
    /// are project structure, created and renamed by project leads in
    /// Fira; the CLI only uses them.
    fn check_title(&self, title: &str, known: &[crate::fira::Named], what: &str) -> Result<(), String> {
        if known.iter().any(|k| k.title == title) {
            return Ok(());
        }
        if let Some(k) = known.iter().find(|k| k.title.eq_ignore_ascii_case(title)) {
            return Err(format!("{what} {title:?} differs only in case from the existing {what} {:?} in Fira; use that spelling", k.title));
        }
        let mut names: Vec<&str> = known.iter().map(|k| k.title.as_str()).collect();
        names.sort_unstable();
        Err(format!(
            "no {what} {title:?} in project {}; {what}s are created by project leads in Fira (project settings){}",
            self.snap.project.title,
            if names.is_empty() { String::new() } else { format!(". Existing: {}", names.join(", ")) }
        ))
    }
}

impl Names for Resolver<'_> {
    fn resolve_user(&self, name: &str) -> Option<Uuid> {
        self.user(name).ok()
    }
    fn handle(&self, id: Uuid) -> String {
        self.handle_of(id)
    }
}

// ---- canonical conversion ----

pub fn local_sprint(repo: &Repo, doc: usize, r: &Resolver) -> Result<Sprint, Vec<String>> {
    let d = &repo.docs[doc];
    let mut errs = vec![];
    let fm = d.front.clone().unwrap_or_default();
    let at = |key: &str| fm.line_of(key).map_or(1, |l| l.line);
    let assignee = match &fm.assignee {
        Some(a) => match r.user(a) {
            Ok(u) => Some(u),
            Err(e) => {
                errs.push(format!("{}:{}: {e}", d.display, at("assignee")));
                None
            }
        },
        None => None,
    };
    let tags = fm.tags.clone().unwrap_or_default();
    for t in &tags {
        if let Err(e) = r.check_title(t, &r.snap.tags, "tag") {
            errs.push(format!("{}:{}: {e}", d.display, at("tags")));
        }
    }
    if let Some(t) = &fm.track {
        if let Err(e) = r.check_title(t, &r.snap.tracks, "track") {
            errs.push(format!("{}:{}: {e}", d.display, at("track")));
        }
    }
    if !errs.is_empty() {
        return Err(errs);
    }
    Ok(Sprint {
        id: repo.sprint_ids[doc].map(|s| s.id).unwrap_or_default(),
        title: d.title.as_ref().map(|t| t.0.clone()).unwrap_or_default(),
        dates: fm.dates,
        track: fm.track.clone(),
        tags,
        assignee,
    })
}

pub fn defaults_of(s: Option<&Sprint>) -> Defaults {
    s.map(|s| Defaults { tags: s.tags.clone(), assignee: s.assignee }).unwrap_or_default()
}

pub fn local_task(repo: &Repo, t: TaskRef, defaults: &Defaults, r: &Resolver) -> Result<Task, Vec<String>> {
    let d = &repo.docs[t.doc];
    let b = &d.tasks[t.task];
    let c = b.comment.as_ref();
    let line = c.map_or(b.line, |c| c.line);
    let mut errs = vec![];
    let assignee = match c.and_then(|c| c.assignee.as_deref()) {
        Some("") => None,
        Some(n) => match r.user(n) {
            Ok(u) => Some(u),
            Err(e) => {
                errs.push(format!("{}:{line}: {e}", d.display));
                None
            }
        },
        None => defaults.assignee,
    };
    let tags = c.and_then(|c| c.tags.clone()).unwrap_or_else(|| defaults.tags.clone());
    if c.and_then(|c| c.tags.as_ref()).is_some() {
        for tag in &tags {
            if let Err(e) = r.check_title(tag, &r.snap.tags, "tag") {
                errs.push(format!("{}:{line}: {e}", d.display));
            }
        }
    }
    if !errs.is_empty() {
        return Err(errs);
    }
    Ok(Task {
        id: repo.task_id(t),
        title: b.title.clone(),
        description: b.description.clone(),
        status: b.status,
        sprint: repo.sprint_of_doc(t.doc),
        tags,
        assignee,
        estimate_min: c.and_then(|c| c.estimate),
        subtasks: b.subtasks.as_ref().map(|s| s.items.clone()).unwrap_or_default(),
    })
}

pub fn remote_sprint(s: &crate::fira::RemoteSprint, r: &Resolver) -> Sprint {
    Sprint {
        id: s.id,
        title: s.title.clone(),
        dates: s.starts_on.zip(s.ends_on),
        track: s.track_id.and_then(|t| r.track_title(t)),
        tags: model::normalize_tags(s.default_tag_ids.iter().filter_map(|t| r.tag_title(*t)).collect()),
        assignee: s.default_assignee_id,
    }
}

pub fn remote_task(t: &RemoteTask, r: &Resolver) -> Task {
    Task {
        id: t.id,
        title: t.title.clone(),
        description: model::normalize_text(&t.description_md),
        status: Status::from_fira(&t.status),
        sprint: t.sprint_id,
        tags: model::normalize_tags(t.tag_ids.iter().filter_map(|x| r.tag_title(*x)).collect()),
        assignee: t.assignee_id,
        estimate_min: t.estimate_min,
        subtasks: t.subtasks.iter().map(|s| Subtask { title: s.title.clone(), done: s.done }).collect(),
    }
}

fn sprint_fields(a: &Sprint, b: &Sprint) -> Vec<Field> {
    let mut f = vec![];
    if a.title != b.title {
        f.push(Field::Title);
    }
    if a.dates != b.dates {
        f.push(Field::Dates);
    }
    if a.track != b.track {
        f.push(Field::Track);
    }
    if a.tags != b.tags {
        f.push(Field::Tags);
    }
    if a.assignee != b.assignee {
        f.push(Field::Assignee);
    }
    f
}

fn task_fields(a: &Task, b: &Task) -> Vec<Field> {
    let mut f = vec![];
    if a.title != b.title {
        f.push(Field::Title);
    }
    if a.status != b.status {
        f.push(Field::Status);
    }
    if a.sprint != b.sprint {
        f.push(Field::Sprint);
    }
    if a.tags != b.tags {
        f.push(Field::Tags);
    }
    if a.assignee != b.assignee {
        f.push(Field::Assignee);
    }
    if a.estimate_min != b.estimate_min {
        f.push(Field::Estimate);
    }
    if a.description != b.description {
        f.push(Field::Description);
    }
    if a.subtasks != b.subtasks {
        f.push(Field::Subtasks);
    }
    f
}

// ---- building a comparison ----

/// What the command covers.
pub enum Scope {
    /// Publish one file, or diff a set of files.
    Docs(Vec<usize>),
    /// Import one remote sprint or task.
    Remote(Uuid),
}

/// Ids to fetch for a scope.
pub fn fetch_ids(repo: &Repo, scope: &Scope) -> (Vec<Uuid>, Vec<Uuid>) {
    let mut sprints = vec![];
    let mut tasks = vec![];
    match scope {
        Scope::Docs(docs) => {
            for &d in docs {
                if let Some(s) = repo.sprint_ids[d].filter(|s| !s.new) {
                    sprints.push(s.id);
                }
                for t in repo.tasks_of(d) {
                    let id = repo.task_ids[t.doc][t.task];
                    if !id.new {
                        tasks.push(id.id);
                    }
                }
            }
        }
        Scope::Remote(id) => {
            sprints.push(*id);
            tasks.push(*id);
            // A sprint import also covers the tasks in its local file.
            if let Some(d) = repo.sprint_doc(*id) {
                for t in repo.tasks_of(d) {
                    let id = repo.task_ids[t.doc][t.task];
                    if !id.new {
                        tasks.push(id.id);
                    }
                }
            }
        }
    }
    (sprints, tasks)
}

pub fn build(repo: &Repo, snap: Snapshot, mode: Mode, scope: &Scope, into: Option<usize>) -> Result<Comparison> {
    let mut entities = vec![];
    let mut notices = vec![];
    let mut errors = vec![];
    let r = Resolver::new(&snap);

    let missing: HashMap<Uuid, String> = snap.missing.iter().map(|m| (m.id, m.state.clone())).collect();
    let remote_sprints: HashMap<Uuid, &crate::fira::RemoteSprint> = snap.sprints.iter().map(|s| (s.id, s)).collect();
    let remote_tasks: HashMap<Uuid, &RemoteTask> = snap.tasks.iter().map(|t| (t.id, t)).collect();

    // Local defaults per doc, for inheritance.
    let mut sprint_cache: HashMap<usize, Option<Sprint>> = HashMap::new();
    let mut local_sprint_of = |doc: usize, errors: &mut Vec<String>| -> Option<Sprint> {
        sprint_cache
            .entry(doc)
            .or_insert_with(|| {
                if repo.docs[doc].kind != DocKind::Sprint {
                    return None;
                }
                match local_sprint(repo, doc, &r) {
                    Ok(s) => Some(s),
                    Err(e) => {
                        errors.extend(e);
                        None
                    }
                }
            })
            .clone()
    };

    // Which sprints and tasks are in scope, locally and remotely.
    let mut sprint_docs: Vec<(Option<usize>, Uuid)> = vec![];
    let mut task_list: Vec<(Option<TaskRef>, Uuid)> = vec![];
    match scope {
        Scope::Docs(docs) => {
            for &d in docs {
                if let Some(s) = repo.sprint_ids[d] {
                    sprint_docs.push((Some(d), s.id));
                }
                for t in repo.tasks_of(d) {
                    task_list.push((Some(t), repo.task_id(t)));
                }
            }
        }
        Scope::Remote(id) => {
            if let Some(rs) = remote_sprints.get(id) {
                sprint_docs.push((repo.sprint_doc(rs.id), rs.id));
                for t in snap.tasks.iter().filter(|t| t.sprint_id == Some(*id)) {
                    task_list.push((repo.find_task(t.id), t.id));
                }
                if let Some(d) = repo.sprint_doc(*id) {
                    for t in repo.tasks_of(d) {
                        let tid = repo.task_id(t);
                        if !task_list.iter().any(|(_, x)| *x == tid) {
                            task_list.push((Some(t), tid));
                        }
                    }
                }
            } else if remote_tasks.contains_key(id) {
                task_list.push((repo.find_task(*id), *id));
            } else {
                let state = missing.get(id).map(String::as_str).unwrap_or("never");
                bail!(
                    "{id} is not a sprint or task in Fira project {} ({})",
                    snap.project.title,
                    match state {
                        "deleted" => "it was deleted",
                        "other_project" => "it belongs to another project; set project_id in tasks/config.toml",
                        _ => "no such id",
                    }
                );
            }
        }
    }

    // Sprints being created in this publish: tasks may join them.
    let creating_sprints: HashSet<Uuid> = sprint_docs
        .iter()
        .filter(|(_, id)| mode == Mode::Publish && !remote_sprints.contains_key(id) && missing.get(id).is_none_or(|s| s == "never"))
        .map(|(_, id)| *id)
        .collect();

    for (doc, id) in &sprint_docs {
        let local = doc.and_then(|d| local_sprint_of(d, &mut errors));
        let remote = remote_sprints.get(id).map(|s| remote_sprint(s, &r));
        let id_new = doc.and_then(|d| repo.sprint_ids[d]).is_some_and(|s| s.new);
        let state = match (&local, &remote) {
            (Some(l), Some(rm)) => {
                if sprint_fields(l, rm).is_empty() { State::InSync } else { State::Differs }
            }
            (Some(_), None) => local_only_state(mode, missing.get(id).map(String::as_str)),
            (None, Some(_)) => State::NewLocal,
            (None, None) => continue,
        };
        let mut fields = vec![];
        if let (Some(l), Some(rm)) = (&local, &remote) {
            for f in sprint_fields(l, rm) {
                let mut fd = FieldDiff { field: f, allow_local: true, allow_remote: true, note: None };
                if f == Field::Dates && l.dates.is_none() {
                    fd.allow_local = false;
                    fd.note = Some("Fira can't unschedule a sprint from the CLI; clear the dates in Fira or keep them locally".into());
                }
                if f == Field::Assignee {
                    if let Some(u) = l.assignee.filter(|u| !r.is_active(*u)) {
                        fd.allow_local = false;
                        fd.note = Some(format!("{} is not an active project member", r.handle_of(u)));
                    }
                }
                fields.push(fd);
            }
        }
        if let Some(l) = &local {
            if state == State::New {
                if let Some(u) = l.assignee.filter(|u| !r.is_active(*u)) {
                    errors.push(format!("{}: sprint assignee {} is not an active member of the project", repo.docs[doc.unwrap()].display, r.handle_of(u)));
                }
            }
        }
        entities.push(Entity {
            kind: Kind::Sprint,
            id: *id,
            id_new,
            doc: *doc,
            task: None,
            local_sprint: local,
            remote_sprint: remote,
            local_task: None,
            remote_task: None,
            revision: remote_sprints.get(id).map(|s| s.revision),
            remote_subtasks: vec![],
            state,
            fields,
        });
    }

    // Is there (or will there be) a local file for this sprint?
    let sprint_has_file = |sid: Uuid| repo.sprint_doc(sid).is_some() || sprint_docs.iter().any(|(_, id)| *id == sid);
    let sprint_name = |sid: Uuid| -> String {
        snap.sprints
            .iter()
            .find(|s| s.id == sid)
            .map(|s| s.title.clone())
            .or_else(|| repo.sprint_doc(sid).and_then(|d| repo.docs[d].title.as_ref().map(|t| t.0.clone())))
            .unwrap_or_else(|| sid.to_string())
    };

    for (tref, id) in &task_list {
        let defaults = tref.map(|t| defaults_of(local_sprint_of(t.doc, &mut errors).as_ref())).unwrap_or_default();
        let local = match tref {
            Some(t) => match local_task(repo, *t, &defaults, &r) {
                Ok(x) => Some(x),
                Err(e) => {
                    errors.extend(e);
                    continue;
                }
            },
            None => None,
        };
        let rt = remote_tasks.get(id);
        let remote = rt.map(|t| remote_task(t, &r));
        let id_new = tref.is_some_and(|t| repo.task_ids[t.doc][t.task].new);
        let state = match (&local, &remote) {
            (Some(l), Some(rm)) => {
                if task_fields(l, rm).is_empty() { State::InSync } else { State::Differs }
            }
            (Some(_), None) => local_only_state(mode, missing.get(id).map(String::as_str)),
            (None, Some(_)) => State::NewLocal,
            (None, None) => continue,
        };
        let mut fields = vec![];
        if let (Some(l), Some(rm)) = (&local, &remote) {
            for f in task_fields(l, rm) {
                let mut fd = FieldDiff { field: f, allow_local: true, allow_remote: true, note: None };
                match f {
                    Field::Sprint => {
                        if let Some(sid) = rm.sprint.filter(|s| !sprint_has_file(*s)) {
                            fd.allow_remote = false;
                            fd.note = Some(format!(
                                "sprint \"{}\" has no local file; run `task-cli import fira {sid}` to bring it in",
                                sprint_name(sid)
                            ));
                        }
                        if let Some(sid) = l.sprint {
                            if !remote_sprints.contains_key(&sid) && !creating_sprints.contains(&sid) {
                                fd.allow_local = false;
                                fd.note = Some(format!("sprint \"{}\" is not in Fira yet; publish its file first", sprint_name(sid)));
                            }
                        }
                    }
                    Field::Assignee => {
                        if let Some(u) = l.assignee.filter(|u| !r.is_active(*u)) {
                            fd.allow_local = false;
                            fd.note = Some(format!("{} is not an active project member", r.handle_of(u)));
                        }
                    }
                    _ => {}
                }
                fields.push(fd);
            }
        }
        if let (Some(l), State::New) = (&local, state) {
            if let Some(u) = l.assignee.filter(|u| !r.is_active(*u)) {
                let t = tref.unwrap();
                errors.push(format!(
                    "{}:{}: assignee {} is not an active member of the project",
                    repo.docs[t.doc].display,
                    repo.docs[t.doc].tasks[t.task].line,
                    r.handle_of(u)
                ));
            }
        }
        entities.push(Entity {
            kind: Kind::Task,
            id: *id,
            id_new,
            doc: tref.map(|t| t.doc),
            task: *tref,
            local_sprint: None,
            remote_sprint: None,
            local_task: local,
            remote_task: remote,
            revision: rt.map(|t| t.revision),
            remote_subtasks: rt.map(|t| t.subtasks.clone()).unwrap_or_default(),
            state,
            fields,
        });
    }

    // Remote tasks in the sprints in scope that the comparison doesn't
    // cover. Absence is never acted on: these are only listed.
    if mode != Mode::Import {
        for (_, sid) in &sprint_docs {
            for t in snap.tasks.iter().filter(|t| t.sprint_id == Some(*sid)) {
                if task_list.iter().any(|(_, id)| *id == t.id) {
                    continue;
                }
                match repo.find_task(t.id) {
                    Some(tr) => notices.push(format!(
                        "in Fira sprint \"{}\" but in {} locally, not touched: \"{}\"",
                        sprint_name(*sid),
                        repo.docs[tr.doc].display,
                        t.title
                    )),
                    None => notices.push(format!(
                        "only in Fira, not touched: \"{}\" (in sprint \"{}\", in no file)",
                        t.title,
                        sprint_name(*sid)
                    )),
                }
            }
        }
    }

    if !errors.is_empty() {
        errors.dedup();
        bail!("{}", errors.join("\n"));
    }
    Ok(Comparison { mode, snap, entities, notices, into })
}

fn local_only_state(mode: Mode, missing: Option<&str>) -> State {
    match missing {
        Some("deleted") => State::DeletedInFira,
        Some("other_project") => State::OtherProject,
        _ if mode == Mode::Publish => State::New,
        _ => State::NotInFira,
    }
}

impl Comparison {
    pub fn in_sync(&self) -> bool {
        self.entities.iter().all(|e| e.state == State::InSync) && self.notices.is_empty()
    }

    /// Anything a publish/import could act on.
    pub fn actionable(&self) -> bool {
        self.entities.iter().any(|e| {
            matches!(e.state, State::Differs | State::DeletedInFira)
                || (e.state == State::New && self.mode == Mode::Publish)
                || (e.state == State::NewLocal && self.mode == Mode::Import)
                || (e.id_new && self.mode == Mode::Publish)
        })
    }
}

// ---- decisions ----

#[derive(Default)]
pub struct Decisions {
    pub fields: HashMap<(Uuid, Field), Side>,
    pub deleted: HashMap<Uuid, DeletedChoice>,
}

/// `--prefer`: answer every differing field in one direction; deleted
/// tasks are always skipped.
pub fn prefer(cmp: &Comparison, side: Side, notes: &mut Vec<String>) -> Decisions {
    let mut d = Decisions::default();
    for e in &cmp.entities {
        for f in &e.fields {
            let ok = match side {
                Side::Local => f.allow_local,
                Side::Remote => f.allow_remote,
            };
            if ok {
                d.fields.insert((e.id, f.field), side);
            } else {
                notes.push(format!(
                    "skipped {} of \"{}\": {}",
                    f.field.name(),
                    e.title(),
                    f.note.clone().unwrap_or_default()
                ));
            }
        }
        if e.state == State::DeletedInFira {
            d.deleted.insert(e.id, DeletedChoice::Skip);
        }
    }
    d
}

// ---- plan ----

pub enum FileWrite {
    Edit { doc: usize, new_text: String },
    Create { path: PathBuf, text: String },
    Remove { doc: usize },
}

pub struct Plan {
    pub ops: Vec<OpEnvelope>,
    pub pre: Vec<Precondition>,
    pub remote_lines: Vec<String>,
    pub local_lines: Vec<String>,
    pub files: Vec<FileWrite>,
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty() && self.files.is_empty()
    }
}

fn merge_sprint(a: &Sprint, b: &Sprint, take_b: &dyn Fn(Field) -> bool) -> Sprint {
    let mut s = a.clone();
    if take_b(Field::Title) {
        s.title = b.title.clone();
    }
    if take_b(Field::Dates) {
        s.dates = b.dates;
    }
    if take_b(Field::Track) {
        s.track = b.track.clone();
    }
    if take_b(Field::Tags) {
        s.tags = b.tags.clone();
    }
    if take_b(Field::Assignee) {
        s.assignee = b.assignee;
    }
    s
}

fn merge_task(a: &Task, b: &Task, take_b: &dyn Fn(Field) -> bool) -> Task {
    let mut t = a.clone();
    if take_b(Field::Title) {
        t.title = b.title.clone();
    }
    if take_b(Field::Status) {
        t.status = b.status;
    }
    if take_b(Field::Sprint) {
        t.sprint = b.sprint;
    }
    if take_b(Field::Tags) {
        t.tags = b.tags.clone();
    }
    if take_b(Field::Assignee) {
        t.assignee = b.assignee;
    }
    if take_b(Field::Estimate) {
        t.estimate_min = b.estimate_min;
    }
    if take_b(Field::Description) {
        t.description = b.description.clone();
    }
    if take_b(Field::Subtasks) {
        t.subtasks = b.subtasks.clone();
    }
    t
}

struct Ops<'a> {
    project_id: Uuid,
    snap: &'a Snapshot,
    ops: Vec<OpEnvelope>,
    lines: Vec<String>,
}

impl Ops<'_> {
    fn push(&mut self, payload: serde_json::Value) {
        self.ops.push(OpEnvelope { op_id: Uuid::new_v4().to_string(), payload });
    }

    /// Titles were checked against Fira when the files were read
    /// (`check_title`), so every one resolves.
    fn tag_ids(&self, titles: &[String]) -> Vec<Uuid> {
        titles
            .iter()
            .filter_map(|t| self.snap.tags.iter().find(|x| x.title == *t).map(|x| x.id))
            .collect()
    }

    fn track_id(&self, title: Option<&String>) -> Option<Uuid> {
        let t = title?;
        self.snap.tracks.iter().find(|x| x.title == *t).map(|x| x.id)
    }

    fn sprint_ops(&mut self, remote: Option<&Sprint>, target: &Sprint) -> bool {
        let before = self.ops.len();
        match remote {
            None => {
                let track_id = self.track_id(target.track.as_ref());
                self.push(json!({"kind": "sprint.create", "sprint": {
                    "id": target.id, "project_id": self.project_id, "track_id": track_id,
                    "title": target.title,
                    "starts_on": target.dates.map(|d| d.0), "ends_on": target.dates.map(|d| d.1),
                }}));
                if !target.tags.is_empty() || target.assignee.is_some() {
                    let tag_ids = self.tag_ids(&target.tags);
                    self.push(json!({"kind": "sprint.set_defaults", "sprint_id": target.id,
                        "default_assignee_id": target.assignee, "default_tag_ids": tag_ids}));
                }
            }
            Some(r) => {
                if r.title != target.title {
                    self.push(json!({"kind": "sprint.set_title", "sprint_id": target.id, "title": target.title}));
                }
                if r.dates != target.dates {
                    if let Some((a, b)) = target.dates {
                        self.push(json!({"kind": "sprint.set_dates", "sprint_id": target.id, "starts_on": a, "ends_on": b}));
                    }
                }
                if r.track != target.track {
                    let track_id = self.track_id(target.track.as_ref());
                    self.push(json!({"kind": "sprint.set_track", "sprint_id": target.id, "track_id": track_id}));
                }
                if r.tags != target.tags || r.assignee != target.assignee {
                    let tag_ids = self.tag_ids(&target.tags);
                    self.push(json!({"kind": "sprint.set_defaults", "sprint_id": target.id,
                        "default_assignee_id": target.assignee, "default_tag_ids": tag_ids}));
                }
            }
        }
        self.ops.len() > before
    }

    fn task_ops(&mut self, remote: Option<(&Task, &[RemoteSubtask])>, target: &Task) -> bool {
        let before = self.ops.len();
        match remote {
            None => {
                let tag_ids = self.tag_ids(&target.tags);
                self.push(json!({"kind": "task.create", "task": {
                    "id": target.id, "project_id": self.project_id, "sprint_id": target.sprint,
                    "assignee_id": target.assignee, "title": target.title,
                    "description_md": target.description,
                    "section": if target.status == Status::Done { "done" } else { "later" },
                    "status": target.status.fira(), "source": "local",
                    "estimate_min": target.estimate_min, "tag_ids": tag_ids,
                }}));
                for (i, s) in target.subtasks.iter().enumerate() {
                    self.push(json!({"kind": "subtask.create", "subtask": {
                        "id": Uuid::new_v4(), "task_id": target.id, "title": s.title,
                        "done": s.done, "sort_key": format!("M{i:03}"),
                    }}));
                }
            }
            Some((r, rsubs)) => {
                let id = target.id;
                if r.title != target.title {
                    self.push(json!({"kind": "task.set_title", "task_id": id, "title": target.title}));
                }
                if r.status != target.status {
                    self.push(json!({"kind": "task.set_status", "task_id": id, "status": target.status.fira()}));
                }
                if r.sprint != target.sprint {
                    self.push(json!({"kind": "task.set_sprint", "task_id": id, "sprint_id": target.sprint}));
                }
                if r.tags != target.tags {
                    let tag_ids = self.tag_ids(&target.tags);
                    self.push(json!({"kind": "task.set_tags", "task_id": id, "tag_ids": tag_ids}));
                }
                if r.assignee != target.assignee {
                    self.push(json!({"kind": "task.set_assignee", "task_id": id, "assignee_id": target.assignee}));
                }
                if r.estimate_min != target.estimate_min {
                    self.push(json!({"kind": "task.set_estimate", "task_id": id, "estimate_min": target.estimate_min}));
                }
                if r.description != target.description {
                    self.push(json!({"kind": "task.set_description", "task_id": id, "description_md": target.description}));
                }
                if r.subtasks != target.subtasks {
                    for op in subtask_ops(id, rsubs, &target.subtasks) {
                        self.push(op);
                    }
                }
            }
        }
        self.ops.len() > before
    }
}

/// Make the remote checklist equal `want`, as an ordered value list:
/// keep subtasks whose titles match (in order), turn the remaining pairs
/// into title edits, create or delete the rest, then fix done flags and
/// order.
pub fn subtask_ops(task_id: Uuid, have: &[RemoteSubtask], want: &[Subtask]) -> Vec<serde_json::Value> {
    let mut ops = vec![];
    let mut assigned: Vec<Option<usize>> = vec![None; want.len()];
    let mut used = vec![false; have.len()];
    for (i, w) in want.iter().enumerate() {
        if let Some(j) = (0..have.len()).find(|&j| !used[j] && have[j].title == w.title) {
            assigned[i] = Some(j);
            used[j] = true;
        }
    }
    let mut spare = (0..have.len()).filter(|&j| !used[j]).collect::<Vec<_>>().into_iter();
    for (i, w) in want.iter().enumerate() {
        if assigned[i].is_none() {
            if let Some(j) = spare.next() {
                assigned[i] = Some(j);
                used[j] = true;
                ops.push(json!({"kind": "subtask.set_title", "subtask_id": have[j].id, "title": w.title}));
            }
        }
    }
    for j in spare {
        ops.push(json!({"kind": "subtask.delete", "subtask_id": have[j].id}));
    }
    let mut order = vec![];
    for (i, w) in want.iter().enumerate() {
        match assigned[i] {
            Some(j) => {
                if have[j].done != w.done {
                    ops.push(json!({"kind": "subtask.tick", "subtask_id": have[j].id, "done": w.done}));
                }
                order.push(have[j].id);
            }
            None => {
                let id = Uuid::new_v4();
                ops.push(json!({"kind": "subtask.create", "subtask": {
                    "id": id, "task_id": task_id, "title": w.title, "done": w.done,
                    "sort_key": format!("M{i:03}"),
                }}));
                order.push(id);
            }
        }
    }
    let kept: Vec<Uuid> = have.iter().filter(|h| order.contains(&h.id)).map(|h| h.id).collect();
    let created = order.len() > kept.len();
    let kept_in_new_order: Vec<Uuid> = order.iter().copied().filter(|id| kept.contains(id)).collect();
    if created || kept_in_new_order != kept {
        ops.push(json!({"kind": "subtask.reorder", "task_id": task_id, "ordered": order}));
    }
    ops
}

/// Turn the comparison and the user's decisions into writes.
pub fn plan(repo: &Repo, cmp: &Comparison, dec: &Decisions, project_id: Uuid) -> Result<Plan> {
    let r = Resolver::new(&cmp.snap);
    let mut ops = Ops {
        project_id,
        snap: &cmp.snap,
        ops: vec![],
        lines: vec![],
    };
    let mut pre = vec![];
    let mut remote_lines = vec![];
    let mut local_lines = vec![];

    let choice = |id: Uuid, f: Field| dec.fields.get(&(id, f)).copied();

    // Target values per side.
    let mut sprint_local_target: HashMap<Uuid, Sprint> = HashMap::new();
    let mut task_local_target: HashMap<Uuid, Task> = HashMap::new();

    // Sprints first: tasks may join a sprint created in this run.
    for e in cmp.entities.iter().filter(|e| e.kind == Kind::Sprint) {
        match (&e.local_sprint, &e.remote_sprint) {
            (Some(l), Some(rm)) => {
                let target_remote = merge_sprint(rm, l, &|f| choice(e.id, f) == Some(Side::Local));
                let target_local = merge_sprint(l, rm, &|f| choice(e.id, f) == Some(Side::Remote));
                if cmp.mode != Mode::Diff && ops.sprint_ops(Some(rm), &target_remote) {
                    pre.push(Precondition { kind: "sprint", id: e.id, revision: e.revision });
                    remote_lines.push(format!("update sprint \"{}\"", target_remote.title));
                }
                sprint_local_target.insert(e.id, target_local);
            }
            (Some(l), None) if e.state == State::New && cmp.mode == Mode::Publish => {
                ops.sprint_ops(None, l);
                pre.push(Precondition { kind: "sprint", id: e.id, revision: None });
                remote_lines.push(format!("create sprint \"{}\"", l.title));
                sprint_local_target.insert(e.id, l.clone());
            }
            (Some(l), None) => {
                sprint_local_target.insert(e.id, l.clone());
            }
            (None, Some(rm)) if cmp.mode == Mode::Import => {
                sprint_local_target.insert(e.id, rm.clone());
            }
            _ => {}
        }
    }

    let mut deletes_local: Vec<TaskRef> = vec![];
    for e in cmp.entities.iter().filter(|e| e.kind == Kind::Task) {
        match (&e.local_task, &e.remote_task) {
            (Some(l), Some(rm)) => {
                let target_remote = merge_task(rm, l, &|f| choice(e.id, f) == Some(Side::Local));
                let target_local = merge_task(l, rm, &|f| choice(e.id, f) == Some(Side::Remote));
                if let Some(u) = target_remote.assignee.filter(|u| Some(*u) != rm.assignee && !r.is_active(*u)) {
                    bail!("cannot assign \"{}\" to {}: not an active member of the project", l.title, r.handle_of(u));
                }
                if ops.task_ops(Some((rm, &e.remote_subtasks)), &target_remote) {
                    pre.push(Precondition { kind: "task", id: e.id, revision: e.revision });
                    let changed: Vec<&str> = task_fields(rm, &target_remote).iter().map(|f| f.name()).collect();
                    remote_lines.push(format!("update task \"{}\": {}", target_remote.title, changed.join(", ")));
                }
                task_local_target.insert(e.id, target_local);
            }
            (Some(l), None) => match (e.state, dec.deleted.get(&e.id)) {
                (State::New, _) if cmp.mode == Mode::Publish => {
                    ops.task_ops(None, l);
                    pre.push(Precondition { kind: "task", id: e.id, revision: None });
                    remote_lines.push(format!("create task \"{}\"", l.title));
                    task_local_target.insert(e.id, l.clone());
                }
                (State::DeletedInFira, Some(DeletedChoice::Recreate)) => {
                    ops.task_ops(None, l);
                    pre.push(Precondition { kind: "task", id: e.id, revision: None });
                    remote_lines.push(format!("recreate task \"{}\" (same id)", l.title));
                    task_local_target.insert(e.id, l.clone());
                }
                (State::DeletedInFira, Some(DeletedChoice::DeleteLocal)) => {
                    deletes_local.push(e.task.unwrap());
                }
                _ => {
                    task_local_target.insert(e.id, l.clone());
                }
            },
            (None, Some(rm)) if cmp.mode == Mode::Import => {
                task_local_target.insert(e.id, rm.clone());
            }
            _ => {}
        }
    }
    remote_lines.extend(std::mem::take(&mut ops.lines));
    let all_ops = ops.ops;

    // ---- local ----
    let mut edits: HashMap<usize, Vec<Edit>> = HashMap::new();
    let mut appends: HashMap<usize, Vec<String>> = HashMap::new();
    let mut new_files: Vec<(PathBuf, String)> = vec![];
    let mut new_sprint_file: HashMap<Uuid, (PathBuf, Sprint, Vec<String>)> = HashMap::new();
    let mut taken: HashSet<PathBuf> = HashSet::new();

    // Defaults each doc's tasks inherit after this run.
    let doc_defaults_new = |doc: usize| -> Defaults {
        match repo.sprint_ids[doc] {
            Some(s) => defaults_of(sprint_local_target.get(&s.id).or(local_sprint(repo, doc, &r).ok().as_ref())),
            None => Defaults::default(),
        }
    };
    let doc_defaults_cur = |doc: usize| -> Defaults {
        if repo.docs[doc].kind == DocKind::Sprint {
            defaults_of(local_sprint(repo, doc, &r).ok().as_ref())
        } else {
            Defaults::default()
        }
    };

    // Sprint frontmatter.
    for e in cmp.entities.iter().filter(|e| e.kind == Kind::Sprint) {
        let Some(target) = sprint_local_target.get(&e.id) else { continue };
        match (e.doc, &e.local_sprint) {
            (Some(d), Some(cur)) => {
                let fm = repo.docs[d].front.as_ref();
                let assignee_ok = match fm.and_then(|f| f.assignee.as_deref()) {
                    Some(a) => r.resolve_user(a) == target.assignee,
                    None => target.assignee.is_none(),
                };
                let write_id = e.id_new && cmp.mode == Mode::Publish && e.state == State::New;
                let es = write::sprint_edits(&repo.docs[d], &write::SprintWrite { cur, target, id_is_new: write_id, assignee_ok }, &r);
                if !es.is_empty() {
                    if cur != target {
                        local_lines.push(format!("{}: update sprint \"{}\"", repo.docs[d].display, target.title));
                    } else if write_id {
                        local_lines.push(format!("{}: insert sprint_id", repo.docs[d].display));
                    }
                    edits.entry(d).or_default().extend(es);
                }
            }
            (None, None) if cmp.mode == Mode::Import => {
                let path = unique_path(&repo.root.dir.join(SPRINTS_DIR), &model::slug(&target.title), &mut taken);
                local_lines.push(format!("{}: new sprint file", crate::config::display_path(&path)));
                new_sprint_file.insert(e.id, (path, target.clone(), vec![]));
            }
            _ => {}
        }
    }

    // Tasks.
    let mut handled: HashSet<TaskRef> = HashSet::new();
    for e in cmp.entities.iter().filter(|e| e.kind == Kind::Task) {
        let Some(target) = task_local_target.get(&e.id) else { continue };
        let write_id = e.id_new;
        match (e.task, &e.local_task) {
            (Some(tr), Some(cur)) => {
                handled.insert(tr);
                let b = &repo.docs[tr.doc].tasks[tr.task];
                let src_sprint = repo.sprint_of_doc(tr.doc);
                let moving = target.sprint != src_sprint;
                let dest_defaults = match target.sprint {
                    Some(sid) => match repo.sprint_doc(sid) {
                        Some(d) => doc_defaults_new(d),
                        None => defaults_of(sprint_local_target.get(&sid)),
                    },
                    None => Defaults::default(),
                };
                let defaults = if moving { dest_defaults } else { doc_defaults_new(tr.doc) };
                let comment = write::comment_for(Some(b), e.id, write_id, target, &defaults, &r);
                let tes = write::task_edits(&repo.docs[tr.doc].text, b, cur, target, comment);
                if !moving {
                    if !tes.is_empty() {
                        let changed: Vec<&str> = task_fields(cur, target).iter().map(|f| f.name()).collect();
                        local_lines.push(if changed.is_empty() {
                            format!("{}:{}: {} \"{}\"", repo.docs[tr.doc].display, b.line, if write_id { "insert id for" } else { "update comment of" }, target.title)
                        } else {
                            format!("{}:{}: update \"{}\": {}", repo.docs[tr.doc].display, b.line, target.title, changed.join(", "))
                        });
                        edits.entry(tr.doc).or_default().extend(tes);
                    }
                    continue;
                }
                // Move: cut the (edited) block and paste it where its sprint is.
                let src_doc = &repo.docs[tr.doc];
                let level = |kind: DocKind| if kind == DocKind::Sprint { 2 } else { 1 };
                match target.sprint {
                    Some(sid) => {
                        if let Some(d) = repo.sprint_doc(sid) {
                            let block = write::extract_block(&src_doc.text, b, &tes, level(DocKind::Sprint))?;
                            appends.entry(d).or_default().push(block);
                            local_lines.push(format!("move \"{}\" from {} to {}", target.title, src_doc.display, repo.docs[d].display));
                        } else if let Some((path, _, blocks)) = new_sprint_file.get_mut(&sid) {
                            let block = write::extract_block(&src_doc.text, b, &tes, level(DocKind::Sprint))?;
                            blocks.push(block);
                            local_lines.push(format!("move \"{}\" from {} to {}", target.title, src_doc.display, crate::config::display_path(path)));
                        } else {
                            bail!("internal error: no local file for sprint {sid}");
                        }
                    }
                    None => {
                        let block = write::extract_block(&src_doc.text, b, &tes, level(DocKind::Single))?;
                        let path = unique_path(&repo.root.dir.join(SINGLE_DIR), &model::slug(&target.title), &mut taken);
                        local_lines.push(format!("move \"{}\" from {} to {}", target.title, src_doc.display, crate::config::display_path(&path)));
                        new_files.push((path, block));
                    }
                }
                edits.entry(tr.doc).or_default().push(Edit::replace(b.block.clone(), ""));
            }
            (None, None) if cmp.mode == Mode::Import => {
                // A new local task goes to `--into`, else its sprint's
                // file (existing or created in this run), else single/.
                // With `--into`, its membership becomes that file's sprint;
                // the next diff shows it if that differs from Fira.
                let dest_doc = cmp.into.or_else(|| target.sprint.and_then(|s| repo.sprint_doc(s)));
                if let Some(d) = dest_doc {
                    if repo.docs[d].kind == DocKind::Single {
                        bail!("--into must name a sprint file; a single task file holds one task");
                    }
                    let mut t = target.clone();
                    t.sprint = repo.sprint_of_doc(d);
                    appends.entry(d).or_default().push(write::render_task(2, e.id, &t, &doc_defaults_new(d), &r));
                    local_lines.push(format!("{}: add task \"{}\"", repo.docs[d].display, t.title));
                } else if let Some((_, s, blocks)) = target.sprint.and_then(|sid| new_sprint_file.get_mut(&sid)) {
                    blocks.push(write::render_task(2, e.id, target, &defaults_of(Some(s)), &r));
                } else {
                    if let Some(sid) = target.sprint {
                        local_lines.push(format!(
                            "note: \"{}\" is in Fira sprint {sid}, which has no local file; it goes to {SINGLE_DIR}/ (import the sprint to place it)",
                            target.title
                        ));
                    }
                    let mut t = target.clone();
                    t.sprint = None;
                    let path = unique_path(&repo.root.dir.join(SINGLE_DIR), &model::slug(&t.title), &mut taken);
                    local_lines.push(format!("{}: new task file \"{}\"", crate::config::display_path(&path), t.title));
                    new_files.push((path, write::render_task(1, e.id, &t, &Defaults::default(), &r)));
                }
            }
            _ => {}
        }
    }

    for tr in deletes_local {
        let b = &repo.docs[tr.doc].tasks[tr.task];
        local_lines.push(format!("{}:{}: delete \"{}\" (deleted in Fira)", repo.docs[tr.doc].display, b.line, b.title));
        edits.entry(tr.doc).or_default().push(Edit::replace(b.block.clone(), ""));
        handled.insert(tr);
    }

    // Tasks not in the comparison whose inherited values would change
    // because their sprint's tags/assignee changed: pin them.
    for d in 0..repo.docs.len() {
        if repo.docs[d].kind != DocKind::Sprint || doc_defaults_cur(d) == doc_defaults_new(d) {
            continue;
        }
        for tr in repo.tasks_of(d) {
            if handled.contains(&tr) || cmp.entities.iter().any(|e| e.task == Some(tr)) {
                continue;
            }
            if let Ok(cur) = local_task(repo, tr, &doc_defaults_cur(d), &r) {
                let b = &repo.docs[d].tasks[tr.task];
                if let Some(c) = write::comment_for(Some(b), cur.id, false, &cur, &doc_defaults_new(d), &r) {
                    edits.entry(d).or_default().extend(write::task_edits(&repo.docs[d].text, b, &cur, &cur, Some(c)));
                }
            }
        }
    }

    // Assemble file writes.
    let mut files = vec![];
    let mut docs: Vec<usize> = edits.keys().chain(appends.keys()).copied().collect();
    docs.sort();
    docs.dedup();
    for d in docs {
        let doc = &repo.docs[d];
        let mut es = edits.remove(&d).unwrap_or_default();
        let base = apply_edits(&doc.text, &es)?;
        if let Some(blocks) = appends.remove(&d) {
            let mut text = base.clone();
            for b in blocks {
                let e = write::append(&text, &b);
                text = apply_edits(&text, &[e])?;
            }
            es.clear();
            files.push(FileWrite::Edit { doc: d, new_text: text });
            continue;
        }
        if doc.kind == DocKind::Single && base.trim().is_empty() {
            files.push(FileWrite::Remove { doc: d });
        } else if base != doc.text {
            files.push(FileWrite::Edit { doc: d, new_text: base });
        }
    }
    for (_, (path, s, blocks)) in new_sprint_file {
        let handle = s.assignee.map(|u| r.handle_of(u));
        files.push(FileWrite::Create { path, text: write::render_sprint_file(&s, handle, &blocks) });
    }
    for (path, text) in new_files {
        files.push(FileWrite::Create { path, text });
    }

    if cmp.mode == Mode::Diff {
        return Ok(Plan { ops: vec![], pre: vec![], remote_lines: vec![], local_lines: vec![], files: vec![] });
    }
    Ok(Plan { ops: all_ops, pre, remote_lines, local_lines, files })
}

fn unique_path(dir: &std::path::Path, slug: &str, taken: &mut HashSet<PathBuf>) -> PathBuf {
    let mut n = 1;
    loop {
        let name = if n == 1 { format!("{slug}.md") } else { format!("{slug}-{n}.md") };
        let p = dir.join(name);
        if !p.exists() && !taken.contains(&p) {
            taken.insert(p.clone());
            return p;
        }
        n += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(users: &[(u128, &str, &str)]) -> Snapshot {
        Snapshot {
            project: crate::fira::Named { id: Uuid::nil(), title: "P".into() },
            users: users
                .iter()
                .map(|(id, email, name)| crate::fira::User { id: Uuid::from_u128(*id), email: (*email).into(), name: (*name).into(), active: true, member: true })
                .collect(),
            tags: vec![],
            tracks: vec![],
            sprints: vec![],
            tasks: vec![],
            missing: vec![],
        }
    }

    #[test]
    fn tags_and_tracks_must_exist() {
        let mut sn = snap(&[]);
        sn.tags = vec![crate::fira::Named { id: Uuid::from_u128(9), title: "bug".into() }];
        let r = Resolver::new(&sn);
        assert!(r.check_title("bug", &sn.tags, "tag").is_ok());
        assert!(r.check_title("Bug", &sn.tags, "tag").unwrap_err().contains("differs only in case"));
        let e = r.check_title("layout", &sn.tags, "tag").unwrap_err();
        assert!(e.contains("no tag \"layout\"") && e.contains("created by project leads") && e.contains("Existing: bug"), "{e}");
    }

    #[test]
    fn assignee_handles() {
        let mut sn = snap(&[(1, "maya@gmail.com", "Maya Chen"), (2, "maya.kowalski@inbox.com", "Maya Kowalski"), (3, "b@x.io", "Bob Reyes")]);
        let r = Resolver::new(&sn);
        assert_eq!(r.handle_of(Uuid::from_u128(1)), "maya.c");
        assert_eq!(r.user("Maya.K"), Ok(Uuid::from_u128(2)));
        assert_eq!(r.user("maya.kowalski@inbox.com"), Ok(Uuid::from_u128(2)));
        assert!(r.user("maya").unwrap_err().contains("did you mean maya.c (Maya Chen) or maya.k (Maya Kowalski)"), "{:?}", r.user("maya"));
        assert!(r.user("zed.z").unwrap_err().contains("members: bob.r (Bob Reyes), maya.c (Maya Chen), maya.k (Maya Kowalski)"));
        // Maya Cole joins: maya.c now fits nobody, and says so.
        sn.users.push(crate::fira::User { id: Uuid::from_u128(4), email: "mc@x.io".into(), name: "Maya Cole".into(), active: true, member: true });
        let r = Resolver::new(&sn);
        let e = r.user("maya.c").unwrap_err();
        assert!(e.contains("maya.ch (Maya Chen)") && e.contains("maya.co (Maya Cole)"), "{e}");
    }

    fn rs(id: u128, title: &str, done: bool) -> RemoteSubtask {
        RemoteSubtask { id: Uuid::from_u128(id), title: title.into(), done }
    }
    fn st(title: &str, done: bool) -> Subtask {
        Subtask { title: title.into(), done }
    }
    fn kinds(ops: &[serde_json::Value]) -> Vec<String> {
        ops.iter().map(|o| o["kind"].as_str().unwrap().to_string()).collect()
    }

    #[test]
    fn subtask_tick_only() {
        let ops = subtask_ops(Uuid::nil(), &[rs(1, "a", false), rs(2, "b", false)], &[st("a", true), st("b", false)]);
        assert_eq!(kinds(&ops), ["subtask.tick"]);
    }

    #[test]
    fn subtask_edit_create_delete_reorder() {
        // Rename b→B, drop c, add d, swap order.
        let have = [rs(1, "a", false), rs(2, "b", false), rs(3, "c", false)];
        let ops = subtask_ops(Uuid::nil(), &have, &[st("B", false), st("a", false)]);
        assert_eq!(kinds(&ops), ["subtask.set_title", "subtask.delete", "subtask.reorder"]);
        assert_eq!(ops[0]["subtask_id"], json!(Uuid::from_u128(2)));
        let ops = subtask_ops(Uuid::nil(), &have[..1], &[st("a", false), st("d", true)]);
        assert_eq!(kinds(&ops), ["subtask.create", "subtask.reorder"]);
    }

    #[test]
    fn subtask_no_ops_when_equal() {
        assert!(subtask_ops(Uuid::nil(), &[rs(1, "a", true)], &[st("a", true)]).is_empty());
    }
}
