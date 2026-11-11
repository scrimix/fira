//! All documents under the tasks root, with identity resolved.
//!
//! Tasks and sprints that have no ID yet get one generated here, in memory.
//! It is written to the file only by `fmt` or as part of an accepted
//! publish; read-only commands just show such items as new.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use uuid::Uuid;

use crate::config::{display_path, Root};
use crate::doc::{self, Doc, DocKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TaskRef {
    pub doc: usize,
    pub task: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct Ident {
    pub id: Uuid,
    /// Generated in this run; not in the file yet.
    pub new: bool,
}

pub struct Repo {
    pub root: Root,
    pub docs: Vec<Doc>,
    /// Per doc: the sprint's identity (sprint files only).
    pub sprint_ids: Vec<Option<Ident>>,
    /// Per doc, per task.
    pub task_ids: Vec<Vec<Ident>>,
}

pub const SPRINTS_DIR: &str = "sprints";
pub const SINGLE_DIR: &str = "single";

fn md_files(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let p = e.path();
        let name = e.file_name();
        if name.to_string_lossy().starts_with('.') {
            continue;
        }
        if p.is_dir() {
            md_files(&p, out)?;
        } else if p.extension().is_some_and(|x| x == "md") {
            out.push(p);
        }
    }
    Ok(())
}

pub fn parse_file(path: &Path, kind: DocKind) -> Result<Doc, Vec<String>> {
    let display = display_path(path);
    let text = std::fs::read_to_string(path).map_err(|e| vec![format!("{display}: {e}")])?;
    doc::parse(path.to_path_buf(), display, text, kind)
}

impl Repo {
    pub fn load(root: Root) -> Result<Repo> {
        let mut paths = vec![];
        for (dir, kind) in [(SPRINTS_DIR, DocKind::Sprint), (SINGLE_DIR, DocKind::Single)] {
            let mut ps = vec![];
            md_files(&root.dir.join(dir), &mut ps)?;
            paths.extend(ps.into_iter().map(|p| (p, kind)));
        }
        let mut docs = vec![];
        let mut errors = vec![];
        for (p, kind) in paths {
            match parse_file(&p, kind) {
                Ok(d) => docs.push(d),
                Err(e) => errors.extend(e),
            }
        }
        if !errors.is_empty() {
            bail!("{}", errors.join("\n"));
        }
        Repo::from_docs(root, docs)
    }

    pub fn from_docs(root: Root, docs: Vec<Doc>) -> Result<Repo> {
        let mut seen: HashMap<Uuid, String> = HashMap::new();
        let mut errors = vec![];
        let mut sprint_ids = vec![];
        let mut task_ids = vec![];
        for d in &docs {
            let sid = match d.kind {
                DocKind::Single => None,
                DocKind::Sprint => Some(match d.front.as_ref().and_then(|f| f.sprint_id) {
                    Some(id) => {
                        let line = d.front.as_ref().and_then(|f| f.line_of("sprint_id")).map_or(1, |l| l.line);
                        let here = format!("{}:{line}", d.display);
                        if let Some(prev) = seen.insert(id, here.clone()) {
                            errors.push(format!("{here}: sprint_id {id} is also used at {prev}; a copied file? Delete the sprint_id line in the copy and run `task-cli fmt`"));
                        }
                        Ident { id, new: false }
                    }
                    None => Ident { id: Uuid::new_v4(), new: true },
                }),
            };
            sprint_ids.push(sid);
            let mut ids = vec![];
            for t in &d.tasks {
                ids.push(match t.id() {
                    Some(id) => {
                        let here = format!("{}:{}", d.display, t.comment.as_ref().map_or(t.line, |c| c.line));
                        if let Some(prev) = seen.insert(id, here.clone()) {
                            errors.push(format!("{here}: id {id} is also used at {prev}; a copy-pasted task block? Delete `id=…` from the copy and run `task-cli fmt`"));
                        }
                        Ident { id, new: false }
                    }
                    None => Ident { id: Uuid::new_v4(), new: true },
                });
            }
            task_ids.push(ids);
        }
        if !errors.is_empty() {
            bail!("{}", errors.join("\n"));
        }
        Ok(Repo { root, docs, sprint_ids, task_ids })
    }

    pub fn task_id(&self, r: TaskRef) -> Uuid {
        self.task_ids[r.doc][r.task].id
    }

    pub fn find_task(&self, id: Uuid) -> Option<TaskRef> {
        self.task_ids.iter().enumerate().find_map(|(d, ids)| {
            ids.iter().position(|i| i.id == id).map(|t| TaskRef { doc: d, task: t })
        })
    }

    pub fn sprint_doc(&self, id: Uuid) -> Option<usize> {
        self.sprint_ids.iter().position(|s| s.is_some_and(|s| s.id == id))
    }

    /// The sprint a task belongs to locally: the sprint of its file.
    pub fn sprint_of_doc(&self, doc: usize) -> Option<Uuid> {
        self.sprint_ids[doc].map(|s| s.id)
    }

    pub fn tasks_of(&self, doc: usize) -> impl Iterator<Item = TaskRef> + '_ {
        (0..self.docs[doc].tasks.len()).map(move |t| TaskRef { doc, task: t })
    }

    pub fn doc_index(&self, path: &Path) -> Option<usize> {
        let canon = path.canonicalize().ok()?;
        self.docs.iter().position(|d| d.path.canonicalize().ok().as_deref() == Some(canon.as_path()))
    }
}
