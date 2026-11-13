//! Task attachments on the local side: where their files live, how links
//! to them are written, validation, and what `fmt` fixes.
//!
//! A task's attachments are its `Attachments` section: one link per file,
//! every file in `<tasks root>/assets/<task-id>/`. The description may
//! embed or link any of them. Fira stores those links as
//! `attachment:<filename>`; the canonical model uses that form too, so a
//! diff never shows local paths or ids.

use std::collections::{BTreeMap, HashMap};
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::doc::{self, Doc, Link, TaskBlock};
use crate::model::Attachment;
use crate::safety::Edit;

pub const ASSETS_DIR: &str = "assets";
/// Fira's upload limit.
pub const MAX_BYTES: u64 = 10 * 1024 * 1024;
pub const SCHEME: &str = "attachment:";

/// Filenames need no escaping in Markdown and survive Fira's filename
/// scrubbing unchanged.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 120
        && !name.starts_with('.')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

pub fn name_rule(name: &str) -> String {
    format!("attachment filename {name:?} may only use letters, digits, '.', '_' and '-' (and not start with '.'); rename the file")
}

pub fn content_type(name: &str) -> &'static str {
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "txt" | "log" => "text/plain",
        "md" | "markdown" => "text/markdown",
        "csv" => "text/csv",
        "json" => "application/json",
        "html" | "htm" => "text/html",
        "xml" => "application/xml",
        "yaml" | "yml" => "application/yaml",
        "zip" => "application/zip",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mov" => "video/quicktime",
        _ => "application/octet-stream",
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

pub fn human_size(n: u64) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{} KB", n.div_ceil(1024))
    } else {
        format!("{:.1} MB", n as f64 / 1024.0 / 1024.0)
    }
}

/// `<tasks root>/assets/<task-id>`.
pub fn task_dir(root: &Path, id: Uuid) -> PathBuf {
    root.join(ASSETS_DIR).join(id.to_string())
}

/// How a document refers to its task's folder: `../assets/<id>/` from
/// `sprints/x.md`, more `../` from nested folders.
pub fn link_prefix(root: &Path, doc_path: &Path, id: Uuid) -> String {
    let depth = doc_path
        .parent()
        .and_then(|d| d.strip_prefix(root).ok())
        .map_or(1, |rel| rel.components().count());
    format!("{}{ASSETS_DIR}/{id}/", "../".repeat(depth))
}

/// A destination that names a file in the working copy (no scheme, no
/// fragment, not absolute).
fn is_local(dest: &str) -> bool {
    !(dest.is_empty()
        || dest.starts_with('/')
        || dest.starts_with('#')
        || dest.contains("://")
        || dest.contains(['?', '#'])
        || dest.split('/').next().is_some_and(|first| first.contains(':')))
}

/// Lexical normalisation (no filesystem access): `a/b/../c` → `a/c`.
fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            c => out.push(c),
        }
    }
    out
}

pub fn resolve(doc_path: &Path, dest: &str) -> Option<PathBuf> {
    if !is_local(dest) {
        return None;
    }
    let dir = doc_path.parent().unwrap_or(Path::new("."));
    Some(normalize(&dir.join(dest)))
}

/// The filename, when `path` is directly in the task's folder.
fn own_name(root: &Path, id: Uuid, path: &Path) -> Option<String> {
    (path.parent() == Some(task_dir(root, id).as_path()))
        .then(|| path.file_name().and_then(|n| n.to_str()).map(str::to_string))
        .flatten()
}

/// Local description → canonical (`attachment:<name>` for the task's own
/// files).
pub fn to_canonical(desc: &str, root: &Path, doc_path: &Path, id: Uuid) -> String {
    doc::rewrite_link_dests(desc, |l| {
        let p = resolve(doc_path, &l.dest)?;
        own_name(root, id, &p).map(|n| format!("{SCHEME}{n}"))
    })
}

/// Canonical description → local links for `doc_path`.
pub fn to_local(desc: &str, root: &Path, doc_path: &Path, id: Uuid) -> String {
    let prefix = link_prefix(root, doc_path, id);
    doc::rewrite_link_dests(desc, |l| {
        let name = l.dest.strip_prefix(SCHEME)?;
        valid_name(name).then(|| format!("{prefix}{name}"))
    })
}

/// The filename an Attachments list item names (its last path segment).
pub fn item_name(l: &Link) -> &str {
    l.dest.rsplit('/').next().unwrap_or(&l.dest)
}

/// The task's attachment set, read from disk and validated. Errors name
/// the file and line and say how to fix it.
pub fn local_set(root: &Path, d: &Doc, b: &TaskBlock, id: Uuid) -> Result<Vec<Attachment>, Vec<String>> {
    let mut errs = vec![];
    let mut set: BTreeMap<String, Attachment> = BTreeMap::new();
    let folder = crate::config::display_path(&task_dir(root, id));
    let line_of = |l: &Link| doc::line_at(&d.text, l.full.start);
    let items = b.attachments.as_ref().map(|s| s.items.as_slice()).unwrap_or_default();
    for it in items {
        let at = format!("{}:{}", d.display, it.line);
        let Some(p) = resolve(&d.path, &it.link.dest) else {
            errs.push(format!("{at}: attachment {:?} is not a local file; attachments are files in {folder}/", it.link.dest));
            continue;
        };
        let Some(name) = own_name(root, id, &p) else {
            errs.push(format!("{at}: attachment {:?} is outside {folder}/; run `task-cli fmt` to move it there", it.link.dest));
            continue;
        };
        if !valid_name(&name) {
            errs.push(format!("{at}: {}", name_rule(&name)));
            continue;
        }
        if set.contains_key(&name) {
            errs.push(format!("{at}: {name} is listed twice in the Attachments section"));
            continue;
        }
        match std::fs::read(&p) {
            Ok(data) if data.len() as u64 > MAX_BYTES => errs.push(format!(
                "{at}: {name} is {}; Fira accepts attachments up to {}",
                human_size(data.len() as u64),
                human_size(MAX_BYTES)
            )),
            Ok(data) => {
                set.insert(name.clone(), Attachment { name, sha256: sha256_hex(&data), size: data.len() as u64 });
            }
            Err(e) => errs.push(format!("{at}: attachment {} does not exist ({e})", crate::config::display_path(&p))),
        }
    }
    for l in &b.desc_links {
        let Some(p) = resolve(&d.path, &l.dest) else { continue };
        let at = format!("{}:{}", d.display, line_of(l));
        match own_name(root, id, &p) {
            Some(name) => {
                if !valid_name(&name) {
                    errs.push(format!("{at}: {}", name_rule(&name)));
                } else if !p.is_file() {
                    errs.push(format!("{at}: {} does not exist", crate::config::display_path(&p)));
                } else if !items.iter().any(|it| item_name(&it.link) == name) {
                    errs.push(format!("{at}: {name} is embedded but not in the task's Attachments section; run `task-cli fmt` to add it"));
                }
            }
            None if l.image && p.is_file() => errs.push(format!(
                "{at}: image {:?} is outside {folder}/; run `task-cli fmt` to move it there and list it",
                l.dest
            )),
            None if l.image => errs.push(format!("{at}: image {} does not exist", crate::config::display_path(&p))),
            None => {}
        }
    }
    if errs.is_empty() {
        Ok(set.into_values().collect())
    } else {
        Err(errs)
    }
}

// ---- fmt ----

/// What `fmt` does for one document's attachments.
#[derive(Default, Debug)]
pub struct FmtPlan {
    pub edits: Vec<Edit>,
    /// Files to copy into a task's folder: (from, to).
    pub copies: Vec<(PathBuf, PathBuf)>,
    /// Sources to delete once every document that moved them is written.
    pub moved_from: Vec<PathBuf>,
    pub errors: Vec<String>,
}

fn same_content(a: &Path, b: &Path) -> bool {
    matches!((std::fs::read(a), std::fs::read(b)), (Ok(x), Ok(y)) if x == y)
}

/// Move linked files into the task's folder, spell every link to the
/// folder canonically, and list every embedded file. `planned` holds
/// copies already planned by other tasks in this run (destination →
/// source), so two tasks can't claim one name with different files.
pub fn fmt_task(
    root: &Path,
    repo_root: &Path,
    d: &Doc,
    b: &TaskBlock,
    id: Uuid,
    planned: &mut HashMap<PathBuf, PathBuf>,
) -> FmtPlan {
    let mut plan = FmtPlan::default();
    let prefix = link_prefix(root, &d.path, id);
    let folder = task_dir(root, id);
    let assets = root.join(ASSETS_DIR);
    let items = b.attachments.as_ref().map(|s| s.items.as_slice()).unwrap_or_default();

    let mut listed: Vec<String> = vec![];
    let mut embedded: Vec<String> = vec![];
    let links = items.iter().map(|it| (&it.link, true)).chain(b.desc_links.iter().map(|l| (l, false)));
    for (l, in_list) in links {
        let Some(p) = resolve(&d.path, &l.dest) else { continue };
        let at = format!("{}:{}", d.display, doc::line_at(&d.text, l.full.start));
        let name = match own_name(root, id, &p) {
            Some(n) => n,
            None if in_list || l.image => {
                let shown = crate::config::display_path(&p);
                if !p.is_file() {
                    plan.errors.push(format!("{at}: {shown} does not exist"));
                    continue;
                }
                if !p.starts_with(repo_root) {
                    plan.errors.push(format!("{at}: {shown} is outside the repository; copy it into {}/ yourself", crate::config::display_path(&folder)));
                    continue;
                }
                let Some(n) = p.file_name().and_then(|n| n.to_str()).map(str::to_string) else { continue };
                if !valid_name(&n) {
                    plan.errors.push(format!("{at}: {}", name_rule(&n)));
                    continue;
                }
                let dest = folder.join(&n);
                let clash = match planned.get(&dest) {
                    Some(src) => src != &p && !same_content(src, &p),
                    None => dest.exists() && !same_content(&dest, &p),
                };
                if clash {
                    plan.errors.push(format!(
                        "{at}: cannot move {shown} into {}: a different file named {n} is already there; rename one of them",
                        crate::config::display_path(&folder)
                    ));
                    continue;
                }
                if !dest.exists() && !planned.contains_key(&dest) {
                    planned.insert(dest.clone(), p.clone());
                    plan.copies.push((p.clone(), dest));
                }
                // Another task's attachment is copied, never taken away.
                if !p.starts_with(&assets) {
                    plan.moved_from.push(p.clone());
                }
                n
            }
            None => continue,
        };
        let canonical = format!("{prefix}{name}");
        if l.dest != canonical && valid_name(&name) {
            plan.edits.push(Edit::replace(l.dest_range.clone(), canonical));
        }
        if in_list {
            listed.push(name);
        } else if !embedded.contains(&name) {
            embedded.push(name);
        }
    }

    let missing: Vec<String> = embedded.into_iter().filter(|n| valid_name(n) && !listed.contains(n)).collect();
    if !missing.is_empty() {
        let bullet = b.attachments.as_ref().map_or("- ", |s| s.bullet.as_str()).to_string();
        let lines: String = missing.iter().map(|n| item_line(&bullet, n, &prefix)).collect();
        plan.edits.push(add_items(&d.text, b, &lines));
    }
    plan
}

pub fn item_line(bullet: &str, name: &str, prefix: &str) -> String {
    format!("{bullet}[{name}]({prefix}{name})\n")
}

pub fn section(level: usize, lines: &str) -> String {
    format!("{} Attachments\n\n{lines}", "#".repeat(level.min(6)))
}

/// Append list lines to the task's Attachments section, creating it
/// (after the description, before Subtasks) when there is none.
pub fn add_items(text: &str, b: &TaskBlock, lines: &str) -> Edit {
    match &b.attachments {
        Some(sec) => match &sec.list {
            Some(list) => {
                let content = text[list.clone()].trim_end().len().max(1);
                let end = list.start + content;
                let nl = if text[..end].ends_with('\n') { "" } else { "\n" };
                let mut ins = format!("{nl}{lines}");
                if text[end..].starts_with('\n') || end == text.len() {
                    ins.pop();
                    if end == text.len() {
                        ins.push('\n');
                    }
                }
                Edit::insert(end, ins)
            }
            None => Edit::insert(sec.heading.end, format!("\n{lines}")),
        },
        None => insert_section(text, b, &section(b.level + 1, lines)),
    }
}

/// Insert a new Attachments section (`sec`, ending in a newline) where it
/// belongs: before Subtasks, or at the end of the task.
pub fn insert_section(text: &str, b: &TaskBlock, sec: &str) -> Edit {
    if let Some(sub) = &b.subtasks {
        return Edit::insert(sub.heading.start, format!("{sec}\n"));
    }
    let region = &text[b.heading_end.min(b.block.end)..b.block.end];
    let p = if region.trim().is_empty() { b.heading_line_end } else { b.heading_end + region.trim_end().len() };
    let mut ins = format!("\n\n{sec}");
    ins.pop(); // keep the whitespace that followed p
    if p == text.len() {
        ins.push('\n');
    }
    Edit::insert(p, ins)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doc::{parse, DocKind};

    const ID: &str = "0b5a8c1e-2d3f-4a5b-8c7d-9e0f1a2b3c4d";

    fn id() -> Uuid {
        ID.parse().unwrap()
    }

    #[test]
    fn names_and_types() {
        assert!(valid_name("layout.png") && valid_name("spec-v2_final.pdf"));
        assert!(!valid_name("my shot.png") && !valid_name(".hidden") && !valid_name("ü.png"));
        assert_eq!(content_type("A.PNG"), "image/png");
        assert_eq!(content_type("x.unknown"), "application/octet-stream");
    }

    #[test]
    fn link_prefix_follows_depth() {
        let root = Path::new("/r/tasks");
        assert_eq!(link_prefix(root, Path::new("/r/tasks/sprints/a.md"), id()), format!("../assets/{ID}/"));
        assert_eq!(link_prefix(root, Path::new("/r/tasks/sprints/2026/a.md"), id()), format!("../../assets/{ID}/"));
    }

    #[test]
    fn descriptions_convert_both_ways() {
        let root = Path::new("/r/tasks");
        let doc = Path::new("/r/tasks/sprints/a.md");
        let local = format!("See ![Layout](../assets/{ID}/layout.png) and [x](https://e.com/a.png) and [o](../assets/other/z.png).");
        let canon = to_canonical(&local, root, doc, id());
        assert_eq!(canon, "See ![Layout](attachment:layout.png) and [x](https://e.com/a.png) and [o](../assets/other/z.png).");
        assert_eq!(to_local(&canon, root, doc, id()), local);
        // Code is content, not a link.
        let code = format!("`![a](../assets/{ID}/a.png)`");
        assert_eq!(to_canonical(&code, root, doc, id()), code);
    }

    fn setup(text: &str) -> (tempfile::TempDir, Doc) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("tasks");
        std::fs::create_dir_all(root.join("sprints")).unwrap();
        let path = root.join("sprints/a.md");
        std::fs::write(&path, text).unwrap();
        let d = parse(path, "a.md".into(), text.into(), DocKind::Sprint).unwrap();
        (dir, d)
    }

    #[test]
    fn fmt_moves_embeds_and_lists_them() {
        let text = format!("# S\n\n## ⚪ A\n<!-- task: id={ID} -->\n\nShell: ![Layout](../../shot.png)\n\n### Subtasks\n\n- [ ] one\n");
        let (dir, d) = setup(&text);
        std::fs::write(dir.path().join("shot.png"), b"png").unwrap();
        let root = dir.path().join("tasks");
        let plan = fmt_task(&root, dir.path(), &d, &d.tasks[0], id(), &mut HashMap::new());
        assert!(plan.errors.is_empty(), "{:?}", plan.errors);
        assert_eq!(plan.copies, vec![(dir.path().join("shot.png"), task_dir(&root, id()).join("shot.png"))]);
        assert_eq!(plan.moved_from, vec![dir.path().join("shot.png")]);
        let out = crate::safety::apply_edits(&d.text, &plan.edits).unwrap();
        assert_eq!(
            out,
            format!("# S\n\n## ⚪ A\n<!-- task: id={ID} -->\n\nShell: ![Layout](../assets/{ID}/shot.png)\n\n### Attachments\n\n- [shot.png](../assets/{ID}/shot.png)\n\n### Subtasks\n\n- [ ] one\n")
        );
    }

    #[test]
    fn fmt_adds_to_an_existing_list_and_refuses_clashes() {
        let text = format!("# S\n\n## ⚪ A\n<!-- task: id={ID} -->\n\n![a](../assets/{ID}/a.png)\n\n### Attachments\n\n- [spec.pdf](../assets/{ID}/spec.pdf)\n- [b.png](../../b.png)\n");
        let (dir, d) = setup(&text);
        let root = dir.path().join("tasks");
        std::fs::create_dir_all(task_dir(&root, id())).unwrap();
        std::fs::write(task_dir(&root, id()).join("b.png"), b"mine").unwrap();
        std::fs::write(dir.path().join("b.png"), b"other").unwrap();
        let plan = fmt_task(&root, dir.path(), &d, &d.tasks[0], id(), &mut HashMap::new());
        assert!(plan.errors[0].contains("a different file named b.png"), "{:?}", plan.errors);
        let out = crate::safety::apply_edits(&d.text, &plan.edits).unwrap();
        assert!(out.ends_with(&format!("- [b.png](../../b.png)\n- [a.png](../assets/{ID}/a.png)\n")), "{out}");
    }

    #[test]
    fn local_set_validates() {
        let text = format!("# S\n\n## ⚪ A\n<!-- task: id={ID} -->\n\n![a](../assets/{ID}/a.png)\n\n### Attachments\n\n- [spec.pdf](../assets/{ID}/spec.pdf)\n");
        let (dir, d) = setup(&text);
        let root = dir.path().join("tasks");
        std::fs::create_dir_all(task_dir(&root, id())).unwrap();
        std::fs::write(task_dir(&root, id()).join("a.png"), b"a").unwrap();
        let e = local_set(&root, &d, &d.tasks[0], id()).unwrap_err();
        assert!(e.iter().any(|e| e.contains("spec.pdf does not exist")), "{e:?}");
        assert!(e.iter().any(|e| e.contains("a.png is embedded but not in the task's Attachments section")), "{e:?}");
        std::fs::write(task_dir(&root, id()).join("spec.pdf"), b"pdf").unwrap();
        std::fs::write(task_dir(&root, id()).join("llm_ctx.md"), b"local").unwrap();
        let text = text.replace("- [spec.pdf]", &format!("- [a.png](../assets/{ID}/a.png)\n- [spec.pdf]"));
        let d = parse(d.path.clone(), "a.md".into(), text, DocKind::Sprint).unwrap();
        let set = local_set(&root, &d, &d.tasks[0], id()).unwrap();
        let names: Vec<&str> = set.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["a.png", "spec.pdf"], "unlisted files stay local");
        assert_eq!(set[0].sha256, sha256_hex(b"a"));
    }
}
