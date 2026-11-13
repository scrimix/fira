//! `task-cli … notion`: a sprint or single-task file mirrored into a PM's
//! Notion page, between a `Tasks` heading and a footer the CLI writes.
//!
//! Both sides are compared as Markdown. The file's body is rendered to
//! blocks and back (`ir`), the page's region is read to blocks and to
//! Markdown, and both texts are parsed by the ordinary document parser, so
//! tasks are matched by the id in their `<!-- task: … -->` line. The
//! footer holds the hash of what was last published, which says which
//! side changed since. The per-field choice is the one `publish fira` uses.

pub mod api;
pub mod ir;
mod json;
mod users;

use std::collections::HashSet;
use std::io::IsTerminal;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::attachments;
use crate::config::{self, display_path};
use crate::doc::{self, Doc, DocKind};
use crate::fira::{self, FetchRequest};
use crate::model::{Sprint, Task};
use crate::repo::{Repo, TaskRef};
use crate::safety::{self, apply_edits, Edit};
use crate::sync::{self, Comparison, Decisions, Entity, Field, FieldDiff, Kind, Mode, Resolver, Scope, Side, State};
use crate::ui;
use crate::write;
use api::{status_of, Api};
use ir::{Block, ReadCtx};
use json::Node;

const FOOTER: &str = "task-cli";
/// How the page is laid out. A page written in an older format is
/// rewritten once even when its content agrees (v1: full task ids, long
/// footer; v2: short ids; v3: no captions under files).
const FORMAT: u32 = 3;
/// Notion's per-file limit on free workspaces.
const MAX_UPLOAD: u64 = 5 * 1024 * 1024;

pub struct Opts {
    pub dry_run: bool,
    pub prefer: Option<Side>,
    pub no_pager: bool,
}

// ---- login / link ----

pub fn login(root: &config::Root) -> Result<u8> {
    let token = if std::io::stdin().is_terminal() {
        eprintln!(
            "Create an internal integration at https://www.notion.so/profile/integrations\n\
             (capabilities: read, update and insert content; user information including email addresses),\n\
             then share each page with it (page menu ••• → Connections)."
        );
        rpassword::prompt_password("Paste the integration secret (input hidden): ")?
    } else {
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        s
    };
    let token = token.trim().to_string();
    if token.is_empty() {
        bail!("no token given");
    }
    let api = Api::new(token.clone())?;
    let me = api.me().context("checking the token")?;
    let bot_id = me["id"].as_str().ok_or_else(|| anyhow!("Notion returned no user for this token"))?.to_string();
    let workspace = me["bot"]["workspace_name"].as_str().unwrap_or("Notion").to_string();
    let path = config::save_notion_credential(config::NotionCredential { workspace: workspace.clone(), bot_id, token })?;
    config::update_table(root, "notion", &[("workspace", workspace.clone())])?;
    println!("Logged in to Notion workspace \"{workspace}\" as \"{}\". Token stored in {}.", me["name"].as_str().unwrap_or("integration"), path.display());
    match api.users() {
        Ok(u) => println!("It can see {} people, so assignees can be matched by email.", u.iter().filter(|u| u["type"] == "person").count()),
        Err(e) => println!(
            "Note: this token can't list Notion users ({}), so only the token's owner is matched for @mentions. \
             An internal integration with \"user information including email addresses\" matches everyone.",
            status_of(&e).map_or("error", |s| s.1)
        ),
    }
    Ok(0)
}

pub fn is_linked(d: &Doc) -> bool {
    page_link(d).is_some()
}

/// The page a file is linked to.
fn page_link(d: &Doc) -> Option<String> {
    match d.kind {
        DocKind::Sprint => d.front.as_ref().and_then(|f| f.notion.clone()),
        DocKind::Single => d.tasks.first().and_then(|t| t.comment.as_ref()).and_then(|c| c.notion.clone()),
    }
}

pub fn link(repo: &Repo, d: usize, url: &str) -> Result<u8> {
    let doc = &repo.docs[d];
    let id = doc::parse_notion_id(url).ok_or_else(|| anyhow!("{url:?} is not a Notion page link or id"))?;
    if page_link(doc).as_deref() == Some(id.as_str()) {
        println!("{} is already linked to that page.", doc.display);
        return Ok(0);
    }
    let edit = match doc.kind {
        DocKind::Sprint => match &doc.front {
            Some(f) => match f.line_of("notion") {
                Some(l) => Edit::replace(l.range.clone(), format!("notion: {id}\n")),
                None => Edit::insert(f.close_start, format!("notion: {id}\n")),
            },
            None => Edit::insert(0, format!("---\nnotion: {id}\n---\n\n")),
        },
        DocKind::Single => {
            let Some(c) = doc.tasks.first().and_then(|t| t.comment.as_ref()) else {
                bail!("{} has no `task:` comment yet; run `task-cli fmt` first", doc.display);
            };
            let mut raw: Vec<(String, String)> = c.raw.iter().filter(|(k, _)| k != "notion").cloned().collect();
            raw.push(("notion".into(), id.clone()));
            Edit::replace(c.range.clone(), doc::format_comment_raw(&raw))
        }
    };
    let new = apply_edits(&doc.text, &[edit])?;
    let diff = similar::TextDiff::from_lines(&doc.text, &new);
    println!("{}:", doc.display);
    for ch in diff.iter_all_changes().filter(|c| c.tag() != similar::ChangeTag::Equal) {
        let sign = if ch.tag() == similar::ChangeTag::Delete { "-" } else { "+" };
        print!("  {sign} {ch}");
    }
    // Best effort: say whether the integration can see the page.
    if let Ok(token) = config::notion_token(&repo.root.config.notion) {
        match Api::new(token)?.page(&id) {
            Ok(p) => println!("Notion page: \"{}\"", page_title(&p)),
            Err(e) if matches!(status_of(&e), Some((404, _))) => eprintln!(
                "warning: the integration can't see this page yet; share it in Notion (page menu ••• → Connections)"
            ),
            Err(e) => eprintln!("warning: couldn't check the page: {e}"),
        }
    }
    if ui::interactive() && !ui::confirm("Write the link?")? {
        println!("Nothing was written.");
        return Ok(0);
    }
    let mut w = safety::Writer::new(&repo.root.dir);
    match w.write(&doc.path, &doc.text, &new)? {
        safety::Outcome::Written => println!("wrote {}", doc.display),
        safety::Outcome::Skipped(why) => bail!("{} not written: {why}", doc.display),
    }
    w.report_backups();
    Ok(0)
}

fn page_title(p: &Value) -> String {
    p["properties"]
        .as_object()
        .and_then(|props| props.values().find(|v| v["type"] == "title"))
        .map(|t| json::plain_text(&t["title"]))
        .unwrap_or_default()
}

// ---- rendering the file ----

struct Rendered {
    blocks: Vec<Block>,
    attach: Vec<(String, String)>,
    /// The files of the kept `attachment:` embeds, in document order.
    files: Vec<PathBuf>,
    /// (dest, alt) of every embed, for reading alt text back.
    alts: Vec<(String, String)>,
    notices: Vec<String>,
}

/// Files Notion hosts, in the order their embeds appear: give each the
/// task section it is in, and make names unique within a task. A repeated
/// name is a second file (pasted images are all `image.png`) unless the
/// task already has a file of that name (the same file embedded twice).
fn scope_files(blocks: &mut [Block], files: &[(String, String)], doc: &Doc, ids: &[Uuid], root: &std::path::Path) -> Vec<(String, String, String)> {
    struct Walk<'a> {
        files: &'a [(String, String)],
        k: usize,
        section: String,
        seen: Vec<(String, String)>,
        out: Vec<(String, String, String)>,
        exists: &'a dyn Fn(&str, &str) -> bool,
    }
    fn walk(bs: &mut [Block], w: &mut Walk, top: bool) {
        for b in bs.iter_mut() {
            match b {
                Block::Heading(_, spans) if top => {
                    let text: String = spans.iter().map(|s| s.text.as_str()).collect();
                    if let Some((len, _, _)) = crate::model::Status::from_marker_prefix(text.trim()) {
                        w.section = text.trim()[len..].trim().to_string();
                        w.seen.clear();
                    }
                }
                Block::Embed { dest, .. } if dest.starts_with(attachments::SCHEME) => {
                    let Some((name, url)) = w.files.get(w.k).cloned() else { continue };
                    w.k += 1;
                    let mut final_name = name.clone();
                    let clash = |n: &str, w: &Walk| w.seen.iter().any(|(s, u)| s == n && *u != url);
                    if clash(&name, w) && !(w.exists)(&w.section, &name) {
                        let (stem, ext) = name.rsplit_once('.').map_or((name.clone(), String::new()), |(a, e)| (a.to_string(), format!(".{e}")));
                        let mut n = 2;
                        loop {
                            final_name = format!("{stem}-{n}{ext}");
                            if !clash(&final_name, w) && !w.seen.iter().any(|(s, _)| *s == final_name) && !(w.exists)(&w.section, &final_name) {
                                break;
                            }
                            n += 1;
                        }
                        *dest = format!("{}{final_name}", attachments::SCHEME);
                    }
                    w.seen.push((final_name.clone(), url.clone()));
                    w.out.push((w.section.clone(), final_name, url));
                }
                Block::Item { children, .. } => walk(children, w, false),
                _ => {}
            }
        }
    }
    let exists = |section: &str, name: &str| {
        doc.tasks
            .iter()
            .zip(ids)
            .find(|(t, _)| t.title == section || doc.kind == DocKind::Single)
            .is_some_and(|(_, id)| attachments::task_dir(root, *id).join(name).exists())
    };
    let first = match doc.kind {
        DocKind::Single => doc.tasks.first().map_or(String::new(), |t| t.title.clone()),
        DocKind::Sprint => String::new(),
    };
    let mut w = Walk { files, k: 0, section: first, seen: vec![], out: vec![], exists: &exists };
    walk(blocks, &mut w, true);
    w.out
}

/// A file a PM put on the page, to be stored with its task.
struct Download {
    task: Uuid,
    name: String,
    url: String,
}

/// Embeds Notion can't take become their alt text, the same way every
/// time, so the projection stays stable.
fn keep_embeds(blocks: Vec<Block>, task: Option<Uuid>, root: &std::path::Path, pending: &[(Uuid, String)], out: &mut Rendered) -> Vec<Block> {
    blocks
        .into_iter()
        .map(|b| match b {
            Block::Embed { image, dest, alt } if dest.starts_with(attachments::SCHEME) => {
                let name = &dest[attachments::SCHEME.len()..];
                if !out.alts.iter().any(|(d, _)| *d == dest) {
                    out.alts.push((dest.clone(), alt.clone()));
                }
                let path = task.map(|t| attachments::task_dir(root, t).join(name));
                let coming = task.is_some_and(|t| pending.iter().any(|(pt, n)| *pt == t && n == name));
                let size = path.as_ref().and_then(|p| std::fs::metadata(p).ok()).map(|m| m.len()).or(coming.then_some(0));
                match (path, size) {
                    (Some(p), Some(s)) if s <= MAX_UPLOAD => {
                        out.files.push(p);
                        Block::Embed { image, dest, alt }
                    }
                    (_, s) => {
                        out.notices.push(match s {
                            Some(s) => format!("{name} is {} (over Notion's 5 MB); shown as text", attachments::human_size(s)),
                            None => format!("{name} is not in the task's attachments folder; shown as text"),
                        });
                        Block::Paragraph(vec![ir::Span::plain(if alt.is_empty() { name.to_string() } else { alt })])
                    }
                }
            }
            Block::Embed { image, dest, alt } => {
                if !out.alts.iter().any(|(d, _)| *d == dest) {
                    out.alts.push((dest.clone(), alt.clone()));
                }
                Block::Embed { image, dest, alt }
            }
            Block::Item { kind, text, children } => Block::Item { kind, text, children: keep_embeds(children, task, root, pending, out) },
            other => other,
        })
        .collect()
}

fn render(repo: &Repo, d: usize, pending: &[(Uuid, String)], ids: bool) -> Rendered {
    let doc = &repo.docs[d];
    let root = &repo.root.dir;
    let mut out = Rendered { blocks: vec![], attach: vec![], files: vec![], alts: vec![], notices: vec![] };
    let md = |out: &mut Rendered, text: &str, task: Option<Uuid>| {
        let mut attach = std::mem::take(&mut out.attach);
        let blocks = ir::from_markdown(text, &mut attach);
        out.attach = attach;
        let kept = keep_embeds(blocks, task, root, pending, out);
        out.blocks.extend(kept);
    };
    if doc.kind == DocKind::Sprint {
        if let Some((_, desc)) = &doc.description {
            md(&mut out, desc, None);
        }
    }
    for (i, b) in doc.tasks.iter().enumerate() {
        let id = repo.task_ids[d][i].id;
        if doc.kind == DocKind::Sprint {
            md(&mut out, &format!("{} {} {}", "#".repeat(b.level), b.status.marker(), b.title), None);
        }
        if let Some(c) = b.comment.as_ref().filter(|_| ids) {
            let raw: Vec<(String, String)> = c.raw.iter().filter(|(k, _)| k != "notion").cloned().collect();
            out.blocks.push(Block::TaskLine(doc::format_comment_raw(&raw)));
        }
        md(&mut out, &attachments::to_canonical(&b.description, root, &doc.path, id), Some(id));
        if let Some(s) = &b.subtasks {
            let items: String = s.items.iter().map(|x| format!("- [{}] {}\n", if x.done { "x" } else { " " }, x.title)).collect();
            md(&mut out, &format!("{} Subtasks\n\n{items}", "#".repeat(s.level)), None);
        }
    }
    out
}

// ---- projection: region Markdown → canonical model ----

struct Projection {
    repo: Repo,
    sprint: Option<Sprint>,
    tasks: Vec<Task>,
}

impl Projection {
    fn find(&self, id: Uuid) -> Option<(usize, &Task)> {
        self.tasks.iter().enumerate().find(|(_, t)| t.id == id)
    }
    fn is_new(&self, i: usize) -> bool {
        self.repo.task_ids[0][i].new
    }

    fn set_id(&mut self, i: usize, id: Uuid) {
        self.tasks[i].id = id;
        self.repo.task_ids[0][i] = crate::repo::Ident { id, new: false };
        if let Some(s) = &mut self.sprint {
            if let Some(x) = s.tasks.get_mut(i) {
                *x = id;
            }
        }
    }

    /// Sections without a task line take the id of the file's task with
    /// the same title (each file task at most once).
    fn match_titles(&mut self, local: &[(Uuid, String)]) {
        let mut taken: HashSet<Uuid> = (0..self.tasks.len()).filter(|&i| !self.is_new(i)).map(|i| self.tasks[i].id).collect();
        for i in 0..self.tasks.len() {
            if !self.is_new(i) {
                continue;
            }
            if let Some((id, _)) = local.iter().find(|(id, t)| !taken.contains(id) && *t == self.tasks[i].title) {
                taken.insert(*id);
                self.set_id(i, *id);
            }
        }
    }
}

/// The file's own heading part with `region` as its body, parsed.
fn project(repo: &Repo, d: usize, region: &str, label: &str, r: &Resolver) -> Result<Projection> {
    let doc = &repo.docs[d];
    let prefix = match doc.kind {
        DocKind::Sprint => {
            let start = doc.description.as_ref().map_or(doc.text.len(), |x| x.0.start);
            doc.text[..start].to_string()
        }
        DocKind::Single => doc.tasks.first().map_or(String::new(), |b| doc.text[..b.heading_end].to_string()),
    };
    let sep = if prefix.ends_with('\n') { "\n" } else { "\n\n" };
    let text = format!("{prefix}{sep}{region}");
    let pdoc = doc::parse(doc.path.clone(), label.to_string(), text, doc.kind)
        .map_err(|e| anyhow!("{}", e.join("\n")))?;
    let prepo = Repo::from_docs(repo.root.clone(), vec![pdoc])?;
    let mut errs = vec![];
    let sprint = match doc.kind {
        DocKind::Sprint => match sync::local_sprint(&prepo, 0, r) {
            Ok(s) => Some(s),
            Err(e) => {
                errs.extend(e);
                None
            }
        },
        DocKind::Single => None,
    };
    let defaults = sync::defaults_of(sprint.as_ref());
    let mut tasks = vec![];
    for t in prepo.tasks_of(0) {
        match sync::local_task(&prepo, t, &defaults, r) {
            Ok(x) => tasks.push(x),
            Err(e) => errs.extend(e),
        }
    }
    if !errs.is_empty() {
        bail!("{}", errs.join("\n"));
    }
    Ok(Projection { repo: prepo, sprint, tasks })
}

fn short_hash(md: &str) -> String {
    attachments::sha256_hex(md.as_bytes())[..16].to_string()
}

// ---- the page ----

struct Located {
    anchor: Option<String>,
    region: Vec<Value>,
    /// The footer's block id, recorded hash, and format version.
    footer: Option<(String, String, u32)>,
    warn: Option<String>,
}

impl Located {
    /// Ids and edit times of everything the CLI reads or replaces.
    fn stamp(&self) -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = self
            .region
            .iter()
            .map(|b| (b["id"].as_str().unwrap_or_default().to_string(), b["last_edited_time"].as_str().unwrap_or_default().to_string()))
            .collect();
        v.extend(self.anchor.clone().map(|a| (a, String::new())));
        v.extend(self.footer.clone().map(|f| (f.0, String::new())));
        v
    }
}

fn heading_level(b: &Value) -> Option<u8> {
    match b["type"].as_str()? {
        "heading_1" => Some(1),
        "heading_2" => Some(2),
        "heading_3" => Some(3),
        "heading_4" => Some(4),
        _ => None,
    }
}

fn text_of(b: &Value) -> String {
    let kind = b["type"].as_str().unwrap_or_default();
    json::plain_text(&b[kind]["rich_text"])
}

fn locate(top: &[Value], anchor: &str, me: &str) -> Result<Located> {
    let anchors: Vec<usize> = (0..top.len()).filter(|&i| heading_level(&top[i]).is_some() && text_of(&top[i]).trim() == anchor).collect();
    let a = match anchors.as_slice() {
        [] => return Ok(Located { anchor: None, region: vec![], footer: None, warn: None }),
        [a] => *a,
        many => bail!("the Notion page has {} \"{anchor}\" headings; keep one, so the CLI knows where its part of the page starts", many.len()),
    };
    let level = heading_level(&top[a]).unwrap_or(1);
    let is_footer = |b: &Value| b["type"] == "paragraph" && b["created_by"]["id"] == me && text_of(b).starts_with(FOOTER);
    let footer = (a + 1..top.len()).find(|&i| is_footer(&top[i]));
    let (end, warn) = match footer {
        Some(f) => (f, None),
        None => match (a + 1..top.len()).find(|&i| heading_level(&top[i]).is_some_and(|l| l <= level)) {
            Some(h) => (h, Some(format!("the footer line is missing; the CLI's part of the page ends at the heading \"{}\"", text_of(&top[h]).trim()))),
            None => (top.len(), Some("the footer line is missing; the CLI's part of the page runs to the end of the page".to_string())),
        },
    };
    Ok(Located {
        anchor: top[a]["id"].as_str().map(str::to_string),
        region: top[a + 1..end].to_vec(),
        footer: footer.map(|f| {
            let t = text_of(&top[f]);
            let mut parts = t.split(" · ");
            let version = parts.next().unwrap_or_default().trim().strip_prefix("task-cli v").and_then(|v| v.parse().ok()).unwrap_or(1);
            let hash = parts.next().unwrap_or_default().trim().to_string();
            (top[f]["id"].as_str().unwrap_or_default().to_string(), hash, version)
        }),
        warn,
    })
}

fn read_blocks(api: &Api, vs: &[Value], handle_of: &dyn Fn(&str, &str) -> String, notices: &mut Vec<String>, files: &mut Vec<(String, String)>, depth: usize) -> Result<Vec<Block>> {
    let mut out = vec![];
    for v in vs {
        let children = if v["has_children"].as_bool().unwrap_or(false) && depth < 5 {
            let id = v["id"].as_str().unwrap_or_default();
            read_blocks(api, &api.children(id)?, handle_of, notices, files, depth + 1)?
        } else {
            vec![]
        };
        if let Some(b) = json::from_json(v, children, handle_of, notices, files) {
            out.push(b);
        }
    }
    Ok(out)
}

/// A block's JSON with its children (one level) attached.
fn with_children(n: &Node) -> Value {
    let mut j = n.json.clone();
    if !n.children.is_empty() {
        let kind = j["type"].as_str().unwrap_or_default().to_string();
        j[kind]["children"] = Value::Array(n.children.iter().map(|c| c.json.clone()).collect());
    }
    j
}

/// Append blocks after `after`; deeper levels go in follow-up requests.
/// Returns the last top-level block written.
fn append_tree(api: &Api, parent: &str, after: Option<String>, nodes: &[Node], done: &mut usize, total: usize) -> Result<Option<String>> {
    let mut after = after;
    for chunk in nodes.chunks(100) {
        let res = api.append(parent, after.as_deref(), chunk.iter().map(with_children).collect())?;
        for (n, created) in chunk.iter().zip(&res) {
            if n.children.iter().any(|c| !c.children.is_empty()) {
                let kids = api.children(created["id"].as_str().unwrap_or_default())?;
                for (c, ck) in n.children.iter().zip(&kids) {
                    if !c.children.is_empty() {
                        append_tree(api, ck["id"].as_str().unwrap_or_default(), None, &c.children, done, total)?;
                    }
                }
            }
        }
        *done += chunk.len();
        if total > 100 {
            eprintln!("Notion: wrote {}/{total} blocks", (*done).min(total));
        }
        after = res.last().and_then(|b| b["id"].as_str()).map(str::to_string).or(after);
    }
    Ok(after)
}

fn footer_block(hash: &str) -> Value {
    json!({
        "object": "block",
        "type": "paragraph",
        "paragraph": {"rich_text": json::rich(&[ir::Span::plain(format!(
            "{FOOTER} v{FORMAT} · {hash} · edits above sync with the repository"
        ))], true)}
    })
}

// ---- publish ----

struct Ctx<'a> {
    r: &'a Resolver<'a>,
    m: &'a users::Matching,
}

impl Ctx<'_> {
    fn handle_of(&self, notion_id: &str, name: &str) -> String {
        match self.m.to_fira.get(notion_id) {
            Some(u) => self.r.handle_of(*u),
            None => format!("@{name}"),
        }
    }
    fn mention(&self, handle: &str) -> Option<String> {
        let u = self.r.user(handle).ok()?;
        self.m.to_notion.get(&u).cloned()
    }
}

fn notion_fields(a: &Task, b: &Task) -> Vec<Field> {
    sync::task_fields(a, b).into_iter().filter(|f| !matches!(f, Field::Sprint | Field::Attachments)).collect()
}

fn fd(field: Field) -> FieldDiff {
    FieldDiff { field, allow_local: true, allow_remote: true, note: None }
}

pub fn publish(full: &Repo, d: usize, opts: &Opts) -> Result<u8> {
    let repo = Repo::from_docs(full.root.clone(), vec![full.docs[d].clone()])?;
    let doc = &repo.docs[0];
    let page_id = page_link(doc).ok_or_else(|| {
        anyhow!("{} is not linked to a Notion page; link the Notion page first: task-cli link notion {} <page url>", doc.display, doc.display)
    })?;
    if repo.task_ids[0].iter().any(|i| i.new) || repo.sprint_ids[0].is_some_and(|s| s.new) {
        bail!("{} has tasks without ids; run `task-cli fmt` first", doc.display);
    }
    let anchor = repo.root.config.notion.anchor().to_string();

    // Fira: the people and tags the file's names refer to.
    let fira = fira::Client::new(&repo.root.config.fira.url, config::token_for(&repo.root.config.fira)?)?;
    let (sprint_ids, task_ids) = sync::fetch_ids(&repo, &Scope::Docs(vec![0]));
    let snap = fira.fetch(&FetchRequest { project_id: repo.root.project_id()?, sprint_ids, task_ids, all_sprints: false })?;
    let r = Resolver::new(&snap);

    // Notion: who the token is, who the people are.
    let api = Api::new(config::notion_token(&repo.root.config.notion)?)?;
    let me = api.me().context("checking the Notion token")?;
    let me_id = me["id"].as_str().unwrap_or_default().to_string();
    let mut notices: Vec<String> = vec![];
    // People only matter for the assignee in task lines.
    let people: Vec<users::Person> = if !repo.root.config.notion.task_ids() { vec![] } else { match api.users() {
        Ok(list) => list.iter().filter_map(users::Person::from_json).collect(),
        Err(e) if matches!(status_of(&e), Some((403, _)) | Some((400, _))) => {
            notices.push("this Notion token can't list users (a personal access token?); only its owner is matched for @mentions".into());
            users::Person::from_json(&me["bot"]["owner"]["user"]).into_iter().collect()
        }
        Err(e) => return Err(e.context("listing Notion users")),
    } };
    let ids_shown = repo.root.config.notion.task_ids();
    let m = users::matching(&snap.users, &people);
    let ctx = Ctx { r: &r, m: &m };

    let page = match api.page(&page_id) {
        Ok(p) => p,
        Err(e) if matches!(status_of(&e), Some((404, _))) => bail!(
            "the Notion page {page_id} linked from {} can't be found: it was deleted, or the integration lost access (share it again: page menu ••• → Connections). \
             The CLI can't tell which. Link another page with `task-cli link notion`",
            doc.display
        ),
        Err(e) => return Err(e),
    };
    if page["in_trash"].as_bool().unwrap_or(false) || page["archived"].as_bool().unwrap_or(false) {
        bail!("the Notion page \"{}\" linked from {} is in the trash; restore it or link another page", page_title(&page), doc.display);
    }
    let title = page_title(&page);

    // Both sides as Markdown.
    let top = api.children(&page_id)?;
    let loc = locate(&top, &anchor, &me_id)?;
    let handle_of = |id: &str, name: &str| ctx.handle_of(id, name);
    let mut notion_files = vec![];
    // Each top-level block with its id, so a rewrite can keep the ones
    // that didn't change.
    let mut old: Vec<(String, Option<Block>)> = vec![];
    for v in &loc.region {
        let mut b = read_blocks(&api, std::slice::from_ref(v), &handle_of, &mut notices, &mut notion_files, 0)?;
        old.push((v["id"].as_str().unwrap_or_default().to_string(), b.pop()));
    }
    let ids: Vec<Uuid> = repo.task_ids[0].iter().map(|i| i.id).collect();
    for (_, b) in old.iter_mut() {
        if let Some(Block::TaskLine(raw)) = b {
            *raw = json::expand_id(raw, &ids);
        }
    }
    let mut flat: Vec<Block> = old.iter().filter_map(|(_, b)| b.clone()).collect();
    let notion_files = scope_files(&mut flat, &notion_files, doc, &ids, &repo.root.dir);
    let mut flat = flat.into_iter();
    for (_, b) in old.iter_mut() {
        if b.is_some() {
            *b = flat.next();
        }
    }
    // Task lines left from a publish with `task_ids` on are dropped (and
    // the page rewritten without them).
    let had_lines = old.iter().any(|(_, b)| matches!(b, Some(Block::TaskLine(_))));
    let notion_blocks: Vec<Block> = old
        .iter()
        .filter_map(|(_, b)| b.clone())
        .filter(|b| ids_shown || !matches!(b, Block::TaskLine(_)))
        .collect();
    let rendered = render(&repo, 0, &[], ids_shown);
    notices.extend(rendered.notices.iter().cloned());
    let read_ctx = ReadCtx { attach: &rendered.attach, alts: &rendered.alts };
    let local_md = ir::to_markdown(&rendered.blocks, &read_ctx);
    let notion_md = ir::to_markdown(&notion_blocks, &read_ctx);
    let mut pl = project(&repo, 0, &local_md, &doc.display, &r)?;
    let mut pn = project(&repo, 0, &notion_md, &format!("Notion page \"{title}\""), &r)
        .map_err(|e| anyhow!("{e}\n(fix the task line in Notion, or publish with the file's version after restoring it)"))?;
    // Without task lines, tasks are known by their titles.
    for (i, id) in ids.iter().enumerate() {
        if i < pl.tasks.len() && pl.is_new(i) {
            pl.set_id(i, *id);
        }
    }
    if !ids_shown && doc.kind == DocKind::Sprint {
        let mut seen = HashSet::new();
        for t in &pl.tasks {
            if !seen.insert(t.title.clone()) {
                bail!(
                    "{} has two tasks titled \"{}\"; the Notion page tells tasks apart by title, so rename one (or set task_ids = true under [notion])",
                    doc.display,
                    t.title
                );
            }
        }
    }
    let local_titles: Vec<(Uuid, String)> = pl.tasks.iter().map(|t| (t.id, t.title.clone())).collect();
    pn.match_titles(&local_titles);
    let (h_local, h_notion) = (short_hash(&local_md), short_hash(&notion_md));
    let footer_hash = loc.footer.as_ref().map(|f| f.1.clone());

    // Assignees without a Notion match.
    let mut warned = HashSet::new();
    for t in pl.tasks.iter().filter(|_| ids_shown) {
        if let Some(u) = t.assignee {
            if let Some(why) = m.why.get(&u) {
                if warned.insert(u) {
                    let name = snap.users.iter().find(|x| x.id == u).map_or(String::new(), |x| x.name.clone());
                    notices.push(format!("assignee {} ({name}): {why}; shown as text in Notion", r.handle_of(u)));
                }
            }
        }
    }

    // The comparison, in `publish fira`'s terms.
    let mut entities = vec![];
    let mut extra = vec![];
    // File tasks not on the page (by index).
    let mut missing: Vec<usize> = vec![];
    if let (Some(ls), Some(ns)) = (&pl.sprint, &pn.sprint) {
        let mut fields = vec![];
        if ls.description != ns.description {
            fields.push(fd(Field::Description));
        }
        if crate::model::order_differs(ls, ns) {
            fields.push(fd(Field::Order));
        }
        entities.push(Entity {
            kind: Kind::Sprint, id: ls.id, id_new: false, doc: Some(0), task: None,
            local_sprint: Some(ls.clone()), remote_sprint: Some(ns.clone()), local_task: None, remote_task: None,
            revision: None, remote_subtasks: vec![], remote_attachments: vec![],
            state: if fields.is_empty() { State::InSync } else { State::Differs }, fields,
        });
    }
    let single = doc.kind == DocKind::Single;
    for (i, lt) in pl.tasks.iter().enumerate() {
        let nt = if single { pn.tasks.first().map(|t| Task { id: lt.id, ..t.clone() }) } else { pn.find(lt.id).map(|x| x.1.clone()) };
        match nt {
            Some(nt) => {
                let fields: Vec<FieldDiff> = notion_fields(lt, &nt).into_iter().map(fd).collect();
                entities.push(Entity {
                    kind: Kind::Task, id: lt.id, id_new: false, doc: Some(0), task: Some(TaskRef { doc: 0, task: i }),
                    local_sprint: None, remote_sprint: None, local_task: Some(lt.clone()), remote_task: Some(nt),
                    revision: None, remote_subtasks: vec![], remote_attachments: vec![],
                    state: if fields.is_empty() { State::InSync } else { State::Differs }, fields,
                });
            }
            None if !notion_md.trim().is_empty() => missing.push(i),
            None => {}
        }
    }
    let mut from_notion: Vec<usize> = vec![];
    if !single {
        for (i, nt) in pn.tasks.iter().enumerate() {
            if pn.is_new(i) {
                from_notion.push(i);
            } else if pl.find(nt.id).is_none() {
                extra.push(format!("\"{}\" on the Notion page is not a task of this file; it goes when the page is rewritten", nt.title));
            }
        }
    }
    let differs = local_md != notion_md;
    let side = match &footer_hash {
        _ if !differs => None,
        // Nothing published there yet: a first publish.
        _ if notion_md.trim().is_empty() => Some(Side::Local),
        Some(h) if *h == h_notion => Some(Side::Local),
        Some(h) if *h == h_local => Some(Side::Remote),
        _ => None,
    };
    let cmp = Comparison { mode: Mode::Sync, remote_label: "notion", snap: snap.clone(), entities, notices: vec![], into: None };
    let style = ui::Style { color: ui::color_ok() };

    // One report, like `publish fira`'s: paged when long, in colour on a
    // terminal.
    let mut report = format!("{} {}\n", style.bold(&format!("Notion page \"{title}\"")), style.dim(&format!("({})", page["url"].as_str().unwrap_or(&page_id))));
    if loc.anchor.is_none() {
        report.push_str(&format!("  no \"{anchor}\" heading yet: it will be added at the end of the page\n"));
    }
    notices.sort();
    notices.dedup();
    for n in loc.warn.iter().chain(&notices).chain(&extra) {
        report.push_str(&format!("  {}\n", style.warn(&format!("note: {n}"))));
    }

    let mut decisions = Decisions::default();
    if !differs {
        print!("{report}");
    } else {
        report.push_str(match side {
            Some(Side::Local) if notion_md.trim().is_empty() => "Nothing under the heading yet: a first publish.\n",
            Some(Side::Local) => "Only the file changed since the last publish.\n",
            Some(Side::Remote) => "Only the Notion page changed since the last publish.\n",
            None if footer_hash.is_some() => "Both the file and the Notion page changed since the last publish.\n",
            None => "No record of a previous publish on the page: choose per field.\n",
        });
        report.push_str(&ui::render(&repo, &cmp, &style, "local", false));
        // Tasks on only one side: not field differences, so `render`
        // doesn't show them.
        let preview = |t: &Task| -> String {
            let mut out = String::new();
            for l in t.description.lines().filter(|l| !l.trim().is_empty()).take(4) {
                out.push_str(&format!("      {}\n", style.dim(l)));
            }
            for st in t.subtasks.iter().take(6) {
                out.push_str(&format!("      {}\n", style.dim(&format!("[{}] {}", if st.done { "x" } else { " " }, st.title))));
            }
            out
        };
        let only_file = side == Some(Side::Local);
        for &i in &missing {
            let t = &pl.tasks[i];
            let what = if only_file { style.local("new in the file: will be added to the page") } else { style.local("in the file, not on the Notion page (deleted or renamed there?)") };
            report.push_str(&format!("  task {}  {}  {what}\n", style.bold(&format!("\"{}\"", t.title)), style.dim(&format!("({}:{})", doc.display, doc.tasks[i].line))));
        }
        for &i in &from_notion {
            let t = &pn.tasks[i];
            let what = if only_file { style.remote("deleted in the file: will be removed from the page") } else { style.remote("on the Notion page, not in the file (added or renamed there?)") };
            report.push_str(&format!("  task {}  {what}\n", style.bold(&format!("\"{} {}\"", t.status.marker(), t.title))));
            if !only_file {
                report.push_str(&preview(t));
            }
        }
        ui::page(&report, opts.no_pager);
        let auto = side.or(opts.prefer);
        if let Some(s) = auto {
            let mut notes = vec![];
            decisions = sync::prefer(&cmp, s, &mut notes);
        } else if opts.dry_run {
            println!("\nDry run: nothing was written. Without --dry-run you choose local or Notion for each differing field.");
            return Ok(0);
        } else if !ui::interactive() {
            bail!("no terminal to ask on. Use `--dry-run` to preview, or `--prefer local|notion` to answer every field in one direction (only when the user asked for it)");
        } else {
            match ui::choose(&repo, &cmp, &style, "local")? {
                Ok(dd) => decisions = dd,
                Err(ui::Quit) => {
                    println!("Quit: nothing was written.");
                    return Ok(0);
                }
            }
        }
    }
    // Tasks on only one side. When only the file changed since the last
    // publish, the file says what exists; otherwise the user picks.
    let mut delete_local: Vec<usize> = vec![];
    let mut page_lines: Vec<String> = vec![];
    let mut undecided = 0;
    if side == Some(Side::Local) {
        for &i in &missing {
            page_lines.push(format!("add \"{}\"", pl.tasks[i].title));
        }
        for &i in &from_notion {
            page_lines.push(format!("remove \"{}\" (deleted in the file)", pn.tasks[i].title));
        }
        from_notion.clear();
    } else if !missing.is_empty() || !from_notion.is_empty() {
        let ask = opts.prefer.is_none() && !opts.dry_run;
        if ask && !ui::interactive() {
            bail!("tasks are on only one side; no terminal to ask on. Use `--dry-run` to preview, or `--prefer local|notion`");
        }
        let pick = |q: String, keys: &[&str]| -> Result<Option<String>> {
            loop {
                let a = ui::ask(&q)?;
                if a == "q" {
                    return Ok(None);
                }
                if keys.contains(&a.as_str()) {
                    return Ok(Some(a));
                }
                eprintln!("There is no default here; pick {} or q.", keys.join(", "));
            }
        };
        let mut keep = vec![];
        for &i in &missing {
            let t = &pl.tasks[i].title;
            let delete = if ask {
                match pick(format!("\n\"{t}\" is in the file but not on the Notion page.\n[p]ut it back on the page  [d]elete it from the file  [q]uit > "), &["p", "d"])? {
                    Some(a) => a == "d",
                    None => {
                        println!("Quit: nothing was written.");
                        return Ok(0);
                    }
                }
            } else {
                undecided += usize::from(opts.dry_run);
                false
            };
            if delete {
                delete_local.push(i);
            } else {
                page_lines.push(format!("put back \"{t}\""));
            }
        }
        for &i in &from_notion {
            let t = &pn.tasks[i].title;
            let add = if ask {
                match pick(format!("\n\"{t}\" is on the Notion page but not in the file.\n[a]dd it to the file  [r]emove it from the page  [q]uit > "), &["a", "r"])? {
                    Some(a) => a == "a",
                    None => {
                        println!("Quit: nothing was written.");
                        return Ok(0);
                    }
                }
            } else {
                undecided += usize::from(opts.dry_run);
                opts.prefer != Some(Side::Local)
            };
            if add {
                keep.push(i);
            } else {
                page_lines.push(format!("remove \"{t}\""));
            }
        }
        from_notion = keep;
    }
    let skipped = cmp.entities.iter().flat_map(|e| e.fields.iter().map(move |f| (e.id, f.field))).filter(|k| !decisions.fields.contains_key(k)).count();

    // The file.
    let (new_text, local_lines, downloads) = file_changes(&repo, &cmp, &decisions, &pn, &from_notion, &delete_local, &notion_files, &r)?;
    let pending: Vec<(Uuid, String)> = downloads.iter().map(|d| (d.task, d.name.clone())).collect();
    let new_repo = if new_text == doc.text {
        None
    } else {
        let pdoc = doc::parse(doc.path.clone(), doc.display.clone(), new_text.clone(), doc.kind)
            .map_err(|e| anyhow!("internal error re-reading the merged file: {}", e.join("; ")))?;
        Some(Repo::from_docs(repo.root.clone(), vec![pdoc])?)
    };
    let target = new_repo.as_ref().unwrap_or(&repo);
    let target_render = render(target, 0, &pending, ids_shown);
    let target_md = ir::to_markdown(&target_render.blocks, &ReadCtx { attach: &target_render.attach, alts: &target_render.alts });
    let target_hash = short_hash(&target_md);

    // Notion.
    let outdated = loc.footer.as_ref().is_some_and(|f| f.2 != FORMAT) || (had_lines && !ids_shown);
    let replace = skipped == 0 && (target_md != notion_md || outdated);
    let footer_only = skipped == 0 && !replace && (footer_hash.as_deref() != Some(target_hash.as_str()) || loc.anchor.is_none());
    if skipped > 0 {
        println!("{skipped} field(s) skipped: the Notion page is left as it is until they are decided.");
    }
    if new_text == doc.text && !replace && !footer_only {
        println!("Nothing to do: the file and the Notion page agree.");
        return Ok(0);
    }
    println!();
    if replace {
        let (ops, offsets) = page_diff(&target_render, &old);
        let (kept, added, removed, files) = diff_counts(&ops, &offsets);
        println!(
            "Notion: under \"{anchor}\": {added} block(s) added, {removed} removed, {kept} unchanged{}",
            if files == 0 { String::new() } else { format!(", {files} file(s) to upload") }
        );
    } else if footer_only {
        println!("Notion: {}", if loc.anchor.is_none() { format!("add the \"{anchor}\" heading and the footer") } else { "update the footer".to_string() });
    } else {
        println!("Notion: no changes");
    }
    for l in page_lines.iter().filter(|_| replace) {
        println!("  {l}");
    }
    println!("Local: {}", if local_lines.is_empty() { "no changes".to_string() } else { "1 file".to_string() });
    for l in &local_lines {
        println!("  {l}");
    }
    if opts.dry_run {
        if undecided > 0 {
            println!("\nWithout --dry-run you choose for the {undecided} task(s) on only one side (shown here as put back / added).");
        }
        println!("\nDry run: nothing was written.");
        return Ok(0);
    }
    if opts.prefer.is_none() && ui::interactive() && !ui::confirm("\nWrite these changes?")? {
        println!("Nothing was written.");
        return Ok(0);
    }

    // Nothing may be based on a page or file that changed meanwhile.
    if replace || footer_only {
        let again = locate(&api.children(&page_id)?, &anchor, &me_id)?;
        if again.stamp() != loc.stamp() {
            bail!("the Notion page changed while the prompt was open; nothing was written. Run the command again to see the new diff");
        }
    }
    if new_text != doc.text {
        let mut w = safety::Writer::new(&repo.root.dir);
        // Files before the document that links them.
        for dl in &downloads {
            let dest = attachments::task_dir(&repo.root.dir, dl.task).join(&dl.name);
            let data = api.download(&dl.url).with_context(|| format!("downloading {} from Notion; nothing was written", dl.name))?;
            std::fs::create_dir_all(dest.parent().unwrap())?;
            match w.put_file(&dest, None, &data)? {
                safety::Outcome::Written => println!("wrote {}", display_path(&dest)),
                safety::Outcome::Skipped(why) => bail!("{} not written ({why}); nothing else was written", display_path(&dest)),
            }
        }
        match w.write(&doc.path, &doc.text, &new_text)? {
            safety::Outcome::Written => println!("wrote {}", doc.display),
            safety::Outcome::Skipped(why) => bail!("{} not written ({why}); nothing was written to Notion either", doc.display),
        }
        w.report_backups();
    }
    if replace || footer_only {
        write_page(&api, &page_id, &loc, &anchor, replace.then_some(&target_render), &old, &target_hash, &ctx)?;
        println!("Notion: done ({} requests).", api.requests.get());
    }
    Ok(0)
}


/// The merged file: chosen Notion values written into the task blocks,
/// the sprint description, tasks added in Notion, and Notion's order.
#[allow(clippy::too_many_arguments)]
fn file_changes(
    repo: &Repo,
    cmp: &Comparison,
    dec: &Decisions,
    pn: &Projection,
    from_notion: &[usize],
    delete_local: &[usize],
    notion_files: &[(String, String, String)],
    r: &Resolver,
) -> Result<(String, Vec<String>, Vec<Download>)> {
    let doc = &repo.docs[0];
    let root = &repo.root.dir;
    let mut edits = vec![];
    let mut lines = vec![];
    let take = |id: Uuid, f: Field| dec.fields.get(&(id, f)) == Some(&Side::Remote);
    let actual_sprint = match doc.kind {
        DocKind::Sprint => Some(sync::local_sprint(repo, 0, r).map_err(|e| anyhow!("{}", e.join("\n")))?),
        DocKind::Single => None,
    };
    let defaults = sync::defaults_of(actual_sprint.as_ref());
    for e in &cmp.entities {
        match e.kind {
            Kind::Sprint => {
                let (Some(cur), Some(ns)) = (&actual_sprint, &e.remote_sprint) else { continue };
                if take(e.id, Field::Description) {
                    let mut t = cur.clone();
                    t.description = ns.description.clone();
                    edits.extend(write::sprint_edits(doc, &write::SprintWrite { cur, target: &t, id_is_new: false, assignee_ok: true }, r));
                    lines.push(format!("{}: sprint description from Notion", doc.display));
                }
            }
            Kind::Task => {
                let (Some(tr), Some(nt)) = (e.task, &e.remote_task) else { continue };
                let chosen: Vec<Field> = e.fields.iter().map(|f| f.field).filter(|f| take(e.id, *f)).collect();
                if chosen.is_empty() {
                    continue;
                }
                let b = &doc.tasks[tr.task];
                let cur = sync::local_task(repo, tr, &defaults, r).map_err(|e| anyhow!("{}", e.join("\n")))?;
                let target = sync::merge_task(&cur, nt, &|f| chosen.contains(&f));
                let localize = |t: &Task| Task { description: attachments::to_local(&t.description, root, &doc.path, t.id), ..t.clone() };
                let (cur_l, target_l) = (localize(&cur), localize(&target));
                let comment = write::comment_for(Some(b), e.id, false, &target_l, &defaults, r);
                let prefix = attachments::link_prefix(root, &doc.path, e.id);
                edits.extend(write::task_edits(&doc.text, b, &cur_l, &target_l, comment, &prefix));
                lines.push(format!(
                    "{}:{}: \"{}\" from Notion: {}",
                    doc.display,
                    b.line,
                    target.title,
                    chosen.iter().map(|f| f.name()).collect::<Vec<_>>().join(", ")
                ));
            }
        }
    }
    for &i in delete_local {
        let b = &doc.tasks[i];
        edits.push(Edit::replace(b.block.clone(), ""));
        lines.push(format!("{}:{}: remove \"{}\"", doc.display, b.line, b.title));
    }
    let mut text = apply_edits(&doc.text, &edits)?;

    // Tasks added in Notion, with an id.
    let pdoc = &pn.repo.docs[0];
    for &i in from_notion {
        let b = &pdoc.tasks[i];
        let id = pn.repo.task_ids[0][i].id;
        let block = &pdoc.text[b.block.clone()];
        let rel = |x: usize| x - b.block.start;
        let block = attachments::to_local(block, root, &doc.path, id);
        let block = block.as_str();
        let with_id = match &b.comment {
            None => format!("{}<!-- task: id={id} -->\n{}", &block[..rel(b.heading_end)], &block[rel(b.heading_end)..]),
            Some(c) => {
                let mut raw = c.raw.clone();
                raw.insert(0, ("id".into(), id.to_string()));
                format!("{}{}{}", &block[..rel(c.range.start)], doc::format_comment_raw(&raw), &block[rel(c.range.end)..])
            }
        };
        text = apply_edits(&text, &[write::append(&text, with_id.trim_end())])?;
        lines.push(format!("{}: add \"{}\" from Notion", doc.display, b.title));
    }

    // Notion's order.
    let sprint_id = cmp.entities.iter().find(|e| e.kind == Kind::Sprint).map(|e| e.id);
    let order_from_notion = sprint_id.is_some_and(|s| take(s, Field::Order))
        || (!from_notion.is_empty() && !sprint_id.is_some_and(|s| dec.fields.get(&(s, Field::Order)) == Some(&Side::Local)));
    if doc.kind == DocKind::Sprint && order_from_notion {
        let parsed = doc::parse(doc.path.clone(), doc.display.clone(), text.clone(), DocKind::Sprint)
            .map_err(|e| anyhow!("internal error re-reading {}: {}", doc.display, e.join("; ")))?;
        let want: Vec<Uuid> = pn.tasks.iter().map(|t| t.id).collect();
        let reordered = write::reorder_blocks(&parsed, &want);
        if reordered != text {
            text = reordered;
            lines.push(format!("{}: task order from Notion", doc.display));
        }
    }
    // Files the PM put on the page: stored with their task and listed in
    // its Attachments section, like any embedded file.
    let mut downloads = vec![];
    if !notion_files.is_empty() && text != doc.text {
        let parsed = doc::parse(doc.path.clone(), doc.display.clone(), text.clone(), doc.kind)
            .map_err(|e| anyhow!("internal error re-reading {}: {}", doc.display, e.join("; ")))?;
        let mut edits = vec![];
        for b in &parsed.tasks {
            let Some(id) = b.id() else { continue };
            let desc = attachments::to_canonical(&b.description, root, &doc.path, id);
            let listed: Vec<&str> = b.attachments.iter().flat_map(|s| s.items.iter().map(|i| attachments::item_name(&i.link))).collect();
            let prefix = attachments::link_prefix(root, &doc.path, id);
            let mut items = String::new();
            for l in doc::inline_links(&desc) {
                let Some(name) = l.dest.strip_prefix(attachments::SCHEME) else { continue };
                if attachments::task_dir(root, id).join(name).exists() || downloads.iter().any(|d: &Download| d.task == id && d.name == name) {
                    continue;
                }
                let single = doc.kind == DocKind::Single;
                let Some((_, _, url)) = notion_files.iter().find(|(s, n, _)| n == name && (single || *s == b.title)) else { continue };
                downloads.push(Download { task: id, name: name.to_string(), url: url.clone() });
                lines.push(format!("{}: store {name} from Notion with \"{}\"", display_path(&attachments::task_dir(root, id)), b.title));
                if !listed.contains(&name) {
                    let bullet = b.attachments.as_ref().map_or("- ".to_string(), |s| s.bullet.clone());
                    items.push_str(&attachments::item_line(&bullet, name, &prefix));
                }
            }
            if !items.is_empty() {
                edits.push(attachments::add_items(&parsed.text, b, &items));
            }
        }
        text = apply_edits(&parsed.text, &edits)?;
    }
    Ok((text, lines, downloads))
}

/// How many `attachment:` embeds (with a file to upload) a block holds.
fn embeds_in(b: &Block) -> usize {
    match b {
        Block::Embed { dest, .. } if dest.starts_with(attachments::SCHEME) => 1,
        Block::Item { children, .. } => children.iter().map(embeds_in).sum(),
        _ => 0,
    }
}

/// The block-level difference between the page's region and what the
/// file renders to, by how each block reads back.
fn page_diff(rd: &Rendered, old: &[(String, Option<Block>)]) -> (Vec<similar::DiffOp>, Vec<usize>) {
    let md_ctx = ReadCtx { attach: &rd.attach, alts: &rd.alts };
    let sig = |b: &Block| ir::to_markdown(std::slice::from_ref(b), &md_ctx);
    // Old blocks the CLI doesn't write never match anything.
    let old_sigs: Vec<String> = old.iter().map(|(id, b)| b.as_ref().map_or_else(|| format!("\u{0}{id}"), &sig)).collect();
    let new_sigs: Vec<String> = rd.blocks.iter().map(&sig).collect();
    let mut offsets = vec![0];
    for b in &rd.blocks {
        offsets.push(offsets.last().unwrap() + embeds_in(b));
    }
    (similar::capture_diff_slices(similar::Algorithm::Myers, &old_sigs, &new_sigs), offsets)
}

/// (kept, added, removed, files to upload).
fn diff_counts(ops: &[similar::DiffOp], offsets: &[usize]) -> (usize, usize, usize, usize) {
    let (mut k, mut a, mut r, mut f) = (0, 0, 0, 0);
    for op in ops {
        match *op {
            similar::DiffOp::Equal { len, .. } => k += len,
            similar::DiffOp::Delete { old_len, .. } => r += old_len,
            similar::DiffOp::Insert { new_index, new_len, .. } => {
                a += new_len;
                f += offsets[new_index + new_len] - offsets[new_index];
            }
            similar::DiffOp::Replace { old_len, new_index, new_len, .. } => {
                r += old_len;
                a += new_len;
                f += offsets[new_index + new_len] - offsets[new_index];
            }
        }
    }
    (k, a, r, f)
}

/// Rewrite the region by difference: blocks that read back the same stay
/// (with their comments), the rest are removed, and new ones go in where
/// they belong. Only inserted files are uploaded.
#[allow(clippy::too_many_arguments)]
fn write_page(api: &Api, page_id: &str, loc: &Located, anchor: &str, rendered: Option<&Rendered>, old: &[(String, Option<Block>)], hash: &str, ctx: &Ctx) -> Result<()> {
    let anchor_id = match &loc.anchor {
        Some(a) => a.clone(),
        None => {
            let h = json!({"object": "block", "type": "heading_1", "heading_1": {"rich_text": json::rich(&[ir::Span::plain(anchor)], false)}});
            let res = api.append(page_id, None, vec![h])?;
            res.first().and_then(|b| b["id"].as_str()).ok_or_else(|| anyhow!("Notion returned no block for the new heading"))?.to_string()
        }
    };
    let mut last = old.last().map_or_else(|| anchor_id.clone(), |o| o.0.clone());
    if let Some(f) = &loc.footer {
        api.delete(&f.0)?;
    }
    if let Some(rd) = rendered {
        let (ops, offsets) = page_diff(rd, old);
        let mention = |h: &str| ctx.mention(h);
        let mut after = anchor_id.clone();
        let mut removed: Vec<&str> = vec![];
        let (mut kept, mut added) = (0, 0);
        let mut insert = |range: std::ops::Range<usize>, after: &mut String| -> Result<()> {
            let mut uploads = vec![];
            for p in &rd.files[offsets[range.start]..offsets[range.end]] {
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("file");
                let data = std::fs::read(p).with_context(|| format!("reading {}", display_path(p)))?;
                eprintln!("Notion: uploading {name}");
                uploads.push(Some(api.upload(name, attachments::content_type(name), data)?));
            }
            let mut it = uploads.into_iter();
            let nodes = json::to_nodes(&rd.blocks[range.clone()], &mut json::WriteCtx { mention: &mention, uploads: &mut it });
            let mut done = 0;
            if let Some(id) = append_tree(api, page_id, Some(after.clone()), &nodes, &mut done, nodes.len())? {
                *after = id;
            }
            added += range.len();
            Ok(())
        };
        for op in ops {
            match op {
                similar::DiffOp::Equal { old_index, len, .. } => {
                    after = old[old_index + len - 1].0.clone();
                    kept += len;
                }
                similar::DiffOp::Delete { old_index, old_len, .. } => {
                    removed.extend(old[old_index..old_index + old_len].iter().map(|o| o.0.as_str()));
                }
                similar::DiffOp::Insert { new_index, new_len, .. } => insert(new_index..new_index + new_len, &mut after)?,
                similar::DiffOp::Replace { old_index, old_len, new_index, new_len } => {
                    removed.extend(old[old_index..old_index + old_len].iter().map(|o| o.0.as_str()));
                    insert(new_index..new_index + new_len, &mut after)?;
                }
            }
        }
        for (n, id) in removed.iter().enumerate() {
            api.delete(id)?;
            if removed.len() > 20 && (n + 1) % 20 == 0 {
                eprintln!("Notion: removed {}/{} blocks", n + 1, removed.len());
            }
        }
        eprintln!("Notion: kept {kept} blocks, added {added}, removed {}", removed.len());
        last = after;
    }
    api.append(page_id, Some(&last), vec![footer_block(hash)])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ir::Span;

    fn embed(name: &str) -> Block {
        Block::Embed { image: true, dest: format!("{}{name}", attachments::SCHEME), alt: String::new() }
    }

    #[test]
    fn file_names_are_unique_per_task() {
        let doc = doc::parse("s.md".into(), "s.md".into(), "# S\n\n## ⚪ A\n\n## ⚪ B\n".into(), DocKind::Sprint).unwrap();
        let ids = [Uuid::from_u128(1), Uuid::from_u128(2)];
        let root = std::env::temp_dir().join("task-cli-scope-test-none");
        let mut blocks = vec![
            Block::Heading(2, vec![Span::plain("⚪ A")]),
            embed("flow.png"),
            embed("image.png"),
            embed("image.png"),
            Block::Heading(2, vec![Span::plain("⚪ B")]),
            embed("flow.png"),
        ];
        let files: Vec<(String, String)> = ["flow.png", "image.png", "image.png", "flow.png"]
            .iter()
            .enumerate()
            .map(|(i, n)| (n.to_string(), format!("https://f/{i}")))
            .collect();
        let out = scope_files(&mut blocks, &files, &doc, &ids, &root);
        let names: Vec<(&str, &str)> = out.iter().map(|(s, n, _)| (s.as_str(), n.as_str())).collect();
        // The same name in two tasks stays; a second pasted image.png in
        // one task becomes image-2.png.
        assert_eq!(names, [("A", "flow.png"), ("A", "image.png"), ("A", "image-2.png"), ("B", "flow.png")]);
        assert_eq!(blocks[3], embed("image-2.png"));
    }
}
