//! task-cli: keep sprint and task Markdown in a repository in sync with
//! Fira, with a field-level diff the user accepts before anything is
//! written on either side.

mod attachments;
mod config;
mod doc;
mod fira;
mod handles;
mod model;
mod repo;
mod safety;
mod sync;
mod ui;
mod write;

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use crate::config::display_path;
use crate::fira::{ApplyFailure, Client, FetchRequest};
use crate::repo::Repo;
use crate::sync::{Mode, Scope, Side};

const AFTER_HELP: &str = "\
Exit codes: 0 success / in sync, 1 differences (diff, fmt --check), 2 error.

Start here:  task-cli help workflow     the write → fmt → diff → publish loop
             task-cli help format       the file format, with examples
             task-cli help agents       everything an LLM agent needs";

#[derive(Parser)]
#[command(name = "task-cli", version, about = "Sync sprint and task Markdown documents with Fira", after_help = AFTER_HELP, disable_help_subcommand = true)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum Target {
    Fira,
}

#[derive(Clone, Copy, ValueEnum)]
enum Prefer {
    Local,
    Remote,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create tasks/config.toml and the sprints/ and single/ directories
    #[command(after_help = "Example:\n  task-cli init --url https://usefira.app\n\nThen run `task-cli login fira`.")]
    Init {
        /// Fira base URL
        #[arg(long, default_value = "https://usefira.app")]
        url: String,
        /// Directory to create (default: ./tasks)
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Store a Fira automation token for this repository's Fira (outside the repo)
    #[command(after_help = "Create a token in Fira: avatar → Account settings → Automation tokens.\n\
Paste it at the prompt, or pipe it in: `echo $TOKEN | task-cli login fira`.\n\
The token is stored in ~/.config/task-cli/credentials.toml (or $TASK_CLI_CONFIG_DIR),\n\
never in the repository. The project is chosen here if tasks/config.toml has none.\n\n\
Examples:\n  task-cli login fira\n  task-cli login fira --project Atlas")]
    Login {
        target: Target,
        /// Project id or title, when the token's workspace has several
        #[arg(long)]
        project: Option<String>,
    },
    /// Insert missing IDs and normalise structure lines; never changes prose
    #[command(after_help = "Moves each `task:` comment directly under its heading, rewrites status markers\n\
to ⚪ / 🚧 / ✅, inserts missing ids and sprint_id, and orders comment keys.\n\
Nothing is sent anywhere.\n\n\
Exit codes: 0 done (or nothing to change), 1 with --check when something would change, 2 error.\n\n\
Examples:\n  task-cli fmt\n  task-cli fmt tasks/sprints/001-onboarding.md\n  task-cli fmt --check    # pre-commit hook")]
    Fmt {
        files: Vec<PathBuf>,
        /// Change nothing; exit 1 if anything would change
        #[arg(long)]
        check: bool,
    },
    /// Show the diff for a file, choose per field, then write both sides
    #[command(after_help = "Covers the file's sprint and its tasks. Tasks in Fira but in no local file are\n\
listed and never touched. Nothing is deleted remotely, ever.\n\
Without a terminal the command fails unless --prefer or --dry-run is given.\n\n\
Examples:\n  task-cli publish fira tasks/sprints/001-onboarding.md\n  task-cli publish fira tasks/single/login-bug.md --dry-run\n  task-cli publish fira tasks/sprints/001-onboarding.md --prefer local   # unattended")]
    Publish {
        target: Target,
        file: PathBuf,
        #[command(flatten)]
        opts: SyncOpts,
    },
    /// Merge files that are already in Fira: diff, choose per field, write both sides
    #[command(after_help = "Like publish, for many files at once (all of tasks/ by default), and it creates\n\
nothing on either side: tasks and sprints not in Fira yet are listed and left for\n\
`publish`, Fira work not in any file is listed and left for `import`.\n\
Without a terminal the command fails unless --prefer or --dry-run is given.\n\n\
Examples:\n  task-cli sync fira\n  task-cli sync fira tasks/sprints/001-onboarding.md --dry-run")]
    Sync {
        target: Target,
        files: Vec<PathBuf>,
        #[command(flatten)]
        opts: SyncOpts,
    },
    /// Bring a Fira sprint or task into the repository, through the same diff
    #[command(after_help = "A sprint lands in tasks/sprints/<slug>.md, or updates the file with that sprint_id.\n\
A task lands in tasks/single/ (or its sprint's file, or --into). Local text is never\n\
deleted or moved because something is missing in Fira.\n\n\
Where to get the reference: a task's \"Copy link\" in Fira; a sprint's title, or\n\
\"Copy import command\" in its menu on the Plan board; or `task-cli sprints`.\n\n\
Examples:\n  task-cli import fira https://usefira.app/#/w/<ws>/t/<task-id>\n  task-cli import fira \"CLI publishing\"\n  task-cli import fira <sprint-id>\n  task-cli import fira <task-id> --into tasks/sprints/002-cli.md")]
    Import {
        target: Target,
        /// Sprint title, sprint/task id, or a Fira task link
        reference: String,
        /// Sprint file to add a new task to
        #[arg(long)]
        into: Option<PathBuf>,
        #[command(flatten)]
        opts: SyncOpts,
    },
    /// List the project's sprints in Fira, with ids and local files
    #[command(after_help = "Example:\n  task-cli sprints\n  task-cli import fira \"CLI publishing\"")]
    Sprints,
    /// Read-only: compare the working copy with Fira
    #[command(after_help = "Exit codes: 0 in sync, 1 differences, 2 error. Never prompts, never writes.\n\n\
Examples:\n  task-cli diff\n  task-cli diff tasks/sprints/001-onboarding.md --all\n  task-cli diff --json")]
    Diff {
        files: Vec<PathBuf>,
        /// Also show fields and tasks that agree
        #[arg(long)]
        all: bool,
        /// Machine-readable output
        #[arg(long)]
        json: bool,
        #[arg(long)]
        no_pager: bool,
    },
    /// Help topics: format, workflow, agents
    Help { topic: Option<String> },
}

#[derive(clap::Args)]
struct SyncOpts {
    /// Show the diff and what would be written; write nothing
    #[arg(long)]
    dry_run: bool,
    /// Answer every differing field in one direction (for unattended runs)
    #[arg(long, value_enum)]
    prefer: Option<Prefer>,
    #[arg(long)]
    no_pager: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<u8> {
    match cli.cmd {
        Cmd::Init { url, dir } => init(&url, dir),
        Cmd::Login { project, .. } => login(project),
        Cmd::Fmt { files, check } => fmt(&files, check),
        Cmd::Publish { file, opts, .. } => publish(&file, &opts),
        Cmd::Import { reference, into, opts, .. } => import(&reference, into.as_deref(), &opts),
        Cmd::Sync { files, opts, .. } => sync_files(&files, &opts),
        Cmd::Diff { files, all, json, no_pager } => diff(&files, all, json, no_pager),
        Cmd::Sprints => sprints(),
        Cmd::Help { topic } => help(topic.as_deref()),
    }
}

fn cwd() -> Result<PathBuf> {
    Ok(std::env::current_dir()?)
}

fn root() -> Result<config::Root> {
    config::find_root(&cwd()?)
}

// ---- init / login ----

fn init(url: &str, dir: Option<PathBuf>) -> Result<u8> {
    let dir = dir.unwrap_or_else(|| PathBuf::from("tasks"));
    let path = dir.join(config::CONFIG_FILE);
    if path.exists() {
        bail!("{} already exists", display_path(&path));
    }
    for sub in [repo::SPRINTS_DIR, repo::SINGLE_DIR] {
        std::fs::create_dir_all(dir.join(sub))?;
    }
    std::fs::write(&path, config::initial_config(url.trim_end_matches('/')))?;
    println!("Created {}. Next: task-cli login fira", display_path(&path));
    Ok(0)
}

fn login(project: Option<String>) -> Result<u8> {
    let root = root()?;
    let url = root.config.fira.url.clone();
    let token = if std::io::stdin().is_terminal() {
        eprintln!("Create a token in Fira ({url}): avatar → Account settings → Automation tokens.");
        rpassword::prompt_password("Paste the token (input hidden): ")?
    } else {
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        s
    };
    let token = token.trim().to_string();
    if !token.starts_with("fira_") {
        bail!("that doesn't look like a Fira automation token (they start with fira_)");
    }
    let client = Client::new(&url, token.clone())?;
    let me = client.whoami()?;
    if let Some(ws) = root.config.fira.workspace_id {
        if ws != me.workspace.id {
            bail!(
                "this token is for workspace \"{}\" ({}), but tasks/config.toml names workspace {ws}; create the token in the right workspace",
                me.workspace.title,
                me.workspace.id
            );
        }
    }
    let project_id = match (root.config.fira.project_id, project) {
        (Some(p), None) => {
            if !me.projects.iter().any(|x| x.id == p) {
                bail!("you have no access to project {p} (from tasks/config.toml) with this token");
            }
            p
        }
        (_, Some(want)) => {
            let found: Vec<_> = me
                .projects
                .iter()
                .filter(|p| p.id.to_string() == want || p.title.eq_ignore_ascii_case(&want))
                .collect();
            match found.as_slice() {
                [p] => p.id,
                [] => bail!("no project {want:?} in workspace \"{}\"; projects: {}", me.workspace.title, titles(&me.projects)),
                _ => bail!("several projects match {want:?}; use the project id"),
            }
        }
        (None, None) => match me.projects.as_slice() {
            [p] => p.id,
            [] => bail!("you have no projects in workspace \"{}\"", me.workspace.title),
            many => bail!(
                "workspace \"{}\" has several projects; rerun with --project <title>: {}",
                me.workspace.title,
                titles(many)
            ),
        },
    };
    let path = config::save_credential(config::FiraCredential { url: url.clone(), workspace_id: me.workspace.id, token })?;
    config::update_config(&root, &[("workspace_id", me.workspace.id.to_string()), ("project_id", project_id.to_string())])?;
    let pname = me.projects.iter().find(|p| p.id == project_id).map_or(String::new(), |p| p.title.clone());
    println!(
        "Logged in as {} to workspace \"{}\", project \"{pname}\" ({}).\nToken stored in {}.",
        me.user.email,
        me.workspace.title,
        if me.can_write { "read and write" } else { "read-only" },
        path.display()
    );
    Ok(0)
}

fn titles(p: &[fira::Named]) -> String {
    p.iter().map(|p| p.title.as_str()).collect::<Vec<_>>().join(", ")
}

// ---- fmt ----

fn docs_for(repo: &Repo, files: &[PathBuf]) -> Result<Vec<usize>> {
    if files.is_empty() {
        return Ok((0..repo.docs.len()).collect());
    }
    files
        .iter()
        .map(|f| {
            repo.doc_index(f).ok_or_else(|| {
                anyhow!(
                    "{} is not a task document under {}/{} or {}/{}",
                    f.display(),
                    display_path(&repo.root.dir),
                    repo::SPRINTS_DIR,
                    display_path(&repo.root.dir),
                    repo::SINGLE_DIR
                )
            })
        })
        .collect()
}

/// The repository a tasks root belongs to: linked files from anywhere in
/// it may be moved into a task's folder.
fn repo_root(tasks_root: &Path) -> PathBuf {
    std::process::Command::new("git")
        .arg("-C")
        .arg(tasks_root)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| PathBuf::from(String::from_utf8_lossy(&o.stdout).trim()))
        .unwrap_or_else(|| tasks_root.parent().unwrap_or(tasks_root).to_path_buf())
}

fn fmt(files: &[PathBuf], check: bool) -> Result<u8> {
    let repo = Repo::load(root()?)?;
    let docs = docs_for(&repo, files)?;
    let root_dir = repo.root.dir.clone();
    let repo_dir = repo_root(&root_dir);
    let mut planned = std::collections::HashMap::new();
    let mut errors = vec![];
    let mut copies = vec![];
    // Source of a move → the docs whose links now point at the copy.
    let mut moved: std::collections::HashMap<PathBuf, Vec<usize>> = std::collections::HashMap::new();
    let mut new_texts = vec![];
    for d in docs {
        let doc = &repo.docs[d];
        let sid = repo.sprint_ids[d].map(|s| (s.id, s.new));
        let ids: Vec<(uuid::Uuid, bool)> = repo.task_ids[d].iter().map(|i| (i.id, i.new)).collect();
        let mut edits = write::fmt_edits(doc, sid, &ids);
        for (t, b) in doc.tasks.iter().enumerate() {
            let p = attachments::fmt_task(&root_dir, &repo_dir, doc, b, repo.task_ids[d][t].id, &mut planned);
            errors.extend(p.errors);
            edits.extend(p.edits);
            copies.extend(p.copies);
            for src in p.moved_from {
                moved.entry(src).or_default().push(d);
            }
        }
        new_texts.push((d, safety::apply_edits(&doc.text, &edits)?));
    }
    if !errors.is_empty() {
        bail!("{}\nNothing was changed.", errors.join("\n"));
    }

    let mut changed = 0;
    for (from, to) in &copies {
        changed += 1;
        if check {
            println!("would move {} to {}", display_path(from), display_path(to));
            continue;
        }
        std::fs::create_dir_all(to.parent().unwrap())?;
        std::fs::copy(from, to).with_context(|| format!("copying {} to {}", display_path(from), display_path(to)))?;
    }
    let mut writer = safety::Writer::new(&repo.root.dir);
    let mut written = std::collections::HashSet::new();
    for (d, new) in new_texts {
        let doc = &repo.docs[d];
        if new == doc.text {
            written.insert(d);
            continue;
        }
        changed += 1;
        if check {
            println!("would reformat {}", doc.display);
            continue;
        }
        match writer.write(&doc.path, &doc.text, &new)? {
            safety::Outcome::Written => {
                written.insert(d);
                println!("formatted {}", doc.display);
            }
            safety::Outcome::Skipped(why) => eprintln!("skipped {}: {why}", doc.display),
        }
    }
    if !check {
        // A moved file's source goes once every link to it was rewritten.
        for (src, ds) in moved {
            if ds.iter().all(|d| written.contains(d)) && src.exists() {
                std::fs::remove_file(&src).with_context(|| format!("removing {}", display_path(&src)))?;
                println!("moved {} into the task's attachments", display_path(&src));
            }
        }
    }
    writer.report_backups();
    Ok(if check && changed > 0 { 1 } else { 0 })
}

// ---- sync commands ----

fn client(root: &config::Root) -> Result<Client> {
    Client::new(&root.config.fira.url, config::token_for(&root.config.fira)?)
}

fn fetch(repo: &Repo, client: &Client, scope: &Scope) -> Result<fira::Snapshot> {
    let (sprint_ids, task_ids) = sync::fetch_ids(repo, scope);
    client.fetch(&FetchRequest { project_id: repo.root.project_id()?, sprint_ids, task_ids, all_sprints: true })
}

fn diff(files: &[PathBuf], all: bool, json: bool, no_pager: bool) -> Result<u8> {
    let repo = Repo::load(root()?)?;
    let docs = docs_for(&repo, files)?;
    let client = client(&repo.root)?;
    let scope = Scope::Docs(docs);
    let snap = fetch(&repo, &client, &scope)?;
    let cmp = sync::build(&repo, snap, Mode::Diff, &scope, None)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&ui::render_json(&repo, &cmp))?);
    } else {
        let text = ui::render(&repo, &cmp, &ui::Style { color: ui::color_ok() && !no_pager }, "current", all);
        ui::page(&text, no_pager);
        if cmp.in_sync() {
            println!("In sync with Fira.");
        }
    }
    Ok(if cmp.in_sync() { 0 } else { 1 })
}

fn publish(file: &Path, opts: &SyncOpts) -> Result<u8> {
    let repo = Repo::load(root()?)?;
    let doc = docs_for(&repo, &[file.to_path_buf()])?[0];
    sync_run(repo, Mode::Publish, Scope::Docs(vec![doc]), None, opts)
}

fn sync_files(files: &[PathBuf], opts: &SyncOpts) -> Result<u8> {
    let repo = Repo::load(root()?)?;
    let docs = docs_for(&repo, files)?;
    sync_run(repo, Mode::Sync, Scope::Docs(docs), None, opts)
}

fn import(reference: &str, into: Option<&Path>, opts: &SyncOpts) -> Result<u8> {
    let repo = Repo::load(root()?)?;
    let id = match fira::parse_ref(reference) {
        Ok(id) => id,
        Err(_) => sprint_by_title(&repo, reference)?,
    };
    let into = match into {
        Some(p) => Some(docs_for(&repo, &[p.to_path_buf()])?[0]),
        None => None,
    };
    sync_run(repo, Mode::Import, Scope::Remote(id), into, opts)
}

/// A sprint named by its title (exact, ignoring case). The sprint id has
/// no place in the Fira UI besides the sprint menu's "Copy import
/// command", so the title is the natural handle.
fn sprint_by_title(repo: &Repo, title: &str) -> Result<uuid::Uuid> {
    let snap = all_sprints(repo)?;
    let want = title.trim();
    let found: Vec<&fira::RemoteSprint> = snap.sprints.iter().filter(|s| s.title.trim().eq_ignore_ascii_case(want)).collect();
    match found.as_slice() {
        [s] => Ok(s.id),
        [] => bail!(
            "{title:?} is not a task link, an id, or the title of a sprint in project \"{}\". \
             Run `task-cli sprints` to list sprints; for a task, use \"Copy link\" in its Fira modal",
            snap.project.title
        ),
        many => bail!(
            "several sprints are titled {title:?}; use the id instead:\n{}",
            many.iter().map(|s| format!("  {}  {}", s.id, fmt_span(s))).collect::<Vec<_>>().join("\n")
        ),
    }
}

fn all_sprints(repo: &Repo) -> Result<fira::Snapshot> {
    client(&repo.root)?.fetch(&FetchRequest {
        project_id: repo.root.project_id()?,
        sprint_ids: vec![],
        task_ids: vec![],
        all_sprints: true,
    })
}

fn fmt_span(s: &fira::RemoteSprint) -> String {
    match (s.starts_on, s.ends_on) {
        (Some(a), Some(b)) => format!("{a} → {b}"),
        _ => "unscheduled".into(),
    }
}

fn sprints() -> Result<u8> {
    let repo = Repo::load(root()?)?;
    let snap = all_sprints(&repo)?;
    if snap.sprints.is_empty() {
        println!("Project \"{}\" has no sprints in Fira.", snap.project.title);
        return Ok(0);
    }
    let width = snap.sprints.iter().map(|s| s.title.chars().count()).max().unwrap_or(0).min(40);
    println!("Sprints in Fira project \"{}\":\n", snap.project.title);
    for s in &snap.sprints {
        let local = repo.sprint_doc(s.id).map_or_else(|| "not imported".to_string(), |d| repo.docs[d].display.clone());
        println!("  {:<23}  {:<width$}  {}  {}", fmt_span(s), s.title, s.id, local);
    }
    println!("\nImport one with: task-cli import fira <id or title>");
    Ok(0)
}

fn sync_run(repo: Repo, mode: Mode, scope: Scope, into: Option<usize>, opts: &SyncOpts) -> Result<u8> {
    let client = client(&repo.root)?;
    let project_id = repo.root.project_id()?;
    let snap = fetch(&repo, &client, &scope)?;
    let cmp = sync::build(&repo, snap, mode, &scope, into)?;
    let style = ui::Style { color: ui::color_ok() };

    if !cmp.actionable() {
        print!("{}", ui::render(&repo, &cmp, &style, "local", false));
        if cmp.in_sync() {
            println!("Nothing to do: the files and Fira agree.");
        } else {
            println!("Nothing to write: everything listed above is left as it is.");
        }
        return Ok(0);
    }
    let text = ui::render(&repo, &cmp, &style, "local", false);

    let decisions = if let Some(p) = opts.prefer {
        print!("{text}");
        let mut notes = vec![];
        let d = sync::prefer(&cmp, if matches!(p, Prefer::Local) { Side::Local } else { Side::Remote }, &mut notes);
        for n in notes {
            eprintln!("{n}");
        }
        d
    } else if opts.dry_run {
        print!("{text}");
        println!("\nDry run: nothing was written. Without --dry-run you choose local or Fira for each differing field.");
        return Ok(0);
    } else if !ui::interactive() {
        print!("{text}");
        bail!(
            "no terminal to ask on. Use `--dry-run` to preview, `task-cli diff --json` to inspect, \
             or `--prefer local|remote` to answer every field in one direction (only when the user asked for it)"
        );
    } else {
        ui::page(&text, opts.no_pager);
        match ui::choose(&repo, &cmp, &style, "local")? {
            Ok(d) => d,
            Err(ui::Quit) => {
                println!("Quit: nothing was written.");
                return Ok(0);
            }
        }
    };

    // Only publish creates tasks, and they go to their creator by default.
    let me = if mode == Mode::Publish { Some(client.whoami()?.user.id) } else { None };
    let plan = sync::plan(&repo, &cmp, &decisions, project_id, me, chrono::Local::now().date_naive())?;
    if plan.is_empty() {
        println!("Nothing to write.");
        return Ok(0);
    }
    let att_writes = plan.uploads.len() + plan.remote_deletes.len();
    println!(
        "\nFira: {}",
        match (plan.ops.len(), att_writes) {
            (0, 0) => "no changes".to_string(),
            (n, 0) => format!("{n} ops"),
            (0, a) => format!("{a} attachment write(s)"),
            (n, a) => format!("{n} ops, then {a} attachment write(s)"),
        }
    );
    for l in &plan.remote_lines {
        println!("  {l}");
    }
    let local_writes = plan.files.len() + plan.downloads.len();
    println!("Local: {}", if local_writes == 0 { "no changes".into() } else { format!("{local_writes} file(s)") });
    for l in &plan.local_lines {
        println!("  {l}");
    }
    if opts.dry_run {
        println!("\nDry run: nothing was written.");
        return Ok(0);
    }
    if opts.prefer.is_none() && !ui::confirm("\nWrite these changes?")? {
        println!("Nothing was written.");
        return Ok(0);
    }

    // Nothing remote may be based on text that changed since it was read.
    for f in &plan.files {
        let d = match f {
            sync::FileWrite::Edit { doc, .. } | sync::FileWrite::Remove { doc } => *doc,
            sync::FileWrite::Create { .. } => continue,
        };
        let doc = &repo.docs[d];
        let now = std::fs::read_to_string(&doc.path).unwrap_or_default();
        if safety::hash(&now) != safety::hash(&doc.text) {
            bail!("{} changed on disk while the prompt was open; nothing was written. Run the command again to see the new diff", doc.display);
        }
    }

    if !plan.ops.is_empty() {
        match client.apply(project_id, &plan.pre, &plan.ops) {
            Ok(res) => println!("Fira: applied {} ops.", res.applied),
            Err(ApplyFailure::Conflict(ids)) => {
                let names: Vec<String> = ids
                    .iter()
                    .map(|id| match cmp.entities.iter().find(|e| e.id == *id) {
                        Some(e) => format!("\"{}\"", e.title()),
                        None if *id == project_id => "task order".to_string(),
                        None => id.to_string(),
                    })
                    .collect();
                bail!(
                    "Fira changed after the diff was shown ({}). Nothing was written, locally or in Fira. Run the command again to see the new diff",
                    names.join(", ")
                );
            }
            Err(ApplyFailure::Rejected(m)) => bail!("Fira rejected the change: {m}. Nothing was written locally"),
            Err(ApplyFailure::Interrupted(m)) => bail!(
                "the connection to Fira broke during the write ({m}). Fira applied either all of it or none of it, \
                 and nothing was written locally. Run the same command again: the diff will show what is left, \
                 and repeating creates is safe"
            ),
            Err(ApplyFailure::Other(e)) => return Err(e.context("nothing was written")),
        }
    }

    // Attachments after the ops (a new task must exist first). Each write
    // stands on its own: a failure leaves the rest, and the next diff
    // shows what is left.
    let mut att_failed = vec![];
    for u in &plan.uploads {
        let what = format!("{} of \"{}\"", u.name, u.task_title);
        let data = match std::fs::read(&u.path) {
            Ok(d) if attachments::sha256_hex(&d) == u.sha256 => d,
            Ok(_) => {
                att_failed.push(format!("{what}: the file changed after the preview; not uploaded"));
                continue;
            }
            Err(e) => {
                att_failed.push(format!("{what}: {e}"));
                continue;
            }
        };
        match client.put_attachment(u.task, &u.name, u.pre, data) {
            Ok(true) => println!("Fira: uploaded {what}"),
            Ok(false) => println!("Fira: {what} was already up to date"),
            Err(e) => att_failed.push(format!("{what}: {e}")),
        }
    }
    for x in &plan.remote_deletes {
        let what = format!("{} of \"{}\"", x.name, x.task_title);
        match client.delete_attachment(x.task, &x.name, x.id) {
            Ok(()) => println!("Fira: deleted attachment {what}"),
            Err(e) => att_failed.push(format!("{what}: {e}")),
        }
    }

    let mut writer = safety::Writer::new(&repo.root.dir);
    let mut skipped = 0;
    // Files before the documents that list them.
    for dl in &plan.downloads {
        let data = match client.download_attachment(dl.id) {
            Ok(d) => d,
            Err(e) => {
                for f in &att_failed {
                    eprintln!("attachment not written: {f}");
                }
                return Err(e.context(format!(
                    "downloading {} failed; no task files were written (Fira's side is done). Run the command again",
                    display_path(&dl.dest)
                )));
            }
        };
        if !dl.sha256.is_empty() {
            let got = attachments::sha256_hex(&data);
            if got != dl.sha256 {
                for f in &att_failed {
                    eprintln!("attachment not written: {f}");
                }
                bail!(
                    "downloaded {} does not match Fira's hash (expected {}, got {}, {} bytes); \
                     it was not written, and no task files were written (Fira's side is done). \
                     Run the command again; if it keeps failing, Fira's stored copy is damaged: \
                     re-upload the file from a good copy",
                    display_path(&dl.dest),
                    dl.sha256,
                    got,
                    data.len()
                );
            }
        }
        match writer.put_file(&dl.dest, dl.replaces.as_deref(), &data)? {
            safety::Outcome::Written => println!("wrote {}", display_path(&dl.dest)),
            safety::Outcome::Skipped(why) => {
                skipped += 1;
                eprintln!("skipped {}: {why}", display_path(&dl.dest));
            }
        }
    }
    for f in &plan.files {
        let (label, outcome) = match f {
            sync::FileWrite::Edit { doc, new_text } => {
                let d = &repo.docs[*doc];
                (d.display.clone(), writer.write(&d.path, &d.text, new_text)?)
            }
            sync::FileWrite::Create { path, text } => (display_path(path), writer.create(path, text)?),
            sync::FileWrite::Remove { doc } => {
                let d = &repo.docs[*doc];
                (format!("{} (removed: its task moved)", d.display), writer.remove(&d.path, &d.text)?)
            }
        };
        match outcome {
            safety::Outcome::Written => println!("wrote {label}"),
            safety::Outcome::Skipped(why) => {
                skipped += 1;
                eprintln!("skipped {label}: {why}");
            }
        }
    }
    writer.report_backups();
    if !att_failed.is_empty() {
        for f in &att_failed {
            eprintln!("attachment not written: {f}");
        }
        eprintln!("Everything else was written. Run the command again: the diff shows what is left (a conflict means the attachment changed in Fira).");
        return Ok(2);
    }
    if skipped > 0 {
        eprintln!("Fira already has the accepted values; run the command again to bring the skipped files in line.");
        return Ok(2);
    }
    Ok(0)
}

// ---- help ----

const HELP_FORMAT: &str = include_str!("help/format.md");
const HELP_WORKFLOW: &str = include_str!("help/workflow.md");
const HELP_AGENTS: &str = include_str!("help/agents.md");

fn help(topic: Option<&str>) -> Result<u8> {
    match topic {
        Some("format") => print!("{HELP_FORMAT}"),
        Some("workflow") => print!("{HELP_WORKFLOW}"),
        Some("agents") => print!("{HELP_AGENTS}"),
        None => {
            use clap::CommandFactory;
            Cli::command().print_help().context("printing help")?;
        }
        Some(other) => bail!("no help topic {other:?}; topics: format, workflow, agents"),
    }
    Ok(0)
}
