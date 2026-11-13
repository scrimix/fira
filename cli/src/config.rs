//! `tasks/config.toml` (committed, no secrets) and the per-developer
//! credentials file (outside the repository).

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use uuid::Uuid;

pub const CONFIG_FILE: &str = "config.toml";

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub fira: FiraConfig,
    #[serde(default)]
    pub notion: NotionConfig,
}

/// `[notion]`: optional. No page or database ids here: pages are linked
/// per file (`notion:` / `notion=`).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct NotionConfig {
    /// The heading text that starts the synced region on a page.
    pub anchor: Option<String>,
    /// Which stored Notion login to use when there are several; filled in
    /// by `task-cli login notion`.
    pub workspace: Option<String>,
    /// Show each task's `<!-- task: … -->` line (id, tags, assignee,
    /// estimate) on the page. Off by default: tasks are matched by title.
    pub task_ids: Option<bool>,
}

pub const DEFAULT_ANCHOR: &str = "Tasks";

impl NotionConfig {
    pub fn task_ids(&self) -> bool {
        self.task_ids.unwrap_or(false)
    }

    pub fn anchor(&self) -> &str {
        self.anchor.as_deref().map(str::trim).filter(|a| !a.is_empty()).unwrap_or(DEFAULT_ANCHOR)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct FiraConfig {
    pub url: String,
    pub workspace_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct Root {
    /// The tasks root: the directory holding `config.toml`.
    pub dir: PathBuf,
    pub config: Config,
}

impl Root {
    pub fn config_path(&self) -> PathBuf {
        self.dir.join(CONFIG_FILE)
    }

    pub fn project_id(&self) -> Result<Uuid> {
        self.config.fira.project_id.ok_or_else(|| {
            anyhow!(
                "{} has no project_id; run `task-cli login fira` to pick the Fira project",
                display_path(&self.config_path())
            )
        })
    }
}

fn is_tasks_config(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.parse::<toml::Table>().ok())
        .is_some_and(|t| t.get("fira").is_some_and(|f| f.is_table()))
}

/// Walk up from `start` to the directory containing a task-cli
/// `config.toml`. At each level `tasks/config.toml` is also checked, so the
/// CLI works from the repository root. This is deliberately not the git
/// top level: `tasks/` may be a submodule or a plain directory.
pub fn find_root(start: &Path) -> Result<Root> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        for candidate in [d.join(CONFIG_FILE), d.join("tasks").join(CONFIG_FILE)] {
            if is_tasks_config(&candidate) {
                let root = candidate.parent().unwrap().to_path_buf();
                return load_root(root);
            }
        }
        dir = d.parent();
    }
    bail!(
        "no tasks/config.toml found in {} or any parent directory; run `task-cli init` in the repository first",
        start.display()
    )
}

pub fn load_root(dir: PathBuf) -> Result<Root> {
    let path = dir.join(CONFIG_FILE);
    let text = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let config: Config = toml::from_str(&text)
        .map_err(|e| anyhow!("{}: {e}", display_path(&path)))?;
    Ok(Root { dir, config })
}

/// Set `[fira]` keys in config.toml, keeping comments and layout.
pub fn update_config(root: &Root, set: &[(&str, String)]) -> Result<()> {
    update_table(root, "fira", set)
}

/// Set keys of one table in config.toml (creating the table), keeping
/// comments and layout.
pub fn update_table(root: &Root, table: &str, set: &[(&str, String)]) -> Result<()> {
    let path = root.config_path();
    let text = std::fs::read_to_string(&path)?;
    let mut doc: toml_edit::DocumentMut = text.parse()?;
    if !doc.contains_table(table) {
        doc[table] = toml_edit::table();
    }
    for (k, v) in set {
        doc[table][k] = toml_edit::value(v.clone());
    }
    crate::safety::atomic_write(&path, &doc.to_string())
}

pub fn initial_config(url: &str) -> String {
    format!(
        "# task-cli configuration. Committed to the repository; holds no secrets.\n\
         # Credentials are per developer and live outside the repository\n\
         # (see `task-cli login fira`).\n\
         \n\
         # workspace_id and project_id are filled in by `task-cli login fira`.\n\
         [fira]\n\
         url = \"{url}\"\n"
    )
}

// ---- credentials ----

#[derive(Debug, Clone, Deserialize, serde::Serialize, Default)]
pub struct Credentials {
    #[serde(default)]
    pub fira: Vec<FiraCredential>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notion: Vec<NotionCredential>,
}

/// A Notion internal integration token, keyed by the integration's bot
/// user (one per workspace).
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct NotionCredential {
    pub workspace: String,
    pub bot_id: String,
    pub token: String,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct FiraCredential {
    pub url: String,
    pub workspace_id: Uuid,
    pub token: String,
}

/// `$TASK_CLI_CONFIG_DIR`, else `$XDG_CONFIG_HOME/task-cli`, else
/// `~/.config/task-cli`. One file holds every login (keyed by URL and
/// workspace), so the directory can be shared between projects; the dev
/// container bind-mounts the host's copy.
pub fn config_dir() -> Result<PathBuf> {
    if let Some(d) = std::env::var_os("TASK_CLI_CONFIG_DIR") {
        return Ok(PathBuf::from(d));
    }
    if let Some(d) = std::env::var_os("XDG_CONFIG_HOME").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(d).join("task-cli"));
    }
    let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set; set TASK_CLI_CONFIG_DIR"))?;
    Ok(PathBuf::from(home).join(".config").join("task-cli"))
}

pub fn credentials_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("credentials.toml"))
}

pub fn load_credentials() -> Result<Credentials> {
    let path = credentials_path()?;
    match std::fs::read_to_string(&path) {
        Ok(s) => toml::from_str(&s).map_err(|e| anyhow!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Credentials::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

pub fn save_credential(cred: FiraCredential) -> Result<PathBuf> {
    let mut all = load_credentials()?;
    all.fira.retain(|c| !(same_url(&c.url, &cred.url) && c.workspace_id == cred.workspace_id));
    all.fira.push(cred);
    save_all(&all)
}

pub fn save_notion_credential(cred: NotionCredential) -> Result<PathBuf> {
    let mut all = load_credentials()?;
    all.notion.retain(|c| c.bot_id != cred.bot_id && c.workspace != cred.workspace);
    all.notion.push(cred);
    save_all(&all)
}

/// `TASK_CLI_NOTION_TOKEN` wins (for CI); else the stored login for
/// `[notion] workspace`, or the only one stored.
pub fn notion_token(cfg: &NotionConfig) -> Result<String> {
    if let Ok(t) = std::env::var("TASK_CLI_NOTION_TOKEN") {
        if !t.trim().is_empty() {
            return Ok(t.trim().to_string());
        }
    }
    let creds = load_credentials()?;
    let found: Vec<&NotionCredential> = creds
        .notion
        .iter()
        .filter(|c| cfg.workspace.as_ref().is_none_or(|w| *w == c.workspace))
        .collect();
    match found.as_slice() {
        [c] => Ok(c.token.clone()),
        [] => match &cfg.workspace {
            Some(w) => bail!("not logged in to Notion workspace \"{w}\"; run `task-cli login notion`"),
            None => bail!("not logged in to Notion; run `task-cli login notion`"),
        },
        _ => bail!("several stored Notion logins; set `workspace` under [notion] in tasks/config.toml or run `task-cli login notion` again"),
    }
}

fn save_all(all: &Credentials) -> Result<PathBuf> {
    let dir = config_dir()?;
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let path = credentials_path()?;
    let text = format!(
        "# task-cli credentials. Personal: never commit or share this file.\n{}",
        toml::to_string(all)?
    );
    crate::safety::atomic_write_private(&path, &text)?;
    Ok(path)
}

pub fn same_url(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

/// `TASK_CLI_FIRA_TOKEN` wins (for CI); else the stored credential for
/// this URL and workspace.
pub fn token_for(cfg: &FiraConfig) -> Result<String> {
    if let Ok(t) = std::env::var("TASK_CLI_FIRA_TOKEN") {
        if !t.trim().is_empty() {
            return Ok(t.trim().to_string());
        }
    }
    let creds = load_credentials()?;
    let found: Vec<&FiraCredential> = creds
        .fira
        .iter()
        .filter(|c| same_url(&c.url, &cfg.url) && cfg.workspace_id.is_none_or(|w| w == c.workspace_id))
        .collect();
    match found.as_slice() {
        [c] => Ok(c.token.clone()),
        [] => bail!("not logged in to {}; run `task-cli login fira`", cfg.url),
        _ => bail!(
            "several stored logins for {}; set workspace_id in tasks/config.toml or run `task-cli login fira` again",
            cfg.url
        ),
    }
}

/// A path for messages: relative to the current directory when it is
/// underneath it.
pub fn display_path(p: &Path) -> String {
    if let Ok(cwd) = std::env::current_dir() {
        if let Ok(rel) = p.strip_prefix(&cwd) {
            return rel.display().to_string();
        }
    }
    p.display().to_string()
}
