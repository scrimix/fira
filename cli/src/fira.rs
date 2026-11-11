//! HTTP client for Fira's `/api/cli/*` endpoints.

use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

pub struct Client {
    base: String,
    token: String,
    http: reqwest::blocking::Client,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Named {
    pub id: Uuid,
    pub title: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    /// May be assigned (owner or active member of the project).
    #[serde(default = "yes")]
    pub active: bool,
    /// In the project (any role); handles are derived among members only.
    #[serde(default = "yes")]
    pub member: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct WhoAmI {
    pub user: User,
    pub workspace: Named,
    pub can_write: bool,
    pub projects: Vec<Named>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RemoteSprint {
    pub id: Uuid,
    pub title: String,
    pub starts_on: Option<NaiveDate>,
    pub ends_on: Option<NaiveDate>,
    pub track_id: Option<Uuid>,
    pub default_assignee_id: Option<Uuid>,
    pub default_tag_ids: Vec<Uuid>,
    pub revision: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RemoteSubtask {
    pub id: Uuid,
    pub title: String,
    pub done: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RemoteTask {
    pub id: Uuid,
    pub sprint_id: Option<Uuid>,
    pub title: String,
    pub description_md: String,
    pub status: String,
    #[allow(dead_code)]
    pub section: String,
    pub assignee_id: Option<Uuid>,
    pub estimate_min: Option<i32>,
    pub tag_ids: Vec<Uuid>,
    pub subtasks: Vec<RemoteSubtask>,
    pub revision: i64,
    /// Absent from servers older than the CLI; new tasks then fall back
    /// to keys that ignore existing order.
    #[serde(default)]
    pub sort_key: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Missing {
    pub id: Uuid,
    pub kind: String,
    /// `deleted`, `other_project` or `never`.
    pub state: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Snapshot {
    pub project: Named,
    pub users: Vec<User>,
    pub tags: Vec<Named>,
    pub tracks: Vec<Named>,
    pub sprints: Vec<RemoteSprint>,
    pub tasks: Vec<RemoteTask>,
    pub missing: Vec<Missing>,
}

#[derive(Debug, Serialize)]
pub struct FetchRequest {
    pub project_id: Uuid,
    pub sprint_ids: Vec<Uuid>,
    pub task_ids: Vec<Uuid>,
    pub all_sprints: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Precondition {
    pub kind: &'static str,
    pub id: Uuid,
    pub revision: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpEnvelope {
    pub op_id: String,
    pub payload: Value,
}

#[derive(Debug, Serialize)]
struct ApplyRequest<'a> {
    project_id: Uuid,
    preconditions: &'a [Precondition],
    ops: &'a [OpEnvelope],
}

#[derive(Debug, Deserialize)]
pub struct ApplyResponse {
    pub applied: usize,
    #[allow(dead_code)]
    pub already_applied: usize,
}

/// A write that Fira refused or that may not have arrived. In every case
/// the batch is all-or-nothing on the server, so the message can say
/// exactly what state things are in.
#[derive(Debug)]
pub enum ApplyFailure {
    Conflict(Vec<Uuid>),
    Rejected(String),
    /// The request may or may not have been applied (connection dropped).
    Interrupted(String),
    Other(anyhow::Error),
}

impl Client {
    pub fn new(base: &str, token: String) -> Result<Client> {
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent(concat!("task-cli/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Client { base: base.trim_end_matches('/').to_string(), token, http })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/api/cli/{path}", self.base)
    }

    fn check(&self, res: reqwest::blocking::Response) -> Result<reqwest::blocking::Response> {
        let status = res.status();
        if status.is_success() {
            return Ok(res);
        }
        let body: Value = res.json().unwrap_or(Value::Null);
        let msg = body.get("error").and_then(|e| e.as_str()).unwrap_or("").to_string();
        match status.as_u16() {
            401 => bail!("Fira rejected the token ({msg}); run `task-cli login fira` with a new token"),
            403 => bail!("Fira refused: {msg}"),
            404 => bail!("not found in Fira ({msg}); check project_id in tasks/config.toml and that you are still a member"),
            503 => bail!("Fira is temporarily unavailable ({msg}); try again"),
            _ => bail!("Fira returned {status}: {msg}"),
        }
    }

    fn network(&self, e: reqwest::Error) -> anyhow::Error {
        anyhow!("could not reach Fira at {}: {e}", self.base)
    }

    pub fn whoami(&self) -> Result<WhoAmI> {
        let res = self.http.get(self.url("whoami")).bearer_auth(&self.token).send().map_err(|e| self.network(e))?;
        Ok(self.check(res)?.json()?)
    }

    pub fn fetch(&self, req: &FetchRequest) -> Result<Snapshot> {
        let res = self
            .http
            .post(self.url("fetch"))
            .bearer_auth(&self.token)
            .json(req)
            .send()
            .map_err(|e| self.network(e))?;
        Ok(self.check(res)?.json()?)
    }

    pub fn apply(&self, project_id: Uuid, pre: &[Precondition], ops: &[OpEnvelope]) -> Result<ApplyResponse, ApplyFailure> {
        let body = ApplyRequest { project_id, preconditions: pre, ops };
        let res = match self.http.post(self.url("apply")).bearer_auth(&self.token).json(&body).send() {
            Ok(r) => r,
            Err(e) if e.is_connect() => return Err(ApplyFailure::Other(self.network(e))),
            Err(e) => return Err(ApplyFailure::Interrupted(e.to_string())),
        };
        let status = res.status();
        if status.is_success() {
            return res.json().map_err(|e| ApplyFailure::Interrupted(e.to_string()));
        }
        let body: Value = res.json().unwrap_or(Value::Null);
        let msg = body.get("error").and_then(|e| e.as_str()).unwrap_or("").to_string();
        match status.as_u16() {
            409 => {
                let ids = body
                    .get("conflicts")
                    .and_then(|c| c.as_array())
                    .map(|a| a.iter().filter_map(|c| c.get("id")?.as_str()?.parse().ok()).collect())
                    .unwrap_or_default();
                Err(ApplyFailure::Conflict(ids))
            }
            400 => Err(ApplyFailure::Rejected(msg)),
            401 => Err(ApplyFailure::Other(anyhow!("Fira rejected the token ({msg}); run `task-cli login fira`"))),
            403 => Err(ApplyFailure::Other(anyhow!("Fira refused the write: {msg}"))),
            _ => Err(ApplyFailure::Other(anyhow!("Fira returned {status}: {msg}"))),
        }
    }
}

/// The task or sprint UUID in a Fira link (`…#/w/<ws>/t/<task>`) or a bare id.
pub fn parse_ref(s: &str) -> Result<Uuid> {
    let s = s.trim();
    if let Ok(id) = s.parse() {
        return Ok(id);
    }
    // Last UUID-shaped segment of the URL.
    let found = s
        .split(|c: char| !(c.is_ascii_hexdigit() || c == '-'))
        .filter(|seg| seg.len() == 36)
        .filter_map(|seg| seg.parse::<Uuid>().ok())
        .next_back();
    found.ok_or_else(|| anyhow!("{s:?} is neither a task/sprint id nor a Fira link containing one"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_links_and_ids() {
        let id = "0b5a8c1e-2d3f-4a5b-8c7d-9e0f1a2b3c4d";
        let ws = "11111111-2d3f-4a5b-8c7d-9e0f1a2b3c4d";
        assert_eq!(parse_ref(id).unwrap().to_string(), id);
        assert_eq!(parse_ref(&format!("https://usefira.app/#/w/{ws}/t/{id}")).unwrap().to_string(), id);
        assert!(parse_ref("nope").is_err());
    }
}
