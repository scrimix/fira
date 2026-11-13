//! A small blocking client for the Notion API: pacing, retries on 429,
//! pagination, and the handful of endpoints task-cli uses.

use std::cell::Cell;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};

const BASE: &str = "https://api.notion.com/v1";
pub const VERSION: &str = "2026-03-11";
/// Notion allows about 3 requests per second per integration.
const GAP: Duration = Duration::from_millis(340);

/// An error response from Notion, kept so callers can tell a missing page
/// from anything else.
#[derive(Debug)]
pub struct ApiError {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Notion: {} ({}, HTTP {})", self.message, self.code, self.status)
    }
}

impl std::error::Error for ApiError {}

pub fn status_of(e: &anyhow::Error) -> Option<(u16, &str)> {
    e.downcast_ref::<ApiError>().map(|a| (a.status, a.code.as_str()))
}

pub struct Api {
    http: reqwest::blocking::Client,
    token: String,
    last: Cell<Option<Instant>>,
    pub requests: Cell<usize>,
}

impl Api {
    pub fn new(token: String) -> Result<Api> {
        let http = reqwest::blocking::Client::builder()
            .user_agent(concat!("task-cli/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(60))
            .build()?;
        Ok(Api { http, token, last: Cell::new(None), requests: Cell::new(0) })
    }

    fn pace(&self) {
        if let Some(t) = self.last.get() {
            let since = t.elapsed();
            if since < GAP {
                std::thread::sleep(GAP - since);
            }
        }
        self.last.set(Some(Instant::now()));
    }

    fn send(&self, make: &dyn Fn() -> Result<reqwest::blocking::RequestBuilder>) -> Result<Value> {
        let mut attempt = 0;
        loop {
            self.pace();
            self.requests.set(self.requests.get() + 1);
            let req = make()?.bearer_auth(&self.token).header("Notion-Version", VERSION);
            let resp = req.send().context("connecting to Notion")?;
            let status = resp.status().as_u16();
            if (status == 429 || status == 529 || status == 503) && attempt < 6 {
                attempt += 1;
                let wait = resp
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.trim().parse::<u64>().ok())
                    .unwrap_or(1 << attempt.min(5));
                eprintln!("Notion is rate limiting; waiting {wait}s");
                std::thread::sleep(Duration::from_secs(wait.min(60)));
                continue;
            }
            let text = resp.text().unwrap_or_default();
            let body: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            if !(200..300).contains(&status) {
                return Err(ApiError {
                    status,
                    code: body["code"].as_str().unwrap_or("error").to_string(),
                    message: body["message"].as_str().map(str::to_string).unwrap_or_else(|| text.chars().take(200).collect()),
                }
                .into());
            }
            return Ok(body);
        }
    }

    fn get(&self, path: &str) -> Result<Value> {
        let url = format!("{BASE}{path}");
        self.send(&|| Ok(self.http.get(&url)))
    }

    fn json(&self, method: reqwest::Method, path: &str, body: Value) -> Result<Value> {
        let url = format!("{BASE}{path}");
        self.send(&|| Ok(self.http.request(method.clone(), &url).json(&body)))
    }

    fn paged(&self, path: &str) -> Result<Vec<Value>> {
        let mut out = vec![];
        let mut cursor: Option<String> = None;
        loop {
            let sep = if path.contains('?') { '&' } else { '?' };
            let p = match &cursor {
                Some(c) => format!("{path}{sep}page_size=100&start_cursor={c}"),
                None => format!("{path}{sep}page_size=100"),
            };
            let v = self.get(&p)?;
            out.extend(v["results"].as_array().cloned().unwrap_or_default());
            match (v["has_more"].as_bool(), v["next_cursor"].as_str()) {
                (Some(true), Some(c)) => cursor = Some(c.to_string()),
                _ => return Ok(out),
            }
        }
    }

    /// The token's own user (the integration's bot).
    pub fn me(&self) -> Result<Value> {
        self.get("/users/me")
    }

    pub fn users(&self) -> Result<Vec<Value>> {
        self.paged("/users")
    }

    pub fn page(&self, id: &str) -> Result<Value> {
        self.get(&format!("/pages/{id}"))
    }

    pub fn children(&self, id: &str) -> Result<Vec<Value>> {
        self.paged(&format!("/blocks/{id}/children"))
    }

    /// Append `children` under `parent`, after block `after` (or at the
    /// end). Returns the created top-level blocks.
    pub fn append(&self, parent: &str, after: Option<&str>, children: Vec<Value>) -> Result<Vec<Value>> {
        let position = match after {
            Some(id) => json!({"type": "after_block", "after_block": {"id": id}}),
            None => json!({"type": "end"}),
        };
        let v = self.json(reqwest::Method::PATCH, &format!("/blocks/{parent}/children"), json!({"children": children, "position": position}))?;
        Ok(v["results"].as_array().cloned().unwrap_or_default())
    }

    /// Move a block to the trash.
    pub fn delete(&self, id: &str) -> Result<()> {
        let url = format!("{BASE}/blocks/{id}");
        match self.send(&|| Ok(self.http.delete(&url))) {
            Ok(_) => Ok(()),
            // Already gone (deleted by someone else meanwhile) is fine.
            Err(e) if matches!(status_of(&e), Some((404, _))) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// A file Notion hosts (a signed URL, no token).
    pub fn download(&self, url: &str) -> Result<Vec<u8>> {
        let resp = self.http.get(url).send().context("downloading from Notion")?;
        if !resp.status().is_success() {
            anyhow::bail!("downloading from Notion: HTTP {}", resp.status());
        }
        Ok(resp.bytes()?.to_vec())
    }

    /// Upload a small file; returns the file upload id to put in a block
    /// within the hour.
    pub fn upload(&self, name: &str, content_type: &str, data: Vec<u8>) -> Result<String> {
        let created = self.json(reqwest::Method::POST, "/file_uploads", json!({"filename": name, "content_type": content_type}))?;
        let id = created["id"].as_str().ok_or_else(|| anyhow!("Notion returned no file upload id"))?.to_string();
        let url = format!("{BASE}/file_uploads/{id}/send");
        let (name, ct) = (name.to_string(), content_type.to_string());
        self.send(&|| {
            let part = reqwest::blocking::multipart::Part::bytes(data.clone()).file_name(name.clone()).mime_str(&ct)?;
            Ok(self.http.post(&url).multipart(reqwest::blocking::multipart::Form::new().part("file", part)))
        })?;
        Ok(id)
    }
}
