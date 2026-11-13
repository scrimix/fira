//! Blocks ↔ Notion's JSON.

use serde_json::{json, Map, Value};

use super::ir::{normalize, Block, ListKind, Marks, Span};
use crate::attachments::SCHEME;

/// A block to append, with the children Notion must get in follow-up
/// requests (it takes two levels per request).
pub struct Node {
    pub json: Value,
    pub children: Vec<Node>,
}

/// How a block refers to people and uploaded files when written.
pub struct WriteCtx<'a> {
    /// Handle (`maya.c`) → Notion user id, for the task line's assignee.
    pub mention: &'a dyn Fn(&str) -> Option<String>,
    /// File upload ids for the `attachment:` embeds, in document order.
    pub uploads: &'a mut std::vec::IntoIter<Option<String>>,
}

const MAX_TEXT: usize = 2000;

fn annotations(m: &Marks, gray: bool) -> Value {
    json!({
        "bold": m.bold,
        "italic": m.italic,
        "strikethrough": m.strike,
        "underline": m.underline,
        "code": m.code,
        "color": if gray { "gray" } else { "default" },
    })
}

fn text_item(content: &str, marks: &Marks, link: Option<&str>, gray: bool) -> Vec<Value> {
    let chars: Vec<char> = content.chars().collect();
    chars
        .chunks(MAX_TEXT)
        .map(|c| {
            let s: String = c.iter().collect();
            let mut text = json!({"content": s});
            if let Some(url) = link {
                text["link"] = json!({"url": url});
            }
            json!({"type": "text", "text": text, "annotations": annotations(marks, gray)})
        })
        .collect()
}

pub fn rich(spans: &[Span], gray: bool) -> Vec<Value> {
    let mut out = vec![];
    for s in spans {
        match &s.mention {
            Some(id) => out.push(json!({"type": "mention", "mention": {"type": "user", "user": {"id": id}}, "annotations": annotations(&s.marks, gray)})),
            None => out.extend(text_item(&s.text, &s.marks, s.link.as_deref(), gray)),
        }
    }
    out
}

fn obj(kind: &str, body: Value) -> Value {
    let mut m = Map::new();
    m.insert("object".into(), json!("block"));
    m.insert("type".into(), json!(kind));
    m.insert(kind.into(), body);
    Value::Object(m)
}

/// The task line, gray, with the assignee as a mention when the person is
/// matched in Notion.
fn task_line(raw: &str, ctx: &WriteCtx) -> Value {
    let short = shorten_id(raw);
    let raw = short.as_str();
    let plain = |t: &str| Span::plain(t);
    let mut spans = vec![plain(raw)];
    if let Some(at) = raw.find(" assignee=") {
        let vstart = at + " assignee=".len();
        let mut in_q = false;
        let mut vend = raw.len();
        for (i, c) in raw[vstart..].char_indices() {
            match c {
                '"' => in_q = !in_q,
                c if c.is_whitespace() && !in_q => {
                    vend = vstart + i;
                    break;
                }
                _ => {}
            }
        }
        let value = raw[vstart..vend].trim_matches('"');
        if let Some(id) = (!value.is_empty()).then(|| (ctx.mention)(value)).flatten() {
            spans = vec![
                plain(&raw[..vstart]),
                Span { text: value.to_string(), marks: Marks::default(), link: None, mention: Some(id) },
                plain(&raw[vend..]),
            ];
        }
    }
    obj("paragraph", json!({"rich_text": rich(&spans, true)}))
}

/// Digits of a task id shown in Notion: enough to tell a file's tasks
/// apart, short enough to keep the task line on one line.
pub const SHORT_ID: usize = 8;

/// `id=<uuid>` → `id=<first 8 hex digits>`.
pub fn shorten_id(raw: &str) -> String {
    let Some(at) = raw.find(" id=") else { return raw.to_string() };
    let start = at + " id=".len();
    let end = raw[start..].find(char::is_whitespace).map_or(raw.len(), |i| start + i);
    if uuid::Uuid::try_parse(&raw[start..end]).is_err() {
        return raw.to_string();
    }
    format!("{}{}{}", &raw[..start], &raw[start..start + SHORT_ID], &raw[end..])
}

/// The reverse, against the ids of the file's tasks. An id that matches
/// none (a task that moved to another file) gets a stand-in that matches
/// nothing, so the section reads as "not a task of this file".
pub fn expand_id(raw: &str, ids: &[uuid::Uuid]) -> String {
    let Some(at) = raw.find(" id=") else { return raw.to_string() };
    let start = at + " id=".len();
    let end = raw[start..].find(char::is_whitespace).map_or(raw.len(), |i| start + i);
    let short = raw[start..end].to_ascii_lowercase();
    if uuid::Uuid::try_parse(&short).is_ok() || short.len() != SHORT_ID || !short.chars().all(|c| c.is_ascii_hexdigit()) {
        return raw.to_string();
    }
    let found: Vec<&uuid::Uuid> = ids.iter().filter(|id| id.to_string().starts_with(&short)).collect();
    let full = match found.as_slice() {
        [id] => id.to_string(),
        _ => format!("{short}-0000-0000-0000-000000000000"),
    };
    format!("{}{full}{}", &raw[..start], &raw[end..])
}


pub fn to_nodes(blocks: &[Block], ctx: &mut WriteCtx) -> Vec<Node> {
    blocks.iter().filter_map(|b| to_node(b, ctx)).collect()
}

fn to_node(b: &Block, ctx: &mut WriteCtx) -> Option<Node> {
    let leaf = |json: Value| Some(Node { json, children: vec![] });
    match b {
        Block::Heading(n, s) => leaf(obj(&format!("heading_{n}"), json!({"rich_text": rich(s, false)}))),
        Block::Paragraph(s) => leaf(obj("paragraph", json!({"rich_text": rich(s, false)}))),
        Block::Quote(s) => leaf(obj("quote", json!({"rich_text": rich(s, false)}))),
        Block::Code { lang, text } => leaf(obj(
            "code",
            json!({"rich_text": rich(&[Span::plain(text.clone())], false), "language": if lang.is_empty() { "plain text" } else { lang }}),
        )),
        Block::Divider => leaf(obj("divider", json!({}))),
        Block::TaskLine(raw) => leaf(task_line(raw, ctx)),
        Block::Other { text, .. } => leaf(obj("paragraph", json!({"rich_text": rich(&[Span::plain(text.clone())], false)}))),
        Block::Item { kind, text, children } => {
            let (k, mut body) = match kind {
                ListKind::Bullet => ("bulleted_list_item", json!({"rich_text": rich(text, false)})),
                ListKind::Number => ("numbered_list_item", json!({"rich_text": rich(text, false)})),
                ListKind::ToDo(done) => ("to_do", json!({"rich_text": rich(text, false), "checked": done})),
            };
            if text.is_empty() {
                body["rich_text"] = json!([]);
            }
            Some(Node { json: obj(k, body), children: to_nodes(children, ctx) })
        }
        // No captions: files are recognised by their name when read back,
        // and alt text stays in the file.
        Block::Embed { image, dest, alt } => {
            if dest.starts_with(SCHEME) {
                let kind = if *image { "image" } else { "file" };
                match ctx.uploads.next().flatten() {
                    Some(id) => leaf(obj(kind, json!({"type": "file_upload", "file_upload": {"id": id}}))),
                    None => leaf(obj("paragraph", json!({"rich_text": rich(&[Span::plain(if alt.is_empty() { dest.clone() } else { alt.clone() })], false)}))),
                }
            } else {
                leaf(obj("image", json!({"type": "external", "external": {"url": dest}})))
            }
        }
    }
}

// ---- reading ----

pub fn plain_text(rich: &Value) -> String {
    rich.as_array()
        .map(|a| a.iter().filter_map(|r| r["plain_text"].as_str()).collect())
        .unwrap_or_default()
}

fn is_web(url: &str) -> bool {
    let u = url.to_ascii_lowercase();
    u.starts_with("http://") || u.starts_with("https://") || u.starts_with("mailto:")
}

pub fn spans(rich: &Value) -> Vec<Span> {
    let mut out = vec![];
    for r in rich.as_array().into_iter().flatten() {
        let a = &r["annotations"];
        let marks = Marks {
            bold: a["bold"].as_bool().unwrap_or(false),
            italic: a["italic"].as_bool().unwrap_or(false),
            strike: a["strikethrough"].as_bool().unwrap_or(false),
            code: a["code"].as_bool().unwrap_or(false),
            underline: a["underline"].as_bool().unwrap_or(false),
        };
        let text = r["plain_text"].as_str().unwrap_or_default().to_string();
        match r["type"].as_str() {
            Some("text") => {
                let link = r["text"]["link"]["url"].as_str().filter(|u| is_web(u)).map(str::to_string);
                out.push(Span { text: r["text"]["content"].as_str().map_or(text, str::to_string), marks, link, mention: None });
            }
            Some("mention") if r["mention"]["type"] == "user" => {
                let id = r["mention"]["user"]["id"].as_str().map(str::to_string);
                out.push(Span { text, marks, link: None, mention: id });
            }
            _ => out.push(Span { text, marks, link: None, mention: None }),
        }
    }
    normalize(out)
}

/// Read one block (its children already read). `handle_of` turns a Notion
/// user id into the handle a file uses.
/// A file stored in Notion, as a name the repository can use.
fn file_name(body: &Value) -> String {
    let from_url = || {
        let url = body["file"]["url"].as_str().unwrap_or_default();
        let path = url.split(['?', '#']).next().unwrap_or_default();
        percent_decode(path.rsplit('/').next().unwrap_or_default())
    };
    let raw = body["name"].as_str().map(str::to_string).filter(|n| !n.trim().is_empty()).unwrap_or_else(from_url);
    let mut n: String = raw
        .trim()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '-' })
        .collect();
    n = n.trim_start_matches(['.', '-']).to_string();
    if n.len() > 100 {
        let ext = n.rsplit_once('.').map(|(_, e)| format!(".{e}")).unwrap_or_default();
        n = format!("{}{ext}", &n[..100 - ext.len().min(20)]);
    }
    if n.is_empty() { "file".into() } else { n }
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Some(v) = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Read one block (its children already read). `handle_of` turns a Notion
/// user id into the handle a file uses; files stored in Notion are listed
/// in `files` as (name, download url).
pub fn from_json(v: &Value, children: Vec<Block>, handle_of: &dyn Fn(&str, &str) -> String, notices: &mut Vec<String>, files: &mut Vec<(String, String)>) -> Option<Block> {
    let kind = v["type"].as_str().unwrap_or("unknown");
    let body = &v[kind];
    let rt = &body["rich_text"];
    let text_of = || spans(rt);
    let dropped_children = |notices: &mut Vec<String>, what: &str| {
        if !children.is_empty() {
            notices.push(format!("content nested inside a {what} in Notion is not read"));
        }
    };
    let b = match kind {
        "paragraph" => {
            dropped_children(notices, "paragraph");
            let plain = plain_text(rt);
            let t = plain.trim();
            if t.starts_with("<!--") && t[4..].trim_start().starts_with("task:") {
                // Mentions become handles again.
                let mut raw = String::new();
                for r in rt.as_array().into_iter().flatten() {
                    if r["type"] == "mention" && r["mention"]["type"] == "user" {
                        let id = r["mention"]["user"]["id"].as_str().unwrap_or_default();
                        let name = r["plain_text"].as_str().unwrap_or_default().trim_start_matches('@');
                        raw.push_str(&crate::doc::quote_item(&handle_of(id, name)));
                    } else {
                        raw.push_str(r["plain_text"].as_str().unwrap_or_default());
                    }
                }
                Block::TaskLine(raw.trim().to_string())
            } else {
                Block::Paragraph(text_of())
            }
        }
        "heading_1" | "heading_2" | "heading_3" => {
            dropped_children(notices, "toggle heading");
            Block::Heading(kind.as_bytes()[8] - b'0', text_of())
        }
        "heading_4" => Block::Paragraph(text_of().into_iter().map(|mut s| { s.marks.bold = true; s }).collect()),
        "bulleted_list_item" => Block::Item { kind: ListKind::Bullet, text: text_of(), children },
        "numbered_list_item" => Block::Item { kind: ListKind::Number, text: text_of(), children },
        "to_do" => Block::Item { kind: ListKind::ToDo(body["checked"].as_bool().unwrap_or(false)), text: text_of(), children },
        "quote" => {
            dropped_children(notices, "quote");
            Block::Quote(text_of())
        }
        "code" => {
            let lang = body["language"].as_str().unwrap_or("plain text");
            Block::Code { lang: if lang == "plain text" { String::new() } else { lang.to_string() }, text: plain_text(rt) }
        }
        "divider" => Block::Divider,
        "image" | "file" => {
            if body["type"] == "file" {
                let url = body["file"]["url"].as_str().unwrap_or_default().to_string();
                // Names are made unique per task later (`scope_files`).
                let name = file_name(body);
                files.push((name.clone(), url));
                return Some(Block::Embed { image: kind == "image", dest: format!("{SCHEME}{name}"), alt: String::new() });
            }
            if kind == "image" && body["type"] == "external" {
                if let Some(url) = body["external"]["url"].as_str() {
                    return Some(Block::Embed { image: true, dest: url.to_string(), alt: String::new() });
                }
            }
            notices.push(format!("a linked {kind} in Notion is not imported (upload it instead)"));
            return None;
        }
        other => {
            let text = plain_text(rt);
            notices.push(format!("unsupported Notion block {other}, read as text"));
            if text.trim().is_empty() {
                return None;
            }
            Block::Other { kind: other.to_string(), text }
        }
    };
    Some(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_ids_round_trip() {
        let id: uuid::Uuid = "a2dea70a-f1e6-5136-84c7-36f2851856d7".parse().unwrap();
        let raw = format!("<!-- task: id={id} tags=perf -->");
        let short = shorten_id(&raw);
        assert_eq!(short, "<!-- task: id=a2dea70a tags=perf -->");
        assert_eq!(expand_id(&short, &[id]), raw);
        assert_eq!(expand_id(&short, &[]), "<!-- task: id=a2dea70a-0000-0000-0000-000000000000 tags=perf -->");
        assert_eq!(expand_id("<!-- task: tags=x -->", &[id]), "<!-- task: tags=x -->");
    }
}
