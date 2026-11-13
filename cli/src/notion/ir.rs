//! The block model between a task document's Markdown and Notion.
//!
//! Publishing turns Markdown into these blocks and the blocks into Notion
//! JSON; reading turns Notion JSON into blocks and the blocks back into
//! Markdown, which the ordinary document parser then reads. The local side
//! is compared through the same round trip (`to_markdown(from_markdown(…))`),
//! so whatever Markdown can't survive the trip (a reference link, a table,
//! a fourth heading level) is lost on both sides alike and never shows up
//! as a difference.

use pulldown_cmark::{CodeBlockKind, Event, HeadingLevel, Options, Parser, Tag, TagEnd};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Marks {
    pub bold: bool,
    pub italic: bool,
    pub strike: bool,
    pub code: bool,
    /// Reserved for links to the task's own attachments, which Notion
    /// can't link to: the label is underlined and read back as the link.
    pub underline: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Span {
    pub text: String,
    pub marks: Marks,
    /// An http(s) or mailto link.
    pub link: Option<String>,
    /// A Notion user mention (user id); `text` is the shown name.
    pub mention: Option<String>,
}

impl Span {
    pub fn plain(text: impl Into<String>) -> Span {
        Span { text: text.into(), marks: Marks::default(), link: None, mention: None }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListKind {
    Bullet,
    Number,
    ToDo(bool),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Block {
    /// Levels 1–3 (Notion has three).
    Heading(u8, Vec<Span>),
    Paragraph(Vec<Span>),
    Item { kind: ListKind, text: Vec<Span>, children: Vec<Block> },
    Quote(Vec<Span>),
    /// `lang` is Notion's language name; empty for plain text.
    Code { lang: String, text: String },
    Divider,
    /// An embedded file: `dest` is `attachment:<name>` or an http(s) URL.
    Embed { image: bool, dest: String, alt: String },
    /// A task's `<!-- task: … -->` line, verbatim.
    TaskLine(String),
    /// Read only: a Notion block the CLI doesn't write, as its text.
    Other { kind: String, text: String },
}

const SCHEME: &str = crate::attachments::SCHEME;

fn is_web(dest: &str) -> bool {
    let d = dest.to_ascii_lowercase();
    d.starts_with("http://") || d.starts_with("https://") || d.starts_with("mailto:")
}

fn is_image_name(name: &str) -> bool {
    crate::attachments::content_type(name).starts_with("image/")
}

// ---- Markdown → blocks ----

#[derive(Debug)]
enum Piece {
    Span(Span),
    Image { dest: String, alt: String },
}

enum Target {
    Paragraph,
    Heading(u8),
    ItemText,
}

enum FrameKind {
    Root,
    Quote,
    Item { kind: ListKind, text: Option<Vec<Span>> },
}

struct Frame {
    kind: FrameKind,
    blocks: Vec<Block>,
}

enum LinkKind {
    Web(String),
    Attachment(String),
    Plain,
}

struct Builder<'a> {
    src: &'a str,
    frames: Vec<Frame>,
    lists: Vec<bool>,
    inline: Option<(Target, Vec<Piece>)>,
    bold: u32,
    italic: u32,
    strike: u32,
    links: Vec<(LinkKind, String)>,
    image: Option<(String, String)>,
    code: Option<(String, String)>,
    html: Option<String>,
    skip: u32,
    /// `[label](attachment:name)` links seen, as (label, dest).
    attach: &'a mut Vec<(String, String)>,
}

/// Notion's name for a fenced code block's language; empty = plain text.
pub fn notion_lang(lang: &str) -> String {
    let l = lang.trim().to_ascii_lowercase();
    let mapped = match l.as_str() {
        "sh" | "zsh" | "console" => "shell",
        "js" | "jsx" | "mjs" => "javascript",
        "ts" | "tsx" => "typescript",
        "py" => "python",
        "rb" => "ruby",
        "rs" => "rust",
        "yml" => "yaml",
        "md" => "markdown",
        "dockerfile" => "docker",
        "cs" | "csharp" => "c#",
        "cpp" | "cxx" => "c++",
        "kt" => "kotlin",
        "golang" => "go",
        "text" | "txt" | "plaintext" | "plain text" => "",
        other => other,
    };
    const KNOWN: &[&str] = &[
        "bash", "c", "c#", "c++", "clojure", "css", "dart", "diff", "docker", "elixir", "erlang", "go", "graphql",
        "haskell", "html", "java", "javascript", "json", "kotlin", "latex", "lua", "makefile", "markdown", "mermaid",
        "nix", "objective-c", "ocaml", "perl", "php", "powershell", "protobuf", "python", "r", "ruby", "rust", "sass",
        "scala", "scss", "shell", "sql", "swift", "toml", "typescript", "xml", "yaml",
    ];
    if KNOWN.contains(&mapped) {
        mapped.to_string()
    } else {
        String::new()
    }
}

impl Builder<'_> {
    fn marks(&self) -> Marks {
        Marks {
            bold: self.bold > 0,
            italic: self.italic > 0,
            strike: self.strike > 0,
            code: false,
            underline: self.links.iter().any(|(k, _)| matches!(k, LinkKind::Attachment(_))),
        }
    }

    fn web_link(&self) -> Option<String> {
        self.links.iter().rev().find_map(|(k, _)| match k {
            LinkKind::Web(u) => Some(u.clone()),
            _ => None,
        })
    }

    fn top(&mut self) -> &mut Frame {
        self.frames.last_mut().expect("root frame")
    }

    fn push_block(&mut self, b: Block) {
        self.top().blocks.push(b);
    }

    /// Inline content outside a paragraph: a tight list item's text.
    fn ensure_inline(&mut self) {
        if self.inline.is_none() {
            let target = match &self.top().kind {
                FrameKind::Item { text: None, .. } => Target::ItemText,
                _ => Target::Paragraph,
            };
            self.inline = Some((target, vec![]));
        }
    }

    fn push_text(&mut self, text: &str, code: bool) {
        if let Some((_, alt)) = &mut self.image {
            alt.push_str(text);
            return;
        }
        for (_, label) in self.links.iter_mut() {
            label.push_str(text);
        }
        self.ensure_inline();
        let mut marks = self.marks();
        marks.code = code;
        let link = self.web_link();
        if let Some((_, pieces)) = &mut self.inline {
            pieces.push(Piece::Span(Span { text: text.to_string(), marks, link, mention: None }));
        }
    }

    fn flush_inline(&mut self) {
        let Some((target, pieces)) = self.inline.take() else { return };
        let only_image = {
            let mut it = pieces.iter().filter(|p| !matches!(p, Piece::Span(s) if s.text.trim().is_empty()));
            match (it.next(), it.next()) {
                (Some(Piece::Image { dest, alt }), None) => Some((dest.clone(), alt.clone())),
                _ => None,
            }
        };
        if let (Target::Paragraph, Some((dest, alt))) = (&target, &only_image) {
            if let Some(b) = embed(dest, alt) {
                self.push_block(b);
                return;
            }
        }
        let spans: Vec<Span> = pieces
            .into_iter()
            .map(|p| match p {
                Piece::Span(s) => s,
                Piece::Image { dest, alt } => Span::plain(if alt.is_empty() { dest.rsplit('/').next().unwrap_or(&dest).to_string() } else { alt }),
            })
            .collect();
        let spans = normalize(spans);
        match target {
            Target::Paragraph => {
                if !spans.is_empty() {
                    self.push_block(Block::Paragraph(spans));
                }
            }
            Target::Heading(n) if n <= 3 => self.push_block(Block::Heading(n, spans)),
            Target::Heading(_) => {
                let bold = spans.into_iter().map(|mut s| {
                    s.marks.bold = true;
                    s
                });
                self.push_block(Block::Paragraph(normalize(bold.collect())));
            }
            Target::ItemText => {
                if let FrameKind::Item { text, .. } = &mut self.top().kind {
                    *text = Some(spans);
                }
            }
        }
    }

    fn event(&mut self, ev: Event, range: std::ops::Range<usize>) {
        if self.skip > 0 {
            match ev {
                Event::Start(Tag::Table(_)) => self.skip += 1,
                Event::End(TagEnd::Table) => self.skip -= 1,
                _ => {}
            }
            return;
        }
        if let Some((_, text)) = &mut self.code {
            match ev {
                Event::Text(t) => text.push_str(&t),
                Event::End(TagEnd::CodeBlock) => {
                    let (lang, text) = self.code.take().unwrap();
                    let text = text.strip_suffix('\n').unwrap_or(&text).to_string();
                    self.push_block(Block::Code { lang, text });
                }
                _ => {}
            }
            return;
        }
        if let Some(h) = &mut self.html {
            match ev {
                Event::Html(t) | Event::Text(t) => h.push_str(&t),
                Event::End(TagEnd::HtmlBlock) => {
                    let h = self.html.take().unwrap();
                    let t = h.trim();
                    if t.starts_with("<!--") && t[4..].trim_start().starts_with("task:") && t.ends_with("-->") {
                        self.push_block(Block::TaskLine(t.to_string()));
                    } else if !t.is_empty() {
                        self.push_block(Block::Paragraph(vec![Span::plain(t)]));
                    }
                }
                _ => {}
            }
            return;
        }
        match ev {
            Event::Start(Tag::Paragraph) => {
                self.flush_inline();
                let target = match &self.top().kind {
                    FrameKind::Item { text: None, .. } => Target::ItemText,
                    _ => Target::Paragraph,
                };
                self.inline = Some((target, vec![]));
            }
            Event::End(TagEnd::Paragraph) => self.flush_inline(),
            Event::Start(Tag::Heading { level, .. }) => {
                self.flush_inline();
                let n = match level {
                    HeadingLevel::H1 => 1,
                    HeadingLevel::H2 => 2,
                    HeadingLevel::H3 => 3,
                    HeadingLevel::H4 => 4,
                    HeadingLevel::H5 => 5,
                    HeadingLevel::H6 => 6,
                };
                self.inline = Some((Target::Heading(n), vec![]));
            }
            Event::End(TagEnd::Heading(_)) => self.flush_inline(),
            Event::Start(Tag::BlockQuote(_)) => {
                self.flush_inline();
                self.frames.push(Frame { kind: FrameKind::Quote, blocks: vec![] });
            }
            Event::End(TagEnd::BlockQuote(_)) => {
                self.flush_inline();
                let f = self.frames.pop().unwrap();
                let mut spans = vec![];
                for b in f.blocks {
                    let s = block_spans(b);
                    if s.is_empty() {
                        continue;
                    }
                    if !spans.is_empty() {
                        spans.push(Span::plain("\n"));
                    }
                    spans.extend(s);
                }
                self.push_block(Block::Quote(normalize(spans)));
            }
            Event::Start(Tag::CodeBlock(kind)) => {
                self.flush_inline();
                let lang = match kind {
                    CodeBlockKind::Fenced(l) => notion_lang(l.split_whitespace().next().unwrap_or("")),
                    CodeBlockKind::Indented => String::new(),
                };
                self.code = Some((lang, String::new()));
            }
            Event::Start(Tag::HtmlBlock) => {
                self.flush_inline();
                self.html = Some(String::new());
            }
            Event::Start(Tag::List(start)) => {
                self.flush_inline();
                self.lists.push(start.is_some());
            }
            Event::End(TagEnd::List(_)) => {
                self.flush_inline();
                self.lists.pop();
            }
            Event::Start(Tag::Item) => {
                self.flush_inline();
                let kind = if self.lists.last().copied().unwrap_or(false) { ListKind::Number } else { ListKind::Bullet };
                self.frames.push(Frame { kind: FrameKind::Item { kind, text: None }, blocks: vec![] });
            }
            Event::TaskListMarker(done) => {
                if let FrameKind::Item { kind, .. } = &mut self.top().kind {
                    *kind = ListKind::ToDo(done);
                }
            }
            Event::End(TagEnd::Item) => {
                self.flush_inline();
                let f = self.frames.pop().unwrap();
                if let FrameKind::Item { kind, text } = f.kind {
                    self.push_block(Block::Item { kind, text: text.unwrap_or_default(), children: f.blocks });
                }
            }
            Event::Start(Tag::Table(_)) => {
                self.flush_inline();
                self.skip = 1;
                let raw = self.src[range].trim_end().to_string();
                self.push_block(Block::Paragraph(vec![Span::plain(raw)]));
            }
            Event::Rule => {
                self.flush_inline();
                self.push_block(Block::Divider);
            }
            Event::Start(Tag::Emphasis) => self.italic += 1,
            Event::End(TagEnd::Emphasis) => self.italic = self.italic.saturating_sub(1),
            Event::Start(Tag::Strong) => self.bold += 1,
            Event::End(TagEnd::Strong) => self.bold = self.bold.saturating_sub(1),
            Event::Start(Tag::Strikethrough) => self.strike += 1,
            Event::End(TagEnd::Strikethrough) => self.strike = self.strike.saturating_sub(1),
            Event::Start(Tag::Link { dest_url, .. }) => {
                let d = dest_url.to_string();
                let kind = if is_web(&d) {
                    LinkKind::Web(d)
                } else if d.starts_with(SCHEME) {
                    LinkKind::Attachment(d)
                } else {
                    LinkKind::Plain
                };
                self.links.push((kind, String::new()));
            }
            Event::End(TagEnd::Link) => {
                if let Some((LinkKind::Attachment(dest), label)) = self.links.pop() {
                    if !self.attach.iter().any(|(l, _)| *l == label) {
                        self.attach.push((label, dest));
                    }
                }
            }
            Event::Start(Tag::Image { dest_url, .. }) => {
                self.ensure_inline();
                self.image = Some((dest_url.to_string(), String::new()));
            }
            Event::End(TagEnd::Image) => {
                if let Some((dest, alt)) = self.image.take() {
                    if let Some((_, pieces)) = &mut self.inline {
                        pieces.push(Piece::Image { dest, alt });
                    }
                }
            }
            Event::Text(t) => self.push_text(&t, false),
            Event::Code(t) => self.push_text(&t, true),
            Event::InlineHtml(t) | Event::Html(t) | Event::InlineMath(t) | Event::DisplayMath(t) => self.push_text(&t, false),
            Event::FootnoteReference(t) => self.push_text(&format!("[^{t}]"), false),
            Event::SoftBreak => self.push_text(" ", false),
            Event::HardBreak => self.push_text("\n", false),
            Event::Start(_) | Event::End(_) => {}
        }
    }
}

/// An embed for an image on its own line, when Notion can show it.
fn embed(dest: &str, alt: &str) -> Option<Block> {
    if let Some(name) = dest.strip_prefix(SCHEME) {
        return Some(Block::Embed { image: is_image_name(name), dest: dest.to_string(), alt: alt.to_string() });
    }
    is_web(dest).then(|| Block::Embed { image: true, dest: dest.to_string(), alt: alt.to_string() })
}

fn block_spans(b: Block) -> Vec<Span> {
    match b {
        Block::Heading(_, s) | Block::Paragraph(s) | Block::Quote(s) => s,
        Block::Item { text, .. } => text,
        Block::Code { text, .. } => vec![Span::plain(text)],
        Block::TaskLine(t) => vec![Span::plain(t)],
        Block::Embed { alt, .. } => vec![Span::plain(alt)],
        Block::Other { text, .. } => vec![Span::plain(text)],
        Block::Divider => vec![],
    }
}

/// Markdown → blocks. Links to the task's own attachments are collected in
/// `attach` as (label, `attachment:<name>`).
pub fn from_markdown(md: &str, attach: &mut Vec<(String, String)>) -> Vec<Block> {
    let opts = Options::ENABLE_TASKLISTS | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TABLES;
    let mut b = Builder {
        src: md,
        frames: vec![Frame { kind: FrameKind::Root, blocks: vec![] }],
        lists: vec![],
        inline: None,
        bold: 0,
        italic: 0,
        strike: 0,
        links: vec![],
        image: None,
        code: None,
        html: None,
        skip: 0,
        attach,
    };
    for (ev, range) in Parser::new_ext(md, opts).into_offset_iter() {
        b.event(ev, range);
    }
    b.flush_inline();
    while b.frames.len() > 1 {
        let f = b.frames.pop().unwrap();
        b.top().blocks.extend(f.blocks);
    }
    b.frames.pop().unwrap().blocks
}

/// Merge neighbouring spans that look the same, and drop empty ones, so
/// that however Notion splits rich text, the same text compares equal.
pub fn normalize(spans: Vec<Span>) -> Vec<Span> {
    let mut out: Vec<Span> = vec![];
    for s in spans {
        if s.text.is_empty() && s.mention.is_none() {
            continue;
        }
        if let Some(last) = out.last_mut() {
            if last.mention.is_none() && s.mention.is_none() && last.marks == s.marks && last.link == s.link {
                last.text.push_str(&s.text);
                continue;
            }
        }
        out.push(s);
    }
    out
}

// ---- blocks → Markdown ----

/// What reading needs to know beyond the blocks.
pub struct ReadCtx<'a> {
    /// (label, dest) of the attachment links seen when rendering.
    pub attach: &'a [(String, String)],
    /// (dest, alt) of the file's embeds: Notion keeps no alt text, so an
    /// embed read back takes the file's.
    pub alts: &'a [(String, String)],
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '&' | '~' | '|' | '$') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// A line of paragraph text must not start a block of its own.
fn escape_line_start(line: &str) -> String {
    let l = line.trim_start();
    let first = l.chars().next();
    if matches!(first, Some('#' | '-' | '+' | '=' | '>')) {
        return format!("\\{l}");
    }
    let digits = l.chars().take_while(char::is_ascii_digit).count();
    if digits > 0 && matches!(l[digits..].chars().next(), Some('.' | ')')) {
        return format!("{}\\{}", &l[..digits], &l[digits..]);
    }
    l.to_string()
}

fn code_span(text: &str) -> String {
    let t = text.replace('\n', " ");
    let longest = t.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let fence = "`".repeat(longest + 1);
    if t.starts_with('`') || t.ends_with('`') || t.starts_with(' ') && t.ends_with(' ') && !t.trim().is_empty() {
        format!("{fence} {t} {fence}")
    } else {
        format!("{fence}{t}{fence}")
    }
}

fn link_dest(d: &str) -> String {
    if d.contains([' ', '(', ')', '<', '>']) {
        format!("<{}>", d.replace('<', "%3C").replace('>', "%3E"))
    } else {
        d.to_string()
    }
}

fn inline_md(spans: &[Span], ctx: &ReadCtx) -> String {
    let mut out = String::new();
    for s in spans {
        if s.text.is_empty() {
            continue;
        }
        if s.mention.is_some() {
            out.push_str(&escape(&s.text));
            continue;
        }
        // Whitespace at the edges goes outside the markers, or the
        // emphasis wouldn't parse.
        let lead = s.text.len() - s.text.trim_start().len();
        let trail = s.text.trim_end().len();
        let (pre, core, post) = if trail <= lead { (&s.text[..], "", "") } else { (&s.text[..lead], &s.text[lead..trail], &s.text[trail..]) };
        if core.is_empty() {
            out.push_str(pre);
            continue;
        }
        let mut t = if s.marks.code { code_span(core) } else { escape(core) };
        if s.marks.strike {
            t = format!("~~{t}~~");
        }
        if s.marks.italic {
            t = format!("*{t}*");
        }
        if s.marks.bold {
            t = format!("**{t}**");
        }
        if s.marks.underline {
            if let Some((_, dest)) = ctx.attach.iter().find(|(label, _)| label == core) {
                t = format!("[{t}]({})", link_dest(dest));
            }
        }
        if let Some(url) = &s.link {
            t = format!("[{t}]({})", link_dest(url));
        }
        out.push_str(pre);
        out.push_str(&t);
        out.push_str(post);
    }
    out
}

/// Paragraph-like text: lines from hard breaks joined with `\`, each line
/// made safe to start with.
fn text_md(spans: &[Span], ctx: &ReadCtx, indent: &str) -> String {
    let md = inline_md(spans, ctx);
    let lines: Vec<String> = md.split('\n').map(escape_line_start).collect();
    let mut lines: Vec<String> = lines.into_iter().map(|l| l.trim_end().to_string()).collect();
    while lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    lines.join(&format!("\\\n{indent}"))
}

fn one_line(spans: &[Span], ctx: &ReadCtx) -> String {
    let flat: Vec<Span> = spans
        .iter()
        .map(|s| Span { text: s.text.replace('\n', " "), ..s.clone() })
        .collect();
    inline_md(&flat, ctx).trim().to_string()
}

fn caption_alt(alt: &str) -> String {
    alt.replace(['[', ']', '\n'], " ").trim().to_string()
}

fn fence_for(text: &str) -> String {
    let longest = text
        .lines()
        .map(|l| l.trim_start().chars().take_while(|c| *c == '`').count())
        .max()
        .unwrap_or(0);
    "`".repeat(longest.max(2) + 1)
}

fn block_md(b: &Block, ctx: &ReadCtx, indent: &str, number: usize) -> String {
    match b {
        Block::Heading(n, s) => format!("{} {}", "#".repeat(*n as usize), one_line(s, ctx)),
        Block::Paragraph(s) => text_md(s, ctx, indent),
        Block::Quote(s) => {
            let md = inline_md(s, ctx);
            md.split('\n')
                .map(|l| {
                    let l = escape_line_start(l);
                    if l.is_empty() { ">".to_string() } else { format!("> {l}") }
                })
                .collect::<Vec<_>>()
                .join(&format!("\n{indent}"))
        }
        Block::Code { lang, text } => {
            let fence = fence_for(text);
            let body: Vec<String> = text.split('\n').map(|l| if l.is_empty() { String::new() } else { format!("{indent}{l}") }).collect();
            format!("{fence}{lang}\n{}\n{indent}{fence}", body.join("\n"))
        }
        Block::Divider => "---".into(),
        Block::Embed { dest, alt, .. } => {
            let alt = if alt.is_empty() { ctx.alts.iter().find(|(d, _)| d == dest).map_or("", |x| x.1.as_str()) } else { alt };
            format!("![{}]({})", caption_alt(alt), link_dest(dest))
        }
        Block::TaskLine(t) => t.clone(),
        Block::Other { text, .. } => text_md(&[Span::plain(text.clone())], ctx, indent),
        Block::Item { kind, text, children } => {
            let marker = match kind {
                ListKind::Bullet => "- ".to_string(),
                ListKind::Number => format!("{number}. "),
                ListKind::ToDo(done) => format!("- [{}] ", if *done { "x" } else { " " }),
            };
            let pad = match kind {
                ListKind::Number => " ".repeat(format!("{number}. ").len()),
                _ => "  ".to_string(),
            };
            let child_indent = format!("{indent}{pad}");
            let mut s = format!("{marker}{}", text_md(text, ctx, &child_indent));
            if !children.is_empty() {
                let inner = blocks_md(children, ctx, &child_indent);
                let sep = if matches!(children[0], Block::Item { .. }) { "\n" } else { "\n\n" };
                s.push_str(sep);
                s.push_str(&child_indent);
                s.push_str(&inner);
            }
            s
        }
    }
}

fn same_list(a: &Block, b: &Block) -> bool {
    match (a, b) {
        (Block::Item { kind: x, .. }, Block::Item { kind: y, .. }) => {
            matches!((x, y), (ListKind::Number, ListKind::Number))
                || (!matches!(x, ListKind::Number) && !matches!(y, ListKind::Number))
        }
        _ => false,
    }
}

fn blocks_md(blocks: &[Block], ctx: &ReadCtx, indent: &str) -> String {
    let mut out = String::new();
    let mut number = 0;
    for (i, b) in blocks.iter().enumerate() {
        let continues = i > 0 && same_list(&blocks[i - 1], b);
        number = if continues { number + 1 } else { 1 };
        if i > 0 {
            out.push_str(if continues { "\n" } else { "\n\n" });
            out.push_str(indent);
        }
        out.push_str(&block_md(b, ctx, indent, number));
    }
    out
}

/// Blocks → Markdown, ending in a newline (empty for no blocks).
pub fn to_markdown(blocks: &[Block], ctx: &ReadCtx) -> String {
    let s = blocks_md(blocks, ctx, "");
    if s.is_empty() {
        s
    } else {
        format!("{s}\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round(md: &str) -> String {
        let mut a = vec![];
        let blocks = from_markdown(md, &mut a);
        to_markdown(&blocks, &ReadCtx { attach: &a, alts: &[] })
    }

    /// The projection is stable: projecting twice changes nothing.
    fn stable(md: &str) {
        let once = round(md);
        let twice = round(&once);
        assert_eq!(once, twice, "not stable for {md:?}");
    }

    #[test]
    fn paragraphs_and_marks() {
        assert_eq!(round("Hello **bold** and *it* and `code` and ~~gone~~.\n"), "Hello **bold** and *it* and `code` and ~~gone~~.\n");
        assert_eq!(round("one\ntwo\n\nthree\n"), "one two\n\nthree\n");
        assert_eq!(round("a  \nb\n"), "a\\\nb\n");
        stable("Use a_b and 2 * 3 [not a link] <b>tag</b> & stuff | pipe\n");
        stable("# Title\n\n#### Deep\n\ntext\n");
    }

    #[test]
    fn headings_beyond_three_become_bold() {
        assert_eq!(round("#### Deep\n"), "**Deep**\n");
        assert_eq!(round("## 🚧 Task\n"), "## 🚧 Task\n");
    }

    #[test]
    fn task_line_kept_verbatim() {
        let md = "## 🚧 T\n<!-- task: id=1 tags=a,b assignee=maya.c -->\n\nBody.\n";
        assert_eq!(round(md), "## 🚧 T\n\n<!-- task: id=1 tags=a,b assignee=maya.c -->\n\nBody.\n");
        stable(md);
    }

    #[test]
    fn lists() {
        let md = "- a\n- b\n  - c\n\n1. one\n2. two\n\n- [x] done\n- [ ] todo\n";
        assert_eq!(round(md), "- a\n- b\n  - c\n\n1. one\n2. two\n\n- [x] done\n- [ ] todo\n");
        stable(md);
        stable("- item\n\n  more text\n- next\n");
        stable("1. a\n   1. b\n      - c\n");
    }

    #[test]
    fn quotes_code_rules() {
        stable("> quoted\n> more\n\n```rs\nfn main() {}\n```\n\n---\n\nafter\n");
        assert_eq!(round("```rs\nfn x() {}\n```\n"), "```rust\nfn x() {}\n```\n");
        assert_eq!(round("```weird\nx\n```\n"), "```\nx\n```\n");
    }

    #[test]
    fn links_and_attachments() {
        assert_eq!(round("See [docs](https://x.y/a) now.\n"), "See [docs](https://x.y/a) now.\n");
        assert_eq!(round("See [spec](attachment:spec.pdf).\n"), "See [spec](attachment:spec.pdf).\n");
        assert_eq!(round("See [readme](../README.md).\n"), "See readme.\n");
        assert_eq!(round("![Layout](attachment:layout.png)\n"), "![Layout](attachment:layout.png)\n");
        assert_eq!(round("Inline ![x](attachment:x.png) image\n"), "Inline x image\n");
        let mut a = vec![];
        let b = from_markdown("![Spec](attachment:spec.pdf)\n", &mut a);
        assert_eq!(b, vec![Block::Embed { image: false, dest: "attachment:spec.pdf".into(), alt: "Spec".into() }]);
    }

    #[test]
    fn line_starts_escaped() {
        let blocks = vec![Block::Paragraph(vec![Span::plain("# not a heading\n- not a list\n1. nor this")])];
        let md = to_markdown(&blocks, &ReadCtx { attach: &[], alts: &[] });
        assert_eq!(md, "\\# not a heading\\\n\\- not a list\\\n1\\. nor this\n");
        let mut a = vec![];
        assert_eq!(from_markdown(&md, &mut a), blocks);
    }

    #[test]
    fn tables_read_as_text() {
        stable("| a | b |\n|---|---|\n| 1 | 2 |\n");
    }
}
