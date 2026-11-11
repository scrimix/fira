//! Local file safety. People run the CLI with unsaved and uncommitted
//! edits in `tasks/`; none of them may be lost:
//!
//! - edits replace only the byte ranges an accepted change names;
//! - each file is re-read just before writing and skipped if it changed
//!   since it was parsed (e.g. saved in an editor while a prompt was open);
//! - a file with uncommitted changes is copied to
//!   `<git-dir>/task-cli/backups/<timestamp>/` first (inside `.git`, so it
//!   is never committed; works for submodules too);
//! - writes go to a temporary file that is renamed over the original;
//! - git is only ever read (`rev-parse`, `status`), never written.

use std::ops::Range;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

use crate::config::display_path;

#[derive(Debug, Clone)]
pub struct Edit {
    pub range: Range<usize>,
    pub text: String,
}

impl Edit {
    pub fn replace(range: Range<usize>, text: impl Into<String>) -> Edit {
        Edit { range, text: text.into() }
    }
    pub fn insert(at: usize, text: impl Into<String>) -> Edit {
        Edit { range: at..at, text: text.into() }
    }
}

/// Apply non-overlapping edits. Insertions at the same offset keep their
/// given order.
pub fn apply_edits(text: &str, edits: &[Edit]) -> Result<String> {
    let mut idx: Vec<usize> = (0..edits.len()).collect();
    idx.sort_by_key(|&i| (edits[i].range.start, edits[i].range.end, i));
    let mut out = String::with_capacity(text.len());
    let mut pos = 0;
    for i in idx {
        let e = &edits[i];
        if e.range.start < pos {
            bail!("internal error: overlapping edits at byte {}", e.range.start);
        }
        out.push_str(&text[pos..e.range.start]);
        out.push_str(&e.text);
        pos = e.range.end;
    }
    out.push_str(&text[pos..]);
    Ok(out)
}

pub fn hash(text: &str) -> [u8; 32] {
    Sha256::digest(text.as_bytes()).into()
}

pub fn atomic_write(path: &Path, text: &str) -> Result<()> {
    write_tmp_and_rename(path, text, None)
}

pub fn atomic_write_private(path: &Path, text: &str) -> Result<()> {
    write_tmp_and_rename(path, text, Some(0o600))
}

fn write_tmp_and_rename(path: &Path, text: &str, mode: Option<u32>) -> Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = dir.join(format!(".{name}.task-cli-{}.tmp", std::process::id()));
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            if let Some(m) = mode {
                opts.mode(m);
            }
        }
        let _ = mode;
        let mut f = opts.open(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
    }
    // Keep the original's permissions.
    if let Ok(meta) = std::fs::metadata(path) {
        if mode.is_none() {
            let _ = std::fs::set_permissions(&tmp, meta.permissions());
        }
    }
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })?;
    Ok(())
}

/// What happened to one planned file write.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Written,
    Skipped(String),
}

pub struct Writer {
    root: PathBuf,
    git_dir: Option<PathBuf>,
    backup_dir: Option<PathBuf>,
    stamp: String,
    pub backups: Vec<PathBuf>,
}

impl Writer {
    pub fn new(root: &Path) -> Writer {
        let git_dir = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["rev-parse", "--absolute-git-dir"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| PathBuf::from(String::from_utf8_lossy(&o.stdout).trim()));
        Writer {
            root: root.to_path_buf(),
            git_dir,
            backup_dir: None,
            stamp: chrono::Local::now().format("%Y%m%d-%H%M%S").to_string(),
            backups: vec![],
        }
    }

    fn is_dirty(&self, path: &Path) -> bool {
        if self.git_dir.is_none() {
            return false;
        }
        Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(["status", "--porcelain", "--"])
            .arg(path)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .is_some_and(|o| !o.stdout.is_empty())
    }

    fn backup(&mut self, path: &Path, content: &str) -> Result<()> {
        let Some(git_dir) = &self.git_dir else { return Ok(()) };
        let dir = self
            .backup_dir
            .get_or_insert_with(|| git_dir.join("task-cli").join("backups").join(&self.stamp))
            .clone();
        let rel = path.strip_prefix(&self.root).unwrap_or(path);
        let dest = dir.join(rel);
        std::fs::create_dir_all(dest.parent().unwrap())?;
        std::fs::write(&dest, content)?;
        self.backups.push(dest);
        Ok(())
    }

    /// Replace `path`, whose content when parsed was `original`.
    pub fn write(&mut self, path: &Path, original: &str, new: &str) -> Result<Outcome> {
        let current = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => return Ok(Outcome::Skipped(format!("cannot read it any more ({e})"))),
        };
        if hash(&current) != hash(original) {
            return Ok(Outcome::Skipped("it changed on disk after it was read (saved in an editor?)".into()));
        }
        if new == current {
            return Ok(Outcome::Written);
        }
        if self.is_dirty(path) {
            self.backup(path, &current)?;
        }
        atomic_write(path, new)?;
        Ok(Outcome::Written)
    }

    pub fn create(&mut self, path: &Path, text: &str) -> Result<Outcome> {
        if path.exists() {
            return Ok(Outcome::Skipped("a file with that name appeared in the meantime".into()));
        }
        std::fs::create_dir_all(path.parent().unwrap())?;
        atomic_write(path, text)?;
        Ok(Outcome::Written)
    }

    /// Remove a file whose last task moved elsewhere. Same checks as
    /// `write`; the content is always backed up first.
    pub fn remove(&mut self, path: &Path, original: &str) -> Result<Outcome> {
        let current = std::fs::read_to_string(path).unwrap_or_default();
        if hash(&current) != hash(original) {
            return Ok(Outcome::Skipped("it changed on disk after it was read".into()));
        }
        if self.git_dir.is_some() {
            self.backup(path, &current)?;
        }
        std::fs::remove_file(path)?;
        Ok(Outcome::Written)
    }

    pub fn report_backups(&self) {
        if let Some(d) = &self.backup_dir {
            eprintln!("Backed up files with uncommitted changes to {}", display_path(d));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edits_apply_in_order() {
        let t = "abcdef";
        let out = apply_edits(t, &[Edit::replace(4..5, "E"), Edit::insert(0, "<"), Edit::insert(0, "!"), Edit::replace(1..2, "")]).unwrap();
        assert_eq!(out, "<!acdEf");
        assert!(apply_edits(t, &[Edit::replace(0..3, ""), Edit::replace(2..4, "")]).is_err());
    }

    #[test]
    fn writer_skips_files_changed_since_read() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.md");
        std::fs::write(&p, "one").unwrap();
        let mut w = Writer::new(dir.path());
        std::fs::write(&p, "edited in editor").unwrap();
        assert!(matches!(w.write(&p, "one", "two").unwrap(), Outcome::Skipped(_)));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "edited in editor");
        assert_eq!(w.write(&p, "edited in editor", "two").unwrap(), Outcome::Written);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "two");
    }
}
