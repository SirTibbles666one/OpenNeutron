//! Audit log: what an admin did, when, and to whom.
//!
//! An admin panel without this is a panel you cannot give to a second person: suspending,
//! deleting and re-keying accounts all leave no trace, so "who removed that account" has no
//! answer. The panel has fifteen endpoints that change things and, until now, no record of
//! any of them being used.
//!
//! **Records are hash-chained.** `hash = sha256(prev | at | actor | action | target | detail)`
//! and each record carries the previous record's hash. The file is append-only and written by
//! the server, so the risk this addresses is not a typo — it is someone with shell access
//! deleting a row to hide what they did. Any deletion or edit breaks every later link, and
//! `verify` names the first record that does not match. It cannot stop a full rewrite; it can
//! make one visible, which is the difference between an audit log and a decoration.
//!
//! What is deliberately **not** recorded: message content, subjects, senders, ordinary users'
//! IP addresses, failed logins, or any secret. A record saying "password changed" is the
//! point; a record saying what it changed to would be a catastrophe. This log must never
//! become a shadow copy of a mailbox.
//!
//! `data/audit.json`:
//! ```json
//! { "records": [ { "at":…, "actor":"tibs", "action":"user.suspend", "target":"x",
//!                  "detail":"reason: abuse", "prev":"…", "hash":"…" } ] }
//! ```

use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const STORE_PATH: &str = "data/audit.json";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub at: u64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: String,
    /// Hash of the record before this one; empty for the first.
    pub prev: String,
    pub hash: String,
}

#[derive(Default, Serialize, Deserialize)]
struct Store {
    #[serde(default)]
    records: Vec<Record>,
}

static LOCK: Mutex<()> = Mutex::new(());

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn path() -> PathBuf {
    PathBuf::from(STORE_PATH)
}

fn read_at(path: &Path) -> Store {
    fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn write_at(path: &Path, store: &Store) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(store)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, &bytes)?;
    fs::rename(&tmp, path)
}

/// The chain link. Field order is part of the format: changing it invalidates every existing
/// record, so it is written once and left alone.
fn digest(prev: &str, at: u64, actor: &str, action: &str, target: &str, detail: &str) -> String {
    let material = format!("{prev}|{at}|{actor}|{action}|{target}|{detail}");
    sha256::digest(material.as_bytes())
}

pub fn append_at(
    path: &Path,
    at: u64,
    actor: &str,
    action: &str,
    target: &str,
    detail: &str,
) -> io::Result<()> {
    let _guard = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut store = read_at(path);
    let prev = store.records.last().map(|r| r.hash.clone()).unwrap_or_default();
    let hash = digest(&prev, at, actor, action, target, detail);
    store.records.push(Record {
        at,
        actor: actor.to_string(),
        action: action.to_string(),
        target: target.to_string(),
        detail: detail.to_string(),
        prev,
        hash,
    });
    write_at(path, &store)
}

pub fn append(actor: &str, action: &str, target: &str, detail: &str) -> io::Result<()> {
    append_at(&path(), now(), actor, action, target, detail)
}

/// Newest first, optionally filtered to one target. The panel reads this, so it is paged
/// like the mail list rather than returning a file that grows forever.
pub fn page_at(
    path: &Path,
    offset: usize,
    limit: usize,
    target: Option<&str>,
) -> (Vec<Record>, usize) {
    let store = read_at(path);
    let filtered: Vec<Record> = store
        .records
        .into_iter()
        .rev()
        .filter(|r| target.map(|t| r.target == t).unwrap_or(true))
        .collect();
    let total = filtered.len();
    (filtered.into_iter().skip(offset).take(limit).collect(), total)
}

pub fn page(offset: usize, limit: usize, target: Option<&str>) -> (Vec<Record>, usize) {
    page_at(&path(), offset, limit, target)
}

/// `Ok(count)` when the chain is intact, `Err((index, why))` naming the first record that is
/// not what the chain says it should be.
pub fn verify_at(path: &Path) -> Result<usize, (usize, String)> {
    let store = read_at(path);
    let mut prev = String::new();
    for (i, record) in store.records.iter().enumerate() {
        if record.prev != prev {
            return Err((
                i,
                format!("record {i} does not follow record {} (prev hash mismatch)", i.saturating_sub(1)),
            ));
        }
        let expected = digest(&record.prev, record.at, &record.actor, &record.action, &record.target, &record.detail);
        if record.hash != expected {
            return Err((i, format!("record {i} was edited after it was written")));
        }
        prev = record.hash.clone();
    }
    Ok(store.records.len())
}

pub fn verify() -> Result<usize, (usize, String)> {
    verify_at(&path())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("audit-{name}-{}.json", std::process::id()))
    }

    #[test]
    fn records_chain_and_verify() {
        let path = tmp("chain");
        append_at(&path, 100, "tibs", "user.suspend", "bob", "reason: abuse").unwrap();
        append_at(&path, 101, "tibs", "user.admin.grant", "bob", "").unwrap();
        assert_eq!(verify_at(&path), Ok(2));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn deleting_a_record_breaks_the_chain_and_is_named() {
        let path = tmp("delete");
        for i in 0..3 {
            append_at(&path, 100 + i, "tibs", "user.suspend", "bob", "").unwrap();
        }
        // Someone with shell access removes the middle action.
        let mut store = read_at(&path);
        store.records.remove(1);
        write_at(&path, &store).unwrap();

        match verify_at(&path) {
            Err((index, why)) => {
                assert_eq!(index, 1);
                assert!(why.contains("prev hash mismatch"), "got: {why}");
            }
            Ok(n) => panic!("a deleted record verified as intact with {n} records"),
        }
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn editing_a_record_is_detected() {
        let path = tmp("edit");
        append_at(&path, 100, "tibs", "user.delete", "bob", "").unwrap();
        let mut store = read_at(&path);
        store.records[0].detail = "nothing to see here".into();
        write_at(&path, &store).unwrap();
        match verify_at(&path) {
            Err((0, why)) => assert!(why.contains("edited"), "got: {why}"),
            other => panic!("edited record not detected: {other:?}"),
        }
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn paging_is_newest_first_and_filterable() {
        let path = tmp("page");
        append_at(&path, 1, "tibs", "user.suspend", "bob", "").unwrap();
        append_at(&path, 2, "tibs", "user.suspend", "carol", "").unwrap();
        append_at(&path, 3, "tibs", "user.delete", "bob", "").unwrap();

        let (all, total) = page_at(&path, 0, 10, None);
        assert_eq!(total, 3);
        assert_eq!(all[0].action, "user.delete");

        let (bob, bob_total) = page_at(&path, 0, 10, Some("bob"));
        assert_eq!(bob_total, 2);
        assert!(bob.iter().all(|r| r.target == "bob"));

        let (second, _) = page_at(&path, 1, 1, None);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].action, "user.suspend");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn an_unreadable_store_reads_as_empty_and_appends_repair_it() {
        let path = tmp("corrupt");
        fs::write(&path, b"{ not json").unwrap();
        assert_eq!(verify_at(&path), Ok(0));
        append_at(&path, 1, "tibs", "audit.read", "", "").unwrap();
        assert_eq!(verify_at(&path), Ok(1));
        let _ = fs::remove_file(&path);
    }
}
