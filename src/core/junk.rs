//! Junk: mail the filter or its owner says is spam, kept out of the Inbox.
//!
//! rspamd has been scoring every message for a while, but nothing acted on the score, so
//! a message it called obvious spam still arrived in the Inbox with a header nobody reads.
//! A report now does two things: it teaches the filter (see `api::endpoints::spam`) and it
//! moves the message here — out of the live list, still readable in the Junk view.
//!
//! This follows `trash` exactly, for the same two reasons: the message stays in the owner's
//! received list so every existing read path keeps working, and the record is a sidecar
//! because `User` is bincode and a new field would make `users.bin` unreadable.
//!
//! `data/junk.json`:
//! ```json
//! { "users": { "alice": { "<uid>": { "uid": ..., "junked_at": 1793... } } } }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const STORE_PATH: &str = "data/junk.json";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Item {
    pub uid: u128,
    pub junked_at: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct Store {
    #[serde(default)]
    users: BTreeMap<String, BTreeMap<String, Item>>,
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
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn write_at(path: &Path, store: &Store) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(store)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    // Write beside and rename, so a crash mid-write cannot truncate the record and
    // silently un-junk every message the account had.
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, &bytes)?;
    fs::rename(&tmp, path)
}

pub fn add_at(path: &Path, username: &str, uid: u128, at: u64) -> io::Result<()> {
    let _guard = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut store = read_at(path);
    store
        .users
        .entry(username.to_string())
        .or_default()
        .insert(uid.to_string(), Item { uid, junked_at: at });
    write_at(path, &store)
}

pub fn remove_at(path: &Path, username: &str, uid: u128) -> io::Result<bool> {
    let _guard = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut store = read_at(path);
    let removed = store
        .users
        .get_mut(username)
        .and_then(|map| map.remove(&uid.to_string()))
        .is_some();
    if removed {
        write_at(path, &store)?;
    }
    Ok(removed)
}

pub fn list_at(path: &Path, username: &str) -> Vec<Item> {
    read_at(path)
        .users
        .get(username)
        .map(|map| map.values().cloned().collect())
        .unwrap_or_default()
}

pub fn add(username: &str, uid: u128) -> io::Result<()> {
    add_at(&path(), username, uid, now())
}

pub fn remove(username: &str, uid: u128) -> io::Result<bool> {
    remove_at(&path(), username, uid)
}

pub fn list(username: &str) -> Vec<Item> {
    list_at(&path(), username)
}

pub fn junked_uids(username: &str) -> HashSet<u128> {
    list(username).into_iter().map(|item| item.uid).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("junk-test-{name}-{}.json", now()))
    }

    #[test]
    fn marks_and_lists_per_account() {
        let path = tmp("marks");
        add_at(&path, "alice", 10, 100).unwrap();
        add_at(&path, "alice", 20, 200).unwrap();
        add_at(&path, "bob", 30, 300).unwrap();

        let alice: HashSet<u128> = list_at(&path, "alice").into_iter().map(|i| i.uid).collect();
        assert_eq!(alice, HashSet::from([10, 20]));
        // One account marking a message cannot hide another account's mail.
        let bob: HashSet<u128> = list_at(&path, "bob").into_iter().map(|i| i.uid).collect();
        assert_eq!(bob, HashSet::from([30]));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn removing_is_the_only_way_a_message_returns() {
        let path = tmp("remove");
        add_at(&path, "alice", 10, 100).unwrap();
        assert!(remove_at(&path, "alice", 10).unwrap());
        assert!(list_at(&path, "alice").is_empty());
        // Removing something that was never there is not an error, and must not write.
        assert!(!remove_at(&path, "alice", 99).unwrap());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn an_unreadable_store_reads_as_empty_rather_than_panicking() {
        let path = tmp("corrupt");
        fs::write(&path, b"{ this is not json").unwrap();
        assert!(list_at(&path, "alice").is_empty());
        // And a later write repairs it rather than propagating the damage.
        add_at(&path, "alice", 7, 1).unwrap();
        assert_eq!(list_at(&path, "alice").len(), 1);
        let _ = fs::remove_file(&path);
    }
}
