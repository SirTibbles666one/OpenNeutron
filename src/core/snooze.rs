//! Snooze: a message that leaves the inbox until a time you choose.
//!
//! A snooze is a timestamp, not a timer. The list endpoints already leave out trashed mail;
//! they leave out a message whose snooze is still in the future the same way, so waking up
//! needs nothing to run and cannot silently stop working — the moment the clock passes the
//! time, the message is simply in the list again.
//!
//! A sidecar for the usual reason: `User` is bincode, `Email` has no field for it, and neither
//! may gain one without making stored data unreadable.
//!
//! `data/snooze.json`:
//! ```json
//! { "users": { "alice": { "<uid>": { "uid": ..., "until": 1793... } } } }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const STORE_PATH: &str = "data/snooze.json";
/// Nothing longer than a year: a snooze that far out is a delete pretending otherwise.
pub const MAX_SECONDS: u64 = 365 * 24 * 60 * 60;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Item {
    pub uid: u128,
    pub until: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct Store {
    #[serde(default)]
    users: BTreeMap<String, BTreeMap<String, Item>>,
}

static LOCK: Mutex<()> = Mutex::new(());

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn path() -> PathBuf {
    PathBuf::from(std::env::var("SNOOZE_PATH").unwrap_or_else(|_| STORE_PATH.to_string()))
}

fn load() -> Store {
    match fs::read_to_string(path()) {
        Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
        Err(_) => Store::default(),
    }
}

fn save(store: &Store) -> io::Result<()> {
    let path = path();
    if let Some(dir) = Path::new(&path).parent() {
        fs::create_dir_all(dir)?;
    }
    let body = serde_json::to_string_pretty(store)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, body)?;
    fs::rename(&tmp, &path)
}

/// The messages that are away right now. `at` is passed in so a page can be reasoned about.
pub fn snoozed_uids(user: &str, at: u64) -> Vec<u128> {
    load()
        .users
        .get(user)
        .map(|items| {
            items
                .values()
                .filter(|item| item.until > at)
                .map(|item| item.uid)
                .collect()
        })
        .unwrap_or_default()
}

/// Everything the account has away, soonest first — what the Snoozed folder shows.
pub fn list(user: &str) -> Vec<Item> {
    let mut items: Vec<Item> = load()
        .users
        .get(user)
        .map(|entries| entries.values().cloned().collect())
        .unwrap_or_default();
    items.sort_by_key(|item| item.until);
    items
}

pub fn set(user: &str, uid: u128, until: u64) -> io::Result<()> {
    let _guard = LOCK.lock().ok();
    let mut store = load();
    store
        .users
        .entry(user.to_string())
        .or_default()
        .insert(uid.to_string(), Item { uid, until });
    save(&store)
}

pub fn clear(user: &str, uid: u128) -> io::Result<bool> {
    let _guard = LOCK.lock().ok();
    let mut store = load();
    let removed = store
        .users
        .get_mut(user)
        .map(|entries| entries.remove(&uid.to_string()).is_some())
        .unwrap_or(false);
    if removed {
        save(&store)?;
    }
    Ok(removed)
}

/// Drop entries whose time has passed, so the file does not grow with history.
pub fn sweep(user: &str, at: u64) -> io::Result<usize> {
    let _guard = LOCK.lock().ok();
    let mut store = load();
    let Some(entries) = store.users.get_mut(user) else { return Ok(0) };
    let before = entries.len();
    entries.retain(|_, item| item.until > at);
    let removed = before - entries.len();
    if removed > 0 {
        save(&store)?;
    }
    Ok(removed)
}

/// An account that is going away takes its snoozes with it.
pub fn purge(user: &str) -> usize {
    let _guard = LOCK.lock().ok();
    let mut store = load();
    let removed = store.users.remove(user).map(|items| items.len()).unwrap_or(0);
    if removed > 0 {
        let _ = save(&store);
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_snooze_in_the_future_is_away_and_a_past_one_is_not() {
        let path = std::env::temp_dir().join(format!("snooze-{}-{}.json", std::process::id(), now()));
        // Unsafe in edition 2024 for the usual reason: the environment is
        // process-global. This is the module's only test.
        unsafe { std::env::set_var("SNOOZE_PATH", &path) };
        let t = now();
        set("alice", 7, t + 60).unwrap();
        set("alice", 9, t - 60).unwrap();
        let away = snoozed_uids("alice", t);
        assert!(away.contains(&7));
        assert!(!away.contains(&9));
        assert_eq!(sweep("alice", t).unwrap(), 1);
        assert_eq!(snoozed_uids("alice", t), vec![7]);
        let _ = fs::remove_file(path);
    }
}
