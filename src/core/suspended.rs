//! Accounts an operator has switched off, and why.
//!
//! `users.bin` is bincode and positional: adding a field to `User` makes every
//! existing record unreadable, so this is a sidecar like `pending_users.json`,
//! keyed by lowercase username. Absence of an entry means the account is live.
//!
//! Suspension is not deletion. The mailbox, its key and every message stay
//! where they are, so lifting the suspension returns the account exactly as it
//! was; nothing has to be rebuilt from a backup. While suspended:
//!
//! - sign-in is refused after the password check (so the refusal cannot be used
//!   to learn which names exist),
//! - SMTP refuses the address at RCPT time with a 5.2.1, so the sender is told
//!   and nothing is accepted and then dropped.
//!
//! Written beside the target and renamed, because a half-written file here
//! would either free every suspended account or trap every live one.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const STORE_PATH: &str = "data/suspended.json";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Suspended {
    pub username: String,
    pub since: u64,
    /// Which administrator did it, as the audit line the panel shows.
    #[serde(default)]
    pub by: String,
    #[serde(default)]
    pub reason: String,
    /// Unix time the suspension lifts by itself. `None` means until someone lifts it.
    #[serde(default)]
    pub until: Option<u64>,
}

#[derive(Default, Serialize, Deserialize)]
struct Store {
    #[serde(default)]
    entries: BTreeMap<String, Suspended>,
}

static LOCK: Mutex<()> = Mutex::new(());

fn key(username: &str) -> String {
    username.trim().to_lowercase()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn path() -> PathBuf {
    PathBuf::from(STORE_PATH)
}

/// A missing or damaged file means "nobody is suspended". That fails open on
/// purpose: a mail server that locked every account because one file would not
/// parse would be a worse outage than the abuse the suspension was for.
fn read_at(path: &Path) -> Store {
    fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn write_at(path: &Path, store: &Store) -> io::Result<()> {
    let text = serde_json::to_string_pretty(store).map_err(io::Error::other)?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    fs::write(&tmp, text)?;
    fs::rename(&tmp, path)
}

/// The suspension record, when this account is switched off.
pub fn entry(username: &str) -> Option<Suspended> {
    read_at(&path()).entries.get(&key(username)).cloned()
}

/// Is this account switched off? Called on every login and every delivery.
pub fn is_suspended(username: &str) -> bool {
    active(username).is_some()
}

/// The live suspension for this account, if there is one. A suspension that has reached its
/// end date is removed here rather than left to a sweeper: the account must be usable the
/// moment it expires, not when a timer next runs.
pub fn active(username: &str) -> Option<Suspended> {
    let path = path();
    let key_name = key(username);
    let entry = read_at(&path).entries.get(&key_name).cloned()?;

    if let Some(until) = entry.until {
        if until <= now() {
            // Take it out. A failure here is not fatal: the account is still treated as
            // live below, and the next login or sweep will try again.
            let _held = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut store = read_at(&path);
            store.entries.remove(&key_name);
            let _ = write_at(&path, &store);
            log::info!("[Suspended] '{}' reached its end date and was lifted", key_name);
            return None;
        }
    }
    Some(entry)
}

/// Switch an account off, or back on. Returns the state afterwards.
///
/// Re-suspending an already suspended account keeps the original `since` and
/// the original operator, and only refreshes the reason: a repeat click must
/// not make it look like the account was freshly caught.
pub fn set(username: &str, suspend: bool, by: &str, reason: &str) -> io::Result<bool> {
    set_until(username, suspend, by, reason, None)
}

/// As `set`, with an end date. `until` is unix seconds; `None` means no end.
pub fn set_until(
    username: &str,
    suspend: bool,
    by: &str,
    reason: &str,
    until: Option<u64>,
) -> io::Result<bool> {
    let _held = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let path = path();
    let mut store = read_at(&path);
    let key = key(username);

    if suspend {
        store
            .entries
            .entry(key.clone())
            .and_modify(|existing| {
                if !reason.trim().is_empty() {
                    existing.reason = reason.trim().chars().take(200).collect();
                }
                existing.by = by.to_string();
                existing.until = until;
            })
            .or_insert_with(|| Suspended {
                username: key,
                since: now(),
                by: by.to_string(),
                reason: reason.trim().chars().take(200).collect(),
                until,
            });
    } else if store.entries.remove(&key).is_none() {
        // Nothing to lift; do not rewrite the file for a no-op.
        return Ok(false);
    }

    write_at(&path, &store)?;
    Ok(suspend)
}

pub fn list() -> Vec<Suspended> {
    let mut entries: Vec<Suspended> = read_at(&path()).entries.into_values().collect();
    entries.sort_by_key(|e| e.since);
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("suspended-test-{}-{}.json", name, std::process::id()))
    }

    #[test]
    fn a_missing_store_means_nobody_is_suspended() {
        let p = temp_path("missing");
        let _ = fs::remove_file(&p);
        assert!(read_at(&p).entries.is_empty());
    }

    #[test]
    fn a_damaged_store_does_not_lock_everyone_out() {
        let p = temp_path("damaged");
        fs::write(&p, b"{ this is not json").unwrap();
        assert!(read_at(&p).entries.is_empty());
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn suspension_round_trips_and_lifts() {
        let p = temp_path("roundtrip");
        let _ = fs::remove_file(&p);
        {
            // Recover rather than panic: one panic while this lock was held would poison it,
            // and every later call would panic too — turning a single bug into an endpoint
            // that is broken until the process restarts. The other nine locks here already
            // recover this way.
            let _held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
            let mut store = Store::default();
            store.entries.insert(
                "tibs".into(),
                Suspended {
                    username: "tibs".into(),
                    since: 1,
                    by: "ops".into(),
                    reason: "probe".into(),
                    until: None,
                },
            );
            write_at(&p, &store).unwrap();
        }
        let store = read_at(&p);
        assert_eq!(store.entries.len(), 1);
        assert_eq!(store.entries["tibs"].reason, "probe");
        let _ = fs::remove_file(&p);
    }
}
