//! Subject rules: file a message into a folder because of what its subject says.
//!
//! Sender rules already live on `Group.filter_addresses`. Subjects cannot: `Group` is part
//! of `User`, which is stored as bincode, so a new field there would make `users.bin`
//! unreadable for every account. This is a sidecar for the same reason `trash` and `junk`
//! are — see `core::junk` for the shape.
//!
//! **These rules match on delivery only.** The alternative — re-filing what is already in
//! the mailbox — is impossible here: mail is stored encrypted and the server cannot read a
//! subject it did not just receive. A rule starts working from the moment it is saved, and
//! the client says so rather than pretending old mail moved.
//!
//! `data/group_subjects.json`:
//! ```json
//! { "users": { "alice": { "<group uid>": ["stack check failed", "invoice"] } } }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const STORE_PATH: &str = "data/group_subjects.json";

#[derive(Default, Serialize, Deserialize)]
struct Store {
    #[serde(default)]
    users: BTreeMap<String, BTreeMap<String, Vec<String>>>,
}

static LOCK: Mutex<()> = Mutex::new(());

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

/// Lower-case, strip reply/forward prefixes, collapse whitespace — the same idea as the
/// client's `normalizeSubject`, so a rule written for "Invoice" also matches "Re: Invoice".
pub fn normalize(subject: &str) -> String {
    let mut value = subject.trim().to_lowercase();
    loop {
        // Own the candidate before rewriting, so the borrow ends with the match.
        let current = value.trim().to_string();
        let mut stripped: Option<String> = None;

        for prefix in ["re:", "fw:", "fwd:", "aw:", "sv:", "vs:"] {
            if let Some(rest) = current.strip_prefix(prefix) {
                stripped = Some(rest.trim_start().to_string());
                break;
            }
        }
        // "re[2]:" and similar numbered variants
        if stripped.is_none() {
            if let Some(rest) = current.strip_prefix("re[") {
                if let Some(close) = rest.find("]:") {
                    stripped = Some(rest[close + 2..].trim_start().to_string());
                }
            }
        }

        match stripped {
            Some(next) if !next.is_empty() => value = next,
            _ => return current.split_whitespace().collect::<Vec<_>>().join(" "),
        }
    }
}

pub fn set_at(path: &Path, username: &str, group: u128, rules: Vec<String>) -> io::Result<()> {
    let _guard = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut store = read_at(path);
    let cleaned: Vec<String> = rules
        .into_iter()
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty())
        .collect();
    let entry = store.users.entry(username.to_string()).or_default();
    if cleaned.is_empty() {
        entry.remove(&group.to_string());
    } else {
        entry.insert(group.to_string(), cleaned);
    }
    write_at(path, &store)
}

pub fn get_at(path: &Path, username: &str, group: u128) -> Vec<String> {
    read_at(path)
        .users
        .get(username)
        .and_then(|m| m.get(&group.to_string()))
        .cloned()
        .unwrap_or_default()
}

pub fn all_at(path: &Path, username: &str) -> BTreeMap<u128, Vec<String>> {
    read_at(path)
        .users
        .get(username)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| k.parse::<u128>().ok().map(|uid| (uid, v.clone())))
                .collect()
        })
        .unwrap_or_default()
}

pub fn set(username: &str, group: u128, rules: Vec<String>) -> io::Result<()> {
    set_at(&path(), username, group, rules)
}

pub fn get(username: &str, group: u128) -> Vec<String> {
    get_at(&path(), username, group)
}

pub fn all(username: &str) -> BTreeMap<u128, Vec<String>> {
    all_at(&path(), username)
}

/// Does this subject fire that rule list? An empty rule list never fires.
pub fn matches(subject: &str, rules: &[String]) -> bool {
    if rules.is_empty() {
        return false;
    }
    let haystack = normalize(subject);
    rules.iter().any(|rule| {
        let needle = normalize(rule);
        !needle.is_empty() && haystack.contains(&needle)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "subjects-{name}-{}.json",
            std::process::id()
        ))
    }

    #[test]
    fn a_rule_matches_through_reply_prefixes_and_case() {
        let rules = vec!["Stack Check Failed".to_string()];
        assert!(matches("Stack check failed", &rules));
        assert!(matches("Re: stack check failed", &rules));
        assert!(matches("RE: Re: STACK CHECK FAILED", &rules));
        assert!(matches("Fwd: stack check failed", &rules));
        // "[3]" is a numbering prefix our own thread rows use; the rule still matches
        // because the match is on the phrase, not on the whole subject.
        assert!(matches("[3] stack check failed", &rules));
        assert!(!matches("All good", &rules));
    }

    #[test]
    fn a_numbered_reply_prefix_is_stripped() {
        assert_eq!(normalize("Re[2]: Invoice"), "invoice");
    }

    #[test]
    fn an_empty_rule_list_never_fires() {
        assert!(!matches("anything", &[]));
    }

    #[test]
    fn rules_round_trip_per_account_and_group() {
        let path = tmp("roundtrip");
        set_at(&path, "alice", 7, vec![" invoice ".into(), "".into()]).unwrap();
        assert_eq!(get_at(&path, "alice", 7), vec!["invoice".to_string()]);
        assert!(get_at(&path, "bob", 7).is_empty());
        // clearing removes the entry rather than storing an empty list
        set_at(&path, "alice", 7, vec![]).unwrap();
        assert!(get_at(&path, "alice", 7).is_empty());
        assert!(all_at(&path, "alice").is_empty());
        let _ = fs::remove_file(&path);
    }
}
