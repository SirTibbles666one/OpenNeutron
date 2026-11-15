//! Named sets of addresses: the mailboxes you switch the inbox to.
//!
//! `users.bin` is bincode and positional and `Email` has no mailbox field, so the
//! definition lives in a sidecar and a message's mailbox is decided by the address it
//! arrived at — which delivery already records (`core::arrival`). Nothing about a
//! message has to change for it to move between mailboxes: the mapping does.
//!
//! An address belongs to one mailbox at a time. A mailbox with no addresses is
//! allowed while it is being built, and simply matches nothing.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

pub const STORE_PATH: &str = "data/mailboxes.json";
pub const MAX_MAILBOXES: usize = 8;
pub const MAX_NAME: usize = 32;
pub const MAX_ADDRESSES: usize = 16;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Mailbox {
    pub name: String,
    #[serde(default)]
    pub addresses: Vec<String>,
    pub created: u64,
}

#[derive(Serialize, Deserialize, Default)]
struct Store {
    #[serde(default)]
    accounts: BTreeMap<String, Vec<Mailbox>>,
}

#[derive(Debug, PartialEq)]
pub enum SetError {
    EmptyName,
    NameTooLong,
    TooMany,
    TooManyAddresses,
    NoSuchMailbox,
    AddressInAnother(String),
    Io(String),
}

#[derive(Debug, PartialEq)]
pub enum RemoveError {
    NotFound,
    Io(String),
}

fn lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn store_path() -> String {
    std::env::var("MAILBOXES_PATH").unwrap_or_else(|_| STORE_PATH.to_string())
}

fn load() -> Store {
    match fs::read_to_string(store_path()) {
        Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
        Err(_) => Store::default(),
    }
}

fn save(store: &Store) -> io::Result<()> {
    let path = store_path();
    if let Some(dir) = Path::new(&path).parent() {
        if !dir.as_os_str().is_empty() {
            fs::create_dir_all(dir)?;
        }
    }
    let body = serde_json::to_string_pretty(store)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    // Write beside the file and rename: a crash mid-write must not leave a mailbox
    // file that parses as "no mailboxes at all".
    let tmp = format!("{path}.tmp");
    fs::write(&tmp, body)?;
    fs::rename(&tmp, &path)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn norm(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

pub fn list(account: &str) -> Vec<Mailbox> {
    load()
        .accounts
        .get(&norm(account))
        .cloned()
        .unwrap_or_default()
}

/// Create or replace a mailbox. `addresses` is taken as the complete set.
pub fn set(account: &str, name: &str, addresses: &[String]) -> Result<Mailbox, SetError> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err(SetError::EmptyName);
    }
    if name.chars().count() > MAX_NAME {
        return Err(SetError::NameTooLong);
    }
    let mut wanted: Vec<String> = Vec::new();
    for address in addresses {
        let address = norm(address);
        if address.is_empty() || wanted.contains(&address) {
            continue;
        }
        wanted.push(address);
    }
    if wanted.len() > MAX_ADDRESSES {
        return Err(SetError::TooManyAddresses);
    }

    let _guard = lock().lock().ok();
    let mut store = load();
    let account_key = norm(account);
    let entries = store.accounts.entry(account_key).or_default();

    // An address belongs to one mailbox: taking it from another is a move, not a duplicate.
    for other in entries.iter() {
        if other.name.eq_ignore_ascii_case(&name) {
            continue;
        }
        if let Some(clash) = wanted.iter().find(|a| other.addresses.contains(a)) {
            return Err(SetError::AddressInAnother(clash.clone()));
        }
    }

    let mailbox = Mailbox { name: name.clone(), addresses: wanted, created: now() };
    match entries.iter_mut().find(|m| m.name.eq_ignore_ascii_case(&name)) {
        Some(existing) => {
            existing.addresses = mailbox.addresses.clone();
            existing.name = mailbox.name.clone();
        }
        None => {
            if entries.len() >= MAX_MAILBOXES {
                return Err(SetError::TooMany);
            }
            entries.push(mailbox.clone());
        }
    }

    save(&store).map_err(|e| SetError::Io(e.to_string()))?;
    Ok(mailbox)
}

pub fn remove(account: &str, name: &str) -> Result<(), RemoveError> {
    let _guard = lock().lock().ok();
    let mut store = load();
    let account_key = norm(account);
    let Some(entries) = store.accounts.get_mut(&account_key) else {
        return Err(RemoveError::NotFound);
    };
    let before = entries.len();
    entries.retain(|m| !m.name.eq_ignore_ascii_case(name));
    if entries.len() == before {
        return Err(RemoveError::NotFound);
    }
    save(&store).map_err(|e| RemoveError::Io(e.to_string()))
}

/// Drop everything an account defined. Called when the account itself goes.
pub fn purge(account: &str) -> usize {
    let _guard = lock().lock().ok();
    let mut store = load();
    let removed = store.accounts.remove(&norm(account)).map(|m| m.len()).unwrap_or(0);
    if removed > 0 {
        let _ = save(&store);
    }
    removed
}

/// The mailbox an arrived-at address belongs to, if any.
pub fn for_address(account: &str, address: &str) -> Option<String> {
    let address = norm(address);
    list(account)
        .into_iter()
        .find(|m| m.addresses.iter().any(|a| *a == address))
        .map(|m| m.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> String {
        let path = std::env::temp_dir().join(format!("mailboxes-{}-{}.json", std::process::id(), now()));
        std::env::set_var("MAILBOXES_PATH", &path);
        let _ = fs::remove_file(&path);
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn an_address_moves_rather_than_duplicates() {
        let path = temp_store();
        set("tibs", "Work", &["work@slothlee.xyz".into()]).unwrap();
        let err = set("tibs", "Shop", &["work@slothlee.xyz".into()]).unwrap_err();
        assert_eq!(err, SetError::AddressInAnother("work@slothlee.xyz".into()));
        assert_eq!(for_address("tibs", "WORK@slothlee.xyz").as_deref(), Some("Work"));
        let _ = fs::remove_file(path);
    }
}
