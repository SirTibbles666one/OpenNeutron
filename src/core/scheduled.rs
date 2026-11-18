//! Messages held until a chosen time, then handed to the normal send path.
//!
//! The point is not a queue: it is that the message does not exist on the wire
//! until the moment it was meant to. The body is stored exactly as the client
//! built it — encrypted payloads stay encrypted, so a scheduled message is no
//! more readable to this server than an immediate one.
//!
//! Stored in `data/scheduled.json`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

static LOCK: Mutex<()> = Mutex::new(());

/// How far ahead a message may be queued.
pub const MAX_AHEAD_SECONDS: u64 = 365 * 24 * 3600;
/// How many a single account may hold at once.
pub const MAX_PENDING_PER_OWNER: usize = 50;

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// What is being held. A raw message is a finished MIME blob; an encrypted one
/// is the whole client request, replayed through the normal send endpoint when
/// its time comes so the encryption and local-copy rules cannot diverge.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Raw,
    Encrypted,
}

impl Default for Kind {
    fn default() -> Self {
        Kind::Raw
    }
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Raw => "raw",
            Kind::Encrypted => "encrypted",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pending,
    /// Claimed by a sender that is putting it on the wire right now. Only one process can hold
    /// this: `claim` flips Pending -> Sending under the lock, so a second process looking at the
    /// same queue cannot send the same message again. Blue-green deploys run two processes.
    Sending,
    Sent,
    Failed,
    Cancelled,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Pending => "pending",
            Status::Sending => "sending",
            Status::Sent => "sent",
            Status::Failed => "failed",
            Status::Cancelled => "cancelled",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Item {
    pub id: String,
    pub owner: String,
    pub to: Vec<String>,
    /// What is being held: a base64 MIME blob, or the JSON send request.
    #[serde(default)]
    pub kind: Kind,
    /// The message exactly as the client built it, base64 or JSON.
    pub data: String,
    /// For the sender's own list; never used for delivery.
    #[serde(default)]
    pub subject: String,
    /// The subject sealed to the sender's own key. Stored and returned opaquely: the server can
    /// hand it back for the held list without ever being able to read what the message is about.
    #[serde(default)]
    pub subject_enc: Option<String>,
    pub created_at: u64,
    pub send_at: u64,
    pub status: Status,
    #[serde(default)]
    pub sent_at: Option<u64>,
    /// When a sender claimed it. Used to recover a claim whose process died mid-send.
    #[serde(default)]
    pub claimed_at: Option<u64>,
    #[serde(default)]
    pub error: String,
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Store {
    #[serde(default)]
    pub items: BTreeMap<String, Item>,
}

fn path() -> PathBuf {
    PathBuf::from("data").join("scheduled.json")
}

fn read_at(path: &PathBuf) -> Store {
    match fs::read(path) {
        Ok(bytes) if !bytes.is_empty() => serde_json::from_slice(&bytes).unwrap_or_default(),
        _ => Store::default(),
    }
}

fn write_at(path: &PathBuf, store: &Store) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let body = serde_json::to_vec_pretty(store).map_err(io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&body)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

/// A short, unguessable id. Not a capability — every read is owner-scoped — so a
/// timestamp plus a counter is enough and keeps the list sortable.
fn new_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("s{:x}", nanos)
}

pub enum QueueError {
    TooMany,
    TooSoon,
    TooFar,
}

pub fn queue(
    owner: &str,
    to: Vec<String>,
    kind: Kind,
    data: String,
    subject: String,
    subject_enc: Option<String>,
    send_at: u64,
) -> Result<Item, QueueError> {
    let _held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = path();
    let mut store = read_at(&path);

    let pending = store
        .items
        .values()
        .filter(|i| i.owner.eq_ignore_ascii_case(owner) && i.status == Status::Pending)
        .count();
    if pending >= MAX_PENDING_PER_OWNER {
        return Err(QueueError::TooMany);
    }

    let current = now();
    if send_at <= current + 5 {
        return Err(QueueError::TooSoon);
    }
    if send_at > current + MAX_AHEAD_SECONDS {
        return Err(QueueError::TooFar);
    }

    let item = Item {
        id: new_id(),
        owner: owner.to_string(),
        to,
        kind,
        data,
        subject: subject.chars().take(120).collect(),
        subject_enc,
        created_at: current,
        send_at,
        status: Status::Pending,
        sent_at: None,
        claimed_at: None,
        error: String::new(),
    };
    store.items.insert(item.id.clone(), item.clone());
    write_at(&path, &store).map_err(|e| {
        log::error!("[Scheduled] Could not save '{}': {}", item.id, e);
        QueueError::TooSoon
    })?;
    Ok(item)
}

/// The sender's own view. Bodies are never returned: the list only needs to say
/// what is waiting and when.
#[derive(Serialize)]
pub struct Row {
    pub id: String,
    pub to: Vec<String>,
    pub subject: String,
    pub subject_enc: Option<String>,
    pub created_at: u64,
    pub send_at: u64,
    pub status: String,
    pub kind: String,
    pub sent_at: Option<u64>,
    pub error: String,
}

pub fn list(owner: &str) -> Vec<Row> {
    let store = read_at(&path());
    let mut rows: Vec<Row> = store
        .items
        .values()
        .filter(|i| i.owner.eq_ignore_ascii_case(owner))
        .map(|i| Row {
            id: i.id.clone(),
            to: i.to.clone(),
            subject: i.subject.clone(),
            subject_enc: i.subject_enc.clone(),
            created_at: i.created_at,
            send_at: i.send_at,
            status: i.status.as_str().to_string(),
            kind: i.kind.as_str().to_string(),
            sent_at: i.sent_at,
            error: i.error.clone(),
        })
        .collect();
    rows.sort_by_key(|r| r.send_at);
    rows
}

/// Withdraw a queued message. Only before it goes out — once sent, nothing here
/// can call it back.
pub fn cancel(owner: &str, id: &str) -> io::Result<bool> {
    let _held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = path();
    let mut store = read_at(&path);
    let item = match store.items.get_mut(id) {
        Some(i) if i.owner.eq_ignore_ascii_case(owner) => i,
        _ => return Ok(false),
    };
    if item.status != Status::Pending {
        return Ok(false);
    }
    item.status = Status::Cancelled;
    item.data.clear();
    write_at(&path, &store)?;
    Ok(true)
}

/// Replace a held message without changing its id.
///
/// A held message is a finished client request, stored exactly as it was built, so
/// editing means swapping in a newly built one — the server never writes a body of
/// its own. Only a *pending* item can be replaced: a released or failed one is
/// history, and rewriting it would let a sender claim that a message already
/// delivered said something else. `Ok(None)` means "no such pending item of yours",
/// the same single answer `cancel` gives, so neither can be used to probe for ids.
pub fn reschedule(
    owner: &str,
    id: &str,
    to: Vec<String>,
    data: String,
    subject: String,
    subject_enc: Option<String>,
    send_at: u64,
) -> Result<Option<Item>, QueueError> {
    let _held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = path();
    let mut store = read_at(&path);

    let kind = match store.items.get(id) {
        Some(i) if i.owner.eq_ignore_ascii_case(owner) => {
            if i.status != Status::Pending {
                return Ok(None);
            }
            i.kind
        }
        _ => return Ok(None),
    };

    let current = now();
    if send_at <= current + 5 {
        return Err(QueueError::TooSoon);
    }
    if send_at > current + MAX_AHEAD_SECONDS {
        return Err(QueueError::TooFar);
    }

    let item = match store.items.get_mut(id) {
        Some(i) => i,
        None => return Ok(None),
    };
    item.to = to;
    item.kind = kind;
    item.data = data;
    item.subject = subject.chars().take(120).collect();
    item.subject_enc = subject_enc;
    item.send_at = send_at;
    item.error.clear();
    let updated = item.clone();
    write_at(&path, &store).map_err(|e| {
        log::error!("[Scheduled] Could not save the edit to '{}': {}", id, e);
        QueueError::TooSoon
    })?;
    Ok(Some(updated))
}

/// Everything that is due, oldest deadline first. The caller delivers and then
/// reports back with `finish`.
pub fn due(at: u64) -> Vec<Item> {
    let store = read_at(&path());
    let mut items: Vec<Item> = store
        .items
        .values()
        .filter(|i| i.status == Status::Pending && i.send_at <= at)
        .cloned()
        .collect();
    items.sort_by_key(|i| i.send_at);
    items
}

/// Take a due message, if it is still there to take.
///
/// `due` is a read: two processes that sweep at the same moment both see the same item. `claim`
/// is the write that decides — exactly one caller moves it to Sending, and the other is told to
/// leave it alone. This is what makes it safe to run an old and a new server at the same time.
/// May this item be taken by a sender at `at`? Pure, so the rule can be tested without a store.
fn claimable(item: &Item, at: u64) -> bool {
    item.status == Status::Pending && item.send_at <= at
}

/// Is this claim older than the point where it must be assumed dead?
fn is_stale(item: &Item, current: u64, stale_after: u64) -> bool {
    if item.status != Status::Sending {
        return false;
    }
    match item.claimed_at {
        Some(when) => when == 0 || current.saturating_sub(when) >= stale_after,
        None => true,
    }
}

pub fn claim(id: &str, at: u64) -> bool {
    let _held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = path();
    let mut store = read_at(&path);
    let taken = match store.items.get_mut(id) {
        Some(item) if claimable(item, at) => {
            item.status = Status::Sending;
            item.claimed_at = Some(now());
            true
        }
        _ => false,
    };
    if taken {
        if let Err(e) = write_at(&path, &store) {
            log::error!("[Scheduled] Could not record a claim on {}: {}", id, e);
            return false;
        }
    }
    taken
}

/// A claim older than `stale_after` seconds belongs to a process that died mid-send. Put it back
/// in the queue rather than leaving a message nobody will ever send and nobody can cancel.
pub fn recover_stale(stale_after: u64) -> usize {
    let _held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = path();
    let mut store = read_at(&path);
    let current = now();
    let mut recovered = 0;
    let mut touched = false;
    for item in store.items.values_mut() {
        if is_stale(item, current, stale_after) {
            item.status = Status::Pending;
            item.claimed_at = None;
            recovered += 1;
            touched = true;
            log::warn!("[Scheduled] Recovered a stale claim on {}", item.id);
        }
    }
    if touched {
        let _ = write_at(&path, &store);
    }
    recovered
}

/// Record the outcome and drop the body: whether it went or failed, the bytes do
/// not need to sit on disk afterwards.
pub fn finish(id: &str, error: Option<String>) -> io::Result<()> {
    let _held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = path();
    let mut store = read_at(&path);
    if let Some(item) = store.items.get_mut(id) {
        item.data.clear();
        match error {
            Some(e) => {
                item.status = Status::Failed;
                item.error = e.chars().take(300).collect();
            }
            None => {
                item.status = Status::Sent;
                item.sent_at = Some(now());
            }
        }
    }
    write_at(&path, &store)
}

/// Drop everything an account has queued. Called when the account goes: a held
/// message with no mailbox behind it can only ever fail on release.
pub fn purge(owner: &str) -> io::Result<usize> {
    let _held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = path();
    let mut store = read_at(&path);
    let before = store.items.len();
    store.items.retain(|_, i| !i.owner.eq_ignore_ascii_case(owner));
    let removed = before - store.items.len();
    if removed > 0 {
        write_at(&path, &store)?;
    }
    Ok(removed)
}

/// Forget finished rows older than a day, so the file does not grow forever.
pub fn sweep_old(at: u64) {
    let _held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = path();
    let mut store = read_at(&path);
    let before = store.items.len();
    store.items.retain(|_, i| {
        let done = i.status != Status::Pending;
        let when = i.sent_at.unwrap_or(i.created_at);
        !(done && at.saturating_sub(when) > 24 * 3600)
    });
    if store.items.len() != before {
        if let Err(e) = write_at(&path, &store) {
            log::warn!("[Scheduled] Could not prune finished items: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_round_trips() {
        let s = serde_json::to_string(&Status::Pending).unwrap();
        assert_eq!(s, "\"pending\"");
        let back: Status = serde_json::from_str("\"failed\"").unwrap();
        assert_eq!(back, Status::Failed);
    }

    fn item(status: Status, send_at: u64, claimed_at: Option<u64>) -> Item {
        Item {
            id: "x".into(),
            owner: "tibs".into(),
            to: vec!["a@b.c".into()],
            kind: Kind::Encrypted,
            data: "payload".into(),
            subject: String::new(),
            subject_enc: None,
            created_at: 0,
            send_at,
            status,
            sent_at: None,
            claimed_at,
            error: String::new(),
        }
    }

    #[test]
    fn only_a_due_pending_item_can_be_claimed() {
        assert!(claimable(&item(Status::Pending, 100, None), 100));
        assert!(!claimable(&item(Status::Pending, 101, None), 100), "not yet due");
        assert!(!claimable(&item(Status::Sending, 100, Some(99)), 100), "already taken");
        assert!(!claimable(&item(Status::Sent, 100, None), 100));
        assert!(!claimable(&item(Status::Cancelled, 100, None), 100));
    }

    #[test]
    fn a_claim_is_stale_only_after_the_grace_period() {
        assert!(!is_stale(&item(Status::Sending, 0, Some(1000)), 1100, 300), "still alive");
        assert!(is_stale(&item(Status::Sending, 0, Some(1000)), 1400, 300), "grace elapsed");
        assert!(is_stale(&item(Status::Sending, 0, None), 1000, 300), "no timestamp at all");
        assert!(!is_stale(&item(Status::Pending, 0, None), 1000, 300), "pending is not a claim");
    }

    #[test]
    fn ids_are_unique() {
        let a = new_id();
        let b = new_id();
        assert_ne!(a, b);
    }
}
