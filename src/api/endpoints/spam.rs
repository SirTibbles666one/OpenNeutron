//! Reporting spam, so the filter can learn what this person calls spam.
//!
//! `POST /api/spam/report` with `{ uid, verdict: "spam" | "ham", raw }`.
//!
//! Why the client sends the message back: this server stores mail encrypted and cannot
//! read it, so it cannot learn from what it holds. The client already has the plaintext —
//! it just rendered it — so a report is the one moment a message is deliberately revealed
//! to the server. That is why this is per-message and user-initiated, never automatic.
//!
//! Two guards that matter more than the learning itself:
//!   * ownership — a report is only accepted for a message in the reporter's own mailbox,
//!     so nobody can poison the corpus by reporting mail they do not own;
//!   * a rate limit — a script cannot flood the classifier with thousands of reports.
//!
//! "ham" is not an afterthought: a filter that only learns spam grows more aggressive
//! until it eats legitimate mail. Both directions are needed for the corpus to be a corpus.

use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tiny_http::{Request, Response};

use crate::api::dto::json_header;
use crate::api::request::read_json_body;
use crate::core::{EmailStorage, User, UserStorage};

/// rspamd's controller, on the loopback interface. Not exposed anywhere else.
const RSPAMD: &str = "127.0.0.1:11334";
/// Reports accepted per account per hour.
const REPORTS_PER_HOUR: u64 = 100;

#[derive(Deserialize)]
struct ReportRequest {
    uid: String,
    verdict: String,
    raw: String,
}

fn out(status: u16, body: Vec<u8>) -> Response<Cursor<Vec<u8>>> {
    Response::from_data(body)
        .with_status_code(status)
        .with_header(json_header())
}

fn json_error(status: u16, code: &str, message: &str) -> Response<Cursor<Vec<u8>>> {
    out(
        status,
        serde_json::to_vec(&json!({ "error": message, "code": code })).unwrap_or_default(),
    )
}

/// Per-account report budget. Rolling hourly window, in memory: a restart forgives a
/// burst, which is the harmless direction to fail in.
static BUDGET: Mutex<Option<HashMap<String, (u64, u64)>>> = Mutex::new(None);

fn take_budget(username: &str) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut guard = match BUDGET.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    let map = guard.get_or_insert_with(HashMap::new);
    let entry = map.entry(username.to_string()).or_insert((now, 0));
    if now.saturating_sub(entry.0) >= 3600 {
        *entry = (now, 0);
    }
    if entry.1 >= REPORTS_PER_HOUR {
        return false;
    }
    entry.1 += 1;
    true
}

/// Hand the message to rspamd. Written by hand rather than with an HTTP crate: this project
/// carries no HTTP client and the build runs offline, and the protocol here is one request
/// with no reply body that matters — a status line is the whole answer.
fn learn(verdict: &str, raw: &str) -> Result<String, String> {
    let path = match verdict {
        "spam" => "/learn_spam",
        "ham" => "/learn_ham",
        other => return Err(format!("unknown verdict '{other}'")),
    };

    let mut stream = TcpStream::connect(RSPAMD)
        .map_err(|e| format!("rspamd is not reachable at {RSPAMD}: {e}"))?;
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(20)));

    let body = raw.as_bytes();
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {RSPAMD}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .and_then(|_| stream.write_all(body))
        .map_err(|e| format!("could not send the message to rspamd: {e}"))?;

    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    let status = response.lines().next().unwrap_or("").to_string();

    if status.contains(" 200") {
        Ok(status)
    } else if status.is_empty() {
        Err("rspamd closed the connection without answering".to_string())
    } else {
        // rspamd answers 404 with an explanation when it has already learned a message.
        // That is not a failure the reporter needs to act on, and saying so would be noise.
        Err(format!("rspamd refused the report: {status}"))
    }
}

pub fn report(
    request: &mut Request,
    user: Option<User>,
    user_storage: std::sync::Arc<UserStorage>,
    _email_storage: std::sync::Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let Some(user) = user else {
        return json_error(401, "unauthorized", "A session is required");
    };

    let body: ReportRequest = match read_json_body(request) {
        Ok(body) => body,
        Err(response) => return response,
    };

    let uid: u128 = match body.uid.trim().parse() {
        Ok(uid) => uid,
        Err(_) => return json_error(400, "bad_uid", "uid must be a message id"),
    };

    // The ownership check. `user` is a snapshot taken at authentication time, so ask the
    // store — a message delivered since could not be in the snapshot.
    let owns = user_storage
        .get_user(&user.username)
        .map(|u| u.emailIds.contains(&uid))
        .unwrap_or(false);
    if !owns {
        // Deliberately the same answer for "not yours" and "does not exist": whether a
        // given uid exists in someone else's mailbox is not this caller's business.
        return json_error(404, "not_found", "No such message in this mailbox");
    }

    if !take_budget(&user.username) {
        return json_error(
            429,
            "rate_limited",
            "Too many reports in an hour; the filter already knows this one",
        );
    }

    if body.raw.len() < 20 || !body.raw.contains(':') {
        return json_error(400, "bad_message", "That does not look like a message");
    }

    match learn(&body.verdict, &body.raw) {
        Ok(_) => out(
            200,
            serde_json::to_vec(&json!({
                "learned": true,
                "verdict": body.verdict,
            }))
            .unwrap_or_default(),
        ),
        Err(message) => {
            // A filter that cannot learn must say so; silently reporting success would let
            // a broken rspamd look like a working spam button for months.
            json_error(503, "learn_failed", &message)
        }
    }
}
