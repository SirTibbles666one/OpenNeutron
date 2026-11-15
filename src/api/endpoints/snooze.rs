//! Snooze endpoints: put a message away until a time, list what is away, wake one early.
//!
//! See `core::snooze` for why this is a timestamp rather than a timer.

use serde::{Deserialize, Serialize};
use std::io::Cursor;
use std::sync::Arc;
use tiny_http::{Request, Response};

use crate::api::dto::{json_header, ErrorResponse};
use crate::api::request::read_json_body;
use crate::core::{snooze, EmailStorage, User, UserStorage};

type Resp = Response<Cursor<Vec<u8>>>;

fn error(status: u16, code: &str, message: &str) -> Resp {
    let body = serde_json::to_vec(&ErrorResponse { error: message.into(), code: code.into() }).unwrap();
    Response::from_data(body).with_status_code(status).with_header(json_header())
}

fn ok<T: Serialize>(value: &T) -> Resp {
    Response::from_data(serde_json::to_vec(value).unwrap()).with_status_code(200).with_header(json_header())
}

#[derive(Deserialize)]
struct SnoozeRequest {
    #[serde(deserialize_with = "crate::api::u128_flex::uid")]
    uid: u128,
    /// Unix time to come back. Absolute, so the client's clock and this one cannot disagree
    /// about what "tomorrow 9am" meant after a reload.
    until: u64,
}

#[derive(Deserialize)]
struct UidRequest {
    #[serde(deserialize_with = "crate::api::u128_flex::uid")]
    uid: u128,
}

#[derive(Serialize)]
struct SnoozeResponse {
    /// Quoted: a 38-digit id does not survive a JavaScript number, and a client that rounds it
    /// can never name the message again.
    uid: String,
    until: u64,
}

#[derive(Serialize)]
struct SnoozeItem {
    /// Quoted for the same reason as SnoozeResponse.
    uid: String,
    until: u64,
}

#[derive(Serialize)]
struct SnoozeListResponse {
    items: Vec<SnoozeItem>,
    /// True for the ones whose time has already passed and are back in the inbox.
    #[serde(skip)]
    now: u64,
}

fn owns(user: &User, uid: u128) -> bool {
    user.emailIds.contains(&uid) || user.sent_emails.contains(&uid)
}

/// POST /email/snooze
pub fn snooze_email(
    request: &mut Request,
    user: Option<User>,
    _users: Arc<UserStorage>,
    _mail: Arc<EmailStorage>,
) -> Resp {
    let user = match user {
        Some(u) => u,
        None => return error(401, "unauthorized", "Unauthorized"),
    };
    let req: SnoozeRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if !owns(&user, req.uid) {
        return error(404, "not_found", "No such message");
    }
    let now = snooze::now();
    if req.until <= now {
        return error(400, "in_the_past", "That time has already passed");
    }
    if req.until > now + snooze::MAX_SECONDS {
        return error(400, "too_far", "A snooze cannot last more than a year");
    }
    match snooze::set(&user.username, req.uid, req.until) {
        Ok(()) => ok(&SnoozeResponse { uid: req.uid.to_string(), until: req.until }),
        Err(e) => {
            log::error!("[Snooze] cannot save for {}: {}", user.username, e);
            error(500, "store_failed", "That message could not be put away")
        }
    }
}

/// POST /email/unsnooze — bring one back now.
pub fn unsnooze_email(
    request: &mut Request,
    user: Option<User>,
    _users: Arc<UserStorage>,
    _mail: Arc<EmailStorage>,
) -> Resp {
    let user = match user {
        Some(u) => u,
        None => return error(401, "unauthorized", "Unauthorized"),
    };
    let req: UidRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if !owns(&user, req.uid) {
        return error(404, "not_found", "No such message");
    }
    match snooze::clear(&user.username, req.uid) {
        Ok(removed) => ok(&serde_json::json!({ "uid": req.uid.to_string(), "was_snoozed": removed })),
        Err(e) => {
            log::error!("[Snooze] cannot clear for {}: {}", user.username, e);
            error(500, "store_failed", "That message could not be brought back")
        }
    }
}

/// POST /email/snoozed — what is away, soonest first.
pub fn list_snoozed(
    _request: &mut Request,
    user: Option<User>,
    _users: Arc<UserStorage>,
    _mail: Arc<EmailStorage>,
) -> Resp {
    let user = match user {
        Some(u) => u,
        None => return error(401, "unauthorized", "Unauthorized"),
    };
    let now = snooze::now();
    let items: Vec<SnoozeItem> = snooze::list(&user.username)
        .into_iter()
        .filter(|item| item.until > now)
        .map(|item| SnoozeItem { uid: item.uid.to_string(), until: item.until })
        .collect();
    let _ = snooze::sweep(&user.username, now);
    ok(&SnoozeListResponse { items, now })
}
