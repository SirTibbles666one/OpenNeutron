//! `POST /api/admin/mail-health` — one answer to "is mail working".

use serde_json::json;
use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;
use tiny_http::{Request, Response};

use crate::api::dto::json_header;
use crate::core::{mailhealth, EmailStorage, User, UserStorage};

/// How stale the host's queue snapshot may be before it is reported as unavailable. The host
/// writes one every five minutes; older than fifteen means the writer has stopped.
const QUEUE_MAX_AGE: u64 = 15 * 60;

fn out(status: u16, body: Vec<u8>) -> Response<Cursor<Vec<u8>>> {
    Response::from_data(body)
        .with_status_code(status)
        .with_header(json_header())
}

pub fn health(
    _request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let Some(caller) = user else {
        return out(401, serde_json::to_vec(&json!({"error":"Unauthorized","code":"unauthorized"})).unwrap_or_default());
    };
    if !caller.is_admin {
        return out(403, serde_json::to_vec(&json!({"error":"Administrators only","code":"forbidden"})).unwrap_or_default());
    }

    let now = crate::core::audit::now();

    let (rspamd, rspamd_error) = match mailhealth::rspamd() {
        Ok(stats) => (Some(stats), None),
        Err(e) => (None, Some(e)),
    };

    // Junk totals across every account: the panel asks "is the filter filing anything", and a
    // per-account breakdown belongs in People, not here.
    let junk = crate::core::junk::summary();

    let queue = std::fs::read_to_string("data/postfix-queue.json")
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|value| {
            let at = value.get("at").and_then(|v| v.as_u64()).unwrap_or(0);
            if now.saturating_sub(at) > QUEUE_MAX_AGE {
                return None;
            }
            Some(json!({
                "depth": value.get("depth").and_then(|v| v.as_u64()).unwrap_or(0),
                "deferred": value.get("deferred").and_then(|v| v.as_u64()).unwrap_or(0),
                "at": at,
            }))
        });

    let payload = json!({
        "as_of": now,
        "rspamd": rspamd,
        "rspamd_error": rspamd_error,
        "junk": junk,
        "queue": queue,
        "queue_available": queue.is_some(),
    });
    let _ = Path::new("data").exists(); // keep the path import meaningful if refactored
    out(200, serde_json::to_vec(&payload).unwrap_or_default())
}
