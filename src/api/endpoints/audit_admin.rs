//! `POST /api/admin/audit` — what administrators have done.
//!
//! Admin-only, and reading is itself recorded: who looked at the log is part of the log.
//! The integrity of the chain is returned with every page, so the panel can show whether
//! the record is intact without a second request — and so a broken chain is impossible to
//! miss rather than something you have to go looking for.

use serde::Deserialize;
use serde_json::json;
use std::io::Cursor;
use std::sync::Arc;
use tiny_http::{Request, Response};

use crate::api::dto::json_header;
use crate::api::request::read_json_body;
use crate::core::{audit, EmailStorage, User, UserStorage};

const DEFAULT_PAGE: usize = 50;
const MAX_PAGE: usize = 200;

#[derive(Default, Deserialize)]
struct AuditRequest {
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    limit: Option<usize>,
    /// Only records about this account.
    #[serde(default)]
    target: Option<String>,
}

fn out(status: u16, body: Vec<u8>) -> Response<Cursor<Vec<u8>>> {
    Response::from_data(body)
        .with_status_code(status)
        .with_header(json_header())
}

pub fn list(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let Some(caller) = user else {
        return out(401, serde_json::to_vec(&json!({ "error": "Unauthorized", "code": "unauthorized" })).unwrap_or_default());
    };
    // Defence in depth: the router already enforces Admin for this path, and this makes the
    // handler safe even if someone registers it under the wrong guard later.
    // Staff may read these: moderation needs the log and the health card. The router already
    // enforces the route; this keeps the handler correct if it is ever registered elsewhere.
    if !crate::core::roles::role(&caller.username, caller.is_admin).can_moderate() {
        return out(403, serde_json::to_vec(&json!({ "error": "Administrators only", "code": "forbidden" })).unwrap_or_default());
    }

    let body: AuditRequest = read_json_body(request).unwrap_or_default();
    let limit = body.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE);
    let offset = body.offset.unwrap_or(0).min(200_000);
    let target = body.target.as_deref().map(|t| t.trim().to_lowercase());
    let target = target.as_deref().filter(|t| !t.is_empty());

    let (records, total) = audit::page(offset, limit, target);

    // Reading the log is an act worth recording. Appended after the page is taken, so the
    // read does not appear in the page it is describing, and the chain is verified after the
    // append so the count reported is the count that exists.
    let _ = audit::append(&caller.username, "audit.read", "", "");
    let chain = match audit::verify() {
        Ok(count) => json!({ "ok": true, "count": count }),
        Err((index, why)) => json!({ "ok": false, "count": index, "why": why }),
    };

    let payload = json!({
        "records": records,
        "total": total,
        "has_more": offset.saturating_add(limit) < total,
        "chain": chain,
    });
    out(200, serde_json::to_vec(&payload).unwrap_or_default())
}
