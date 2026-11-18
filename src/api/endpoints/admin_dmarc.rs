//! `POST /api/admin/dmarc` — who is reporting on this domain, and who says mail failed.

use serde::Deserialize;
use serde_json::json;
use std::io::Cursor;
use std::sync::Arc;
use tiny_http::{Request, Response};

use crate::api::dto::json_header;
use crate::api::request::read_json_body;
use crate::core::{EmailStorage, User, UserStorage};

#[derive(Default, Deserialize)]
struct Window {
    #[serde(default)]
    days: Option<u64>,
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
        return out(401, serde_json::to_vec(&json!({"error":"Unauthorized","code":"unauthorized"})).unwrap_or_default());
    };
    if !crate::core::roles::role(&caller.username, caller.is_admin).can_moderate() {
        return out(403, serde_json::to_vec(&json!({"error":"Moderators only","code":"forbidden"})).unwrap_or_default());
    }

    let body: Window = read_json_body(request).unwrap_or_default();
    let days = body.days.unwrap_or(30).clamp(1, 365);
    let summary = crate::core::reports::summary(days);
    out(200, serde_json::to_vec(&summary).unwrap_or_default())
}
