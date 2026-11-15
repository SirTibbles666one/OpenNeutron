//! Mailbox definitions, over HTTP.
//!
//! - `GET  /api/mailboxes`         the caller's mailboxes
//! - `POST /api/mailboxes`         create or rename one, with its addresses
//! - `POST /api/mailboxes/delete`  remove one (its messages return to their address)
//!
//! Ownership is checked here, not in the store: a mailbox may only name the caller's own
//! address or an alias the caller controls. Otherwise a mailbox would be a way to read
//! someone else's mail.

use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::Cursor;
use std::sync::Arc;
use tiny_http::{Request, Response};

use crate::api::dto::json_header;
use crate::api::request::read_json_body;
use crate::core::{aliases, mailboxes, EmailStorage, User, UserStorage};

fn out(status: u16, body: Vec<u8>) -> Response<Cursor<Vec<u8>>> {
    Response::from_data(body).with_status_code(status).with_header(json_header())
}

fn notify(status: u16, code: &str, message: &str) -> Response<Cursor<Vec<u8>>> {
    out(status, serde_json::to_vec(&json!({ "error": message, "code": code })).unwrap_or_default())
}

#[derive(Serialize)]
struct MailboxRow {
    name: String,
    addresses: Vec<String>,
    created_at: u64,
}

fn domain() -> String {
    crate::config::get().server.domain.clone()
}

/// Every address this account may put in a mailbox: its own, plus the aliases it controls.
fn owned(user: &User) -> Vec<String> {
    let dom = domain().trim_start_matches('@').to_ascii_lowercase();
    let mut out = vec![format!("{}@{}", user.username.to_ascii_lowercase(), dom)];
    for (local, alias) in aliases::list(&user.username) {
        let owner = if alias.owner.trim().is_empty() {
            alias.username.clone()
        } else {
            alias.owner.clone()
        };
        if !owner.eq_ignore_ascii_case(&user.username) {
            continue;
        }
        out.push(format!("{}@{}", local.to_ascii_lowercase(), dom));
    }
    out
}

pub fn list(
    _request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return notify(401, "unauthorized", "Unauthorized"),
    };
    let rows: Vec<MailboxRow> = mailboxes::list(&user.username)
        .into_iter()
        .map(|m| MailboxRow {
            name: m.name,
            addresses: m.addresses,
            created_at: m.created,
        })
        .collect();
    let body = serde_json::to_vec(&json!({
        "mailboxes": rows,
        // What the caller could put in one, so the client does not have to guess.
        "addresses": owned(&user),
        "max": mailboxes::MAX_MAILBOXES,
    }))
    .unwrap_or_default();
    out(200, body)
}

#[derive(Deserialize)]
struct SetRequest {
    name: String,
    #[serde(default)]
    addresses: Vec<String>,
}

pub fn set(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return notify(401, "unauthorized", "Unauthorized"),
    };
    let req: SetRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let allowed = owned(&user);
    let wanted: Vec<String> = req
        .addresses
        .iter()
        .map(|a| a.trim().to_ascii_lowercase())
        .collect();
    if let Some(stray) = wanted.iter().find(|a| !allowed.contains(a)) {
        return notify(
            403,
            "not_your_address",
            &format!("{stray} is not an address this account controls"),
        );
    }

    match mailboxes::set(&user.username, &req.name, &wanted) {
        Ok(mailbox) => {
            log::info!(
                "[Mailboxes] {} set '{}' with {} address(es)",
                user.username,
                mailbox.name,
                mailbox.addresses.len()
            );
            out(
                200,
                serde_json::to_vec(&json!({
                    "name": mailbox.name,
                    "addresses": mailbox.addresses,
                    "created_at": mailbox.created,
                }))
                .unwrap_or_default(),
            )
        }
        Err(mailboxes::SetError::EmptyName) => notify(400, "name_required", "A mailbox needs a name"),
        Err(mailboxes::SetError::NameTooLong) => notify(
            400,
            "name_too_long",
            &format!("Keep the name under {} characters", mailboxes::MAX_NAME),
        ),
        Err(mailboxes::SetError::TooMany) => notify(
            409,
            "too_many_mailboxes",
            &format!("An account can keep {} mailboxes", mailboxes::MAX_MAILBOXES),
        ),
        Err(mailboxes::SetError::TooManyAddresses) => notify(
            400,
            "too_many_addresses",
            &format!("A mailbox can hold {} addresses", mailboxes::MAX_ADDRESSES),
        ),
        Err(mailboxes::SetError::NoSuchMailbox) => notify(404, "not_found", "No such mailbox"),
        Err(mailboxes::SetError::Io(why)) => {
            log::error!("[Mailboxes] cannot save for {}: {}", user.username, why);
            notify(500, "store_failed", "The mailbox could not be saved")
        }
        Err(mailboxes::SetError::AddressInAnother(which)) => notify(
            409,
            "address_taken",
            &format!("{which} is already in another mailbox"),
        ),
    }
}

#[derive(Deserialize)]
struct DeleteRequest {
    name: String,
}

pub fn delete(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return notify(401, "unauthorized", "Unauthorized"),
    };
    let req: DeleteRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match mailboxes::remove(&user.username, &req.name) {
        Ok(()) => {
            log::info!("[Mailboxes] {} removed '{}'", user.username, req.name);
            out(200, serde_json::to_vec(&json!({ "removed": true })).unwrap_or_default())
        }
        Err(mailboxes::RemoveError::NotFound) => notify(404, "not_found", "No such mailbox"),
        Err(mailboxes::RemoveError::Io(why)) => {
            log::error!("[Mailboxes] cannot delete for {}: {}", user.username, why);
            notify(500, "store_failed", "The mailbox could not be removed")
        }
    }
}
