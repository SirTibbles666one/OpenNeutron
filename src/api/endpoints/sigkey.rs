//! Published ML-DSA-65 signing key for the signed-in account.
//!
//! `GET  /api/user/sigkey` — the key this account publishes, or `null`.
//! `POST /api/user/sigkey` — publish one, so senders can verify signatures.
//!
//! Two stores are written, in this order: the key-transparency log (a leaf that
//! commits to the key's hash) and the sidecar that serves the key itself. Log
//! first means the server never hands out a key the log has not witnessed — a
//! sender that checks the head would find no entry and the signature would be
//! useless. If the second write fails, the retry is harmless: the log append is a
//! no-op once the hash is present.
//!
//! The private half never arrives here. This server cannot sign anything for the
//! user, which is what makes a signature meaningful.

use crate::core::{keylog, sigkeys};
use serde::Deserialize;
use serde_json::json;
use std::io::Cursor;
use std::sync::Arc;
use tiny_http::{Request, Response};

use crate::api::dto::json_header;
use crate::api::request::read_json_body;
use crate::core::{EmailStorage, User, UserStorage};

#[derive(Deserialize)]
struct SetSigKeyRequest {
    sig_key: String,
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

pub fn get(
    _request: &mut Request,
    user: Option<User>,
    _u: Arc<UserStorage>,
    _e: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return json_error(401, "unauthorized", "Unauthorized"),
    };
    let sig_key = sigkeys::get(&user.username).map(|k| k.public_key);
    out(
        200,
        serde_json::to_vec(&json!({
            "sig_key": sig_key,
        }))
        .unwrap_or_default(),
    )
}

pub fn set(
    request: &mut Request,
    user: Option<User>,
    _u: Arc<UserStorage>,
    _e: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return json_error(401, "unauthorized", "Unauthorized"),
    };
    let req: SetSigKeyRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if let Err(e) = sigkeys::validate(&req.sig_key) {
        return json_error(400, "invalid_sig_key", &e);
    }
    // The log needs the account's encryption-key leaf to reuse its rsa/pq hashes.
    // Refusing here is honest: an account with no key leaf has nothing for a
    // sender to verify against either.
    if let Err(e) = keylog::record_signing_key(&user.username, &req.sig_key) {
        return json_error(500, "keylog_failed", &e);
    }
    if let Err(e) = sigkeys::set(&user.username, &req.sig_key) {
        return json_error(500, "store_failed", &e);
    }
    log::info!("[sigkey] '{}' published a message signing key", user.username);
    out(
        200,
        serde_json::to_vec(&json!({
            "sig_key": req.sig_key.trim(),
            "message": "Signing key published",
        }))
        .unwrap_or_default(),
    )
}
