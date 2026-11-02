//! Public endpoints for the key-transparency log.
//!
//! Both are unauthenticated on purpose. A sender checking that the key it was just
//! handed really belongs to the recipient has no account here, and a proof that only
//! insiders can fetch proves nothing to the people who need it.
//!
//! What they expose is hashes and signatures: no public keys, no addresses beyond the
//! one asked for, nothing that helps an attacker more than `/api/email/publickeys`
//! already does.

use crate::api::dto::json_header;
use crate::core::keylog;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;
use serde_json::json;
use crate::core::user::{User, UserStorage};
use std::io::Cursor;
use std::sync::Arc;
use tiny_http::{Request, Response};

fn json_response(body: serde_json::Value, status: u16) -> Response<Cursor<Vec<u8>>> {
    let bytes = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    Response::from_data(bytes)
        .with_status_code(status)
        .with_header(json_header())
}

/// GET /api/kt/head — the signed root, for anything that wants to pin one.
pub fn head(
    _request: &mut Request,
    _user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<crate::core::email::EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    match keylog::head() {
        Some(head) => json_response(
            json!({
                "size": head.size,
                "root": head.root,
                "alg": head.alg,
                "pk": head.pk,
                "sig": head.sig,
            }),
            200,
        ),
        None => json_response(json!({ "error": "no log yet", "code": "no_log" }), 404),
    }
}

#[derive(Deserialize)]
struct ProofRequest {
    username: String,
}

/// POST /api/kt/proof — one account's newest leaf and the path that binds it to the head.
pub fn proof(
    request: &mut Request,
    _user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<crate::core::email::EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let mut body = String::new();
    if std::io::Read::read_to_string(request.as_reader(), &mut body).is_err() {
        return json_response(json!({ "error": "unreadable body", "code": "bad_request" }), 400);
    }
    let req: ProofRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return json_response(json!({ "error": "bad request", "code": "bad_request" }), 400),
    };

    match keylog::proof(&req.username) {
        Some((leaf, index, path, head)) => {
            let path: Vec<String> = path.iter().map(|node| STANDARD.encode(node)).collect();
            json_response(
                json!({
                    "leaf": {
                        "seq": leaf.seq,
                        "account": leaf.account,
                        "rsa": leaf.rsa,
                        "pq": leaf.pq,
                        "at": leaf.at,
                    },
                    "index": index,
                    "path": path,
                    "head": {
                        "size": head.size,
                        "root": head.root,
                        "alg": head.alg,
                        "pk": head.pk,
                        "sig": head.sig,
                    },
                }),
                200,
            )
        }
        None => json_response(json!({ "error": "no leaf for that account", "code": "no_leaf" }), 404),
    }
}
