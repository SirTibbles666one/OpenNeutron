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

#[derive(Deserialize)]
struct ConsistencyRequest {
    first: u64,
    second: u64,
}

/// POST /api/kt/consistency — proof that the tree at `second` still contains the tree at
/// `first`.
///
/// This is the check a pinned head cannot do on its own. A browser that saw size 13 can
/// only notice a shrink or a same-size change; a server that rewrites an old leaf and then
/// grows past it looks exactly like normal operation. Here the client names the size it
/// saw, and the proof either extends that history or does not.
pub fn consistency(
    request: &mut Request,
    _user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<crate::core::email::EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let mut body = String::new();
    if std::io::Read::read_to_string(request.as_reader(), &mut body).is_err() {
        return json_response(json!({ "error": "unreadable body", "code": "bad_request" }), 400);
    }
    let req: ConsistencyRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return json_response(json!({ "error": "bad request", "code": "bad_request" }), 400),
    };

    let Some(head) = keylog::head() else {
        return json_response(json!({ "error": "no log yet", "code": "no_log" }), 404);
    };
    if req.second != head.size {
        // Only the current head can be answered for; a client should ask for what it sees.
        return json_response(
            json!({
                "error": "that is not the current tree size",
                "code": "not_current",
                "size": head.size,
            }),
            409,
        );
    }
    if req.first == 0 || req.first > req.second {
        return json_response(
            json!({ "error": "first must be at least 1 and no larger than second", "code": "bad_range" }),
            400,
        );
    }

    match keylog::consistency_proof(req.first as usize, req.second as usize) {
        Some(proof) => {
            let nodes: Vec<String> = proof.iter().map(|node| STANDARD.encode(node)).collect();
            // Included for diagnostics and tests only: a client must verify against the
            // root it pinned, never against one the server hands it now.
            let first_root = keylog::root_at(req.first as usize)
                .map(|root| STANDARD.encode(root))
                .unwrap_or_default();
            json_response(
                json!({
                    "first_size": req.first,
                    "first_root": first_root,
                    "second_size": head.size,
                    "second_root": head.root,
                    "alg": head.alg,
                    "pk": head.pk,
                    "sig": head.sig,
                    "proof": nodes,
                }),
                200,
            )
        }
        None => json_response(json!({ "error": "cannot prove that range", "code": "no_proof" }), 400),
    }
}
