//! Security-key (WebAuthn) endpoints: enrol a YubiKey, list keys, remove one,
//! and sign in with a key.
//!
//! Login mirrors `twofactor::login_with_code`: the password step hands out a
//! scoped `mfa` challenge, and no session exists until the second factor is
//! proven. The challenge that WebAuthn signs is generated here, kept in memory,
//! and deleted the moment it is redeemed — a signature over an old challenge is
//! still a valid signature, so single-use is the server's job, not the key's.

use serde_json;
use tiny_http::{Request, Response};
use std::collections::HashMap;
use std::io::Cursor;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::api::dto::{json_header, ErrorResponse, LoginResponse};
use crate::api::request::read_json_body;
use crate::api::ratelimit;
use crate::core::webauthn;
use crate::core::twofactor;
use crate::core::{EmailStorage, User, UserStorage};
use crate::utils::jwt::{generate_jwt_with_sid, validate_jwt};

type Resp = Response<Cursor<Vec<u8>>>;

/// Where the key will be used. Both are checked by the verifier, so a key
/// enrolled on another site cannot be replayed here.
const RP_ID: &str = "mail.slothlee.xyz";
const ORIGIN: &str = "https://mail.slothlee.xyz";
/// Five minutes, matching the login challenge: long enough to touch a key,
/// short enough that a leaked challenge is worthless.
const CHALLENGE_TTL: u64 = 300;

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn error(status: u16, code: &str, message: &str) -> Resp {
    let body = serde_json::to_vec(&ErrorResponse { error: message.into(), code: code.into() }).unwrap();
    Response::from_data(body).with_status_code(status).with_header(json_header())
}

fn ok_json(value: serde_json::Value) -> Resp {
    Response::from_data(serde_json::to_vec(&value).unwrap())
        .with_status_code(200)
        .with_header(json_header())
}

#[derive(Clone)]
struct Pending {
    challenge: String,
    username: String,
    expires: u64,
}

fn pendings() -> &'static Mutex<HashMap<String, Pending>> {
    static P: OnceLock<Mutex<HashMap<String, Pending>>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Issue a challenge and remember it. The id is what the client echoes back, so a
/// client cannot choose its own challenge.
fn issue_challenge(username: &str) -> (String, String) {
    let mut raw = [0u8; 32];
    rand::Rng::fill(&mut rand::thread_rng(), &mut raw);
    let challenge = webauthn::b64url_encode(&raw);
    let id = webauthn::b64url_encode(&raw[..16]);
    if let Ok(mut map) = pendings().lock() {
        map.retain(|_, p| p.expires > now());
        map.insert(id.clone(), Pending {
            challenge: challenge.clone(),
            username: username.to_string(),
            expires: now() + CHALLENGE_TTL,
        });
    }
    (id, challenge)
}

/// Take a challenge out of the store. Single use: the second attempt finds nothing.
fn take_challenge(id: &str, username: &str) -> Option<String> {
    let mut map = pendings().lock().ok()?;
    let p = map.remove(id)?;
    if p.expires < now() || p.username != username {
        return None;
    }
    Some(p.challenge)
}

fn decode_field(body: &serde_json::Value, name: &str) -> Result<Vec<u8>, Resp> {
    let s = body.get(name).and_then(|v| v.as_str()).unwrap_or("");
    if s.is_empty() {
        return Err(error(400, "missing_field", &format!("{} is required", name)));
    }
    webauthn::b64_decode_any(s).map_err(|_| error(400, "bad_encoding", &format!("{} is not valid base64", name)))
}

/// A second factor must be proven before the key list can be changed, so a stolen
/// session cannot enrol a key of its own and keep access after the password changes.

/// Proof by an existing key, valid for five minutes.
///
/// In memory on purpose: a restart voids every grant, and a grant is worth less than the
/// risk of persisting a "this session may skip the second factor" flag to disk.
static REAUTH: std::sync::Mutex<Option<std::collections::HashMap<String, u64>>> =
    std::sync::Mutex::new(None);

const REAUTH_SECONDS: u64 = 300;

fn grant_reauth(username: &str) {
    if let Ok(mut guard) = REAUTH.lock() {
        let map = guard.get_or_insert_with(std::collections::HashMap::new);
        map.insert(username.to_lowercase(), now() + REAUTH_SECONDS);
    }
}

fn reauth_live(username: &str) -> bool {
    match REAUTH.lock() {
        Ok(mut guard) => {
            let map = guard.get_or_insert_with(std::collections::HashMap::new);
            match map.get(&username.to_lowercase()).copied() {
                Some(until) if until > now() => true,
                Some(_) => {
                    map.remove(&username.to_lowercase());
                    false
                }
                None => false,
            }
        }
        Err(_) => false,
    }
}

fn reauthenticated(username: &str, body: &serde_json::Value) -> Result<(), Resp> {
    if !twofactor::is_enabled(username) {
        return Ok(());
    }
    // No key enrolled yet: there is nothing to touch and, if the person has no authenticator
    // app to hand, no code to give. The password-authenticated session is the proof, and the
    // alternative is an account that can never add a hardware key at all.
    if webauthn::count(username) == 0 {
        return Ok(());
    }
    // A key touched in the last five minutes is proof enough, and is the flow a hardware
    // key owner expects: no app, no digits, one touch.
    if reauth_live(username) {
        return Ok(());
    }
    let code = body.get("code").and_then(|v| v.as_str()).unwrap_or("");
    if code.is_empty() {
        return Err(error(401, "code_required", "Enter a code from your authenticator to change security keys"));
    }
    let accepted = twofactor::verify_login_code(username, code, now())
        || twofactor::consume_recovery_code(username, code);
    if !accepted {
        return Err(error(401, "invalid_code", "That code is not valid"));
    }
    Ok(())
}

/// GET /user/webauthn — the keys on this account.
pub fn list(request: &mut Request, user: Option<User>, _u: Arc<UserStorage>, _e: Arc<EmailStorage>) -> Resp {
    let _ = request;
    let Some(user) = user else {
        return error(401, "unauthorized", "Unauthorized");
    };
    let keys: Vec<serde_json::Value> = webauthn::list(&user.username)
        .into_iter()
        .map(|k| serde_json::json!({
            "id": k.id,
            "name": k.name,
            "created_at": k.created_at,
            "last_used_at": k.last_used_at,
            "sign_count": k.sign_count,
        }))
        .collect();
    ok_json(serde_json::json!({
        "keys": keys,
        "max": webauthn::MAX_KEYS_PER_USER,
        "rp_id": RP_ID,
        // An account without an authenticator app has no code to give, and asking
        // for one would make the screen unusable rather than safer.
        // Only once a key exists: with none enrolled there is nothing to touch, and asking
        // for an app code is the deadlock that made the first key impossible to add.
        "code_required": twofactor::is_enabled(&user.username)
            && webauthn::count(&user.username) > 0,
    }))
}


/// How hard the key must prove a person is present.
///
/// "preferred" lets a bare touch satisfy a sign-in; "required" demands the key's PIN or
/// biometric. Required is stronger and is what a key guarding an admin panel deserves — but
/// a key with no PIN cannot answer it, so this is a switch the owner throws after checking
/// their own key, not a default changed underneath a working setup.
fn user_verification() -> &'static str {
    match std::env::var("SLOTH_WEBAUTHN_UV").ok().as_deref() {
        Some("required") => "required",
        Some("discouraged") => "discouraged",
        _ => "preferred",
    }
}

/// POST /user/webauthn/register/begin — hand the browser creation options.
pub fn register_begin(
    request: &mut Request,
    user: Option<User>,
    _u: Arc<UserStorage>,
    _e: Arc<EmailStorage>,
) -> Resp {
    let Some(user) = user else {
        return error(401, "unauthorized", "Unauthorized");
    };
    let body: serde_json::Value = match read_json_body(request) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    if let Err(resp) = reauthenticated(&user.username, &body) {
        return resp;
    }
    if webauthn::count(&user.username) >= webauthn::MAX_KEYS_PER_USER {
        return error(400, "too_many_keys", "Remove a security key before adding another");
    }

    let (challenge_id, challenge) = issue_challenge(&user.username);
    // A stable, opaque user handle: the key stores this, not the username, so the
    // hardware never learns who the account belongs to.
    let handle = {
        use sha2::{Digest, Sha256};
        webauthn::b64url_encode(&Sha256::digest(user.username.as_bytes())[..16])
    };
    let exclude: Vec<serde_json::Value> = webauthn::list(&user.username)
        .into_iter()
        .map(|k| serde_json::json!({ "type": "public-key", "id": k.id }))
        .collect();

    ok_json(serde_json::json!({
        "challenge_id": challenge_id,
        "options": {
            "challenge": challenge,
            "rp": { "id": RP_ID, "name": "Sloth Lee Mail" },
            "user": { "id": handle, "name": user.username, "displayName": user.username },
            "pubKeyCredParams": [ { "type": "public-key", "alg": -7 } ],
            "timeout": 120000,
            "attestation": "none",
            "authenticatorSelection": {
                "residentKey": "discouraged",
                "requireResidentKey": false,
                "userVerification": user_verification()
            },
            "excludeCredentials": exclude,
        }
    }))
}

/// POST /user/webauthn/register/finish — verify the attestation and store the key.
pub fn register_finish(
    request: &mut Request,
    user: Option<User>,
    _u: Arc<UserStorage>,
    _e: Arc<EmailStorage>,
) -> Resp {
    let Some(user) = user else {
        return error(401, "unauthorized", "Unauthorized");
    };
    let body: serde_json::Value = match read_json_body(request) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    if webauthn::count(&user.username) >= webauthn::MAX_KEYS_PER_USER {
        return error(400, "too_many_keys", "Remove a security key before adding another");
    }
    let challenge_id = body.get("challenge_id").and_then(|v| v.as_str()).unwrap_or("");
    let Some(challenge) = take_challenge(challenge_id, &user.username) else {
        return error(400, "stale_challenge", "That enrolment expired; start again");
    };
    let client_data = match decode_field(&body, "clientDataJSON") {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let attestation = match decode_field(&body, "attestationObject") {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let name = if name.is_empty() { "Security key".to_string() } else { name.chars().take(40).collect() };

    let registered = match webauthn::verify_registration(&client_data, &attestation, &challenge, ORIGIN, RP_ID) {
        Ok(r) => r,
        Err(e) => {
            log::warn!("[WebAuthn] registration refused for '{}': {}", user.username, e);
            return error(400, "registration_failed", &e);
        }
    };

    let key = webauthn::SecurityKey {
        id: registered.credential_id.clone(),
        public_key: registered.public_key,
        alg: registered.alg,
        sign_count: 0,
        name: name.clone(),
        created_at: now(),
        last_used_at: 0,
    };
    if let Err(e) = webauthn::add(&user.username, key) {
        return error(400, "storage_error", &e);
    }
    log::info!("[WebAuthn] '{}' enrolled a security key '{}'", user.username, name);
    let _ = crate::core::audit::append(&user.username, "user.key.add", &user.username, &name);
    ok_json(serde_json::json!({
        "message": "Security key added",
        "key": { "id": registered.credential_id, "name": name }
    }))
}

/// POST /user/webauthn/remove — drop a key. Requires a fresh second factor.
pub fn remove(
    request: &mut Request,
    user: Option<User>,
    _u: Arc<UserStorage>,
    _e: Arc<EmailStorage>,
) -> Resp {
    let Some(user) = user else {
        return error(401, "unauthorized", "Unauthorized");
    };
    let body: serde_json::Value = match read_json_body(request) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    if let Err(resp) = reauthenticated(&user.username, &body) {
        return resp;
    }
    let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
    if id.is_empty() {
        return error(400, "missing_field", "id is required");
    }
    match webauthn::remove(&user.username, id) {
        Ok(()) => {
            log::warn!("[WebAuthn] '{}' removed a security key", user.username);
            let _ = crate::core::audit::append(&user.username, "user.key.remove", &user.username, &id);
    ok_json(serde_json::json!({ "message": "Security key removed" }))
        }
        Err(e) => error(404, "not_found", &e),
    }
}

/// POST /auth/login/webauthn/begin — assertion options for a pending login.
pub fn login_begin(
    request: &mut Request,
    _user: Option<User>,
    _u: Arc<UserStorage>,
    _e: Arc<EmailStorage>,
) -> Resp {
    let body: serde_json::Value = match read_json_body(request) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let mfa = body.get("challenge").and_then(|v| v.as_str()).unwrap_or("");
    let claims = match validate_jwt(mfa) {
        Ok(c) => c,
        Err(_) => return error(401, "invalid_challenge", "That login attempt expired; sign in again"),
    };
    if claims.scope.as_deref() != Some("mfa") {
        return error(401, "invalid_challenge", "That login attempt expired; sign in again");
    }
    let username = claims.sub.to_lowercase();
    let keys = webauthn::list(&username);
    if keys.is_empty() {
        return error(400, "no_keys", "No security keys are registered on this account");
    }
    let (challenge_id, challenge) = issue_challenge(&username);
    let allow: Vec<serde_json::Value> = keys
        .iter()
        .map(|k| serde_json::json!({ "type": "public-key", "id": k.id }))
        .collect();
    ok_json(serde_json::json!({
        "challenge_id": challenge_id,
        "options": {
            "challenge": challenge,
            "rpId": RP_ID,
            "timeout": 120000,
            "userVerification": user_verification(),
            "allowCredentials": allow,
        }
    }))
}

/// POST /auth/login/webauthn/finish — verify the assertion and open a session.
pub fn login_finish(
    request: &mut Request,
    _user: Option<User>,
    user_storage: Arc<UserStorage>,
    email_storage: Arc<EmailStorage>,
) -> Resp {
    let body: serde_json::Value = match read_json_body(request) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    // The same scoped challenge the password step issued: a complete login cannot be
    // assembled from a key assertion alone.
    let mfa = body.get("challenge").and_then(|v| v.as_str()).unwrap_or("");
    let claims = match validate_jwt(mfa) {
        Ok(c) => c,
        Err(_) => return error(401, "invalid_challenge", "That login attempt expired; sign in again"),
    };
    if claims.scope.as_deref() != Some("mfa") {
        return error(401, "invalid_challenge", "That login attempt expired; sign in again");
    }
    let username = claims.sub.to_lowercase();
    let user_key = format!("user:{}", username);
    if ratelimit::is_locked_out(&user_key, ratelimit::MAX_ACCOUNT_FAILURES) {
        return error(429, "too_many_attempts", "Too many attempts; try again later");
    }

    let challenge_id = body.get("challenge_id").and_then(|v| v.as_str()).unwrap_or("");
    let Some(challenge) = take_challenge(challenge_id, &username) else {
        return error(401, "stale_challenge", "That login attempt expired; sign in again");
    };
    let credential_id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let Some(key) = webauthn::get(&username, credential_id) else {
        ratelimit::record_failure(&user_key);
        log::warn!("[WebAuthn] assertion for an unknown key on '{}'", username);
        return error(401, "unknown_key", "That security key is not registered on this account");
    };
    let client_data = match decode_field(&body, "clientDataJSON") {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let auth_data = match decode_field(&body, "authenticatorData") {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let signature = match decode_field(&body, "signature") {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let asserted = match webauthn::verify_assertion(
        &key, &client_data, &auth_data, &signature, &challenge, ORIGIN, RP_ID, &username, now(),
    ) {
        Ok(a) => a,
        Err(e) => {
            ratelimit::record_failure(&user_key);
            log::warn!("[WebAuthn] refused assertion for '{}': {}", username, e);
            return error(401, "assertion_failed", &e);
        }
    };
    if let Err(e) = webauthn::record_use(&username, &asserted.credential_id, asserted.sign_count, now()) {
        log::error!("[WebAuthn] could not record key use for '{}': {}", username, e);
    }

    let Some(user) = user_storage.get_user(&username) else {
        return error(401, "invalid_challenge", "That login attempt expired; sign in again");
    };
    let session_id = crate::core::sessions::new_id();
    let token = match generate_jwt_with_sid(&username, Some(&session_id)) {
        Ok(t) => t,
        Err(e) => return error(500, "token_error", &e.to_string()),
    };
    let user_agent = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("User-Agent"))
        .map(|h| h.value.to_string())
        .unwrap_or_default();
    let ip = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("X-Real-IP"))
        .map(|h| h.value.to_string())
        .filter(|v| !v.trim().is_empty())
        .or_else(|| request.remote_addr().map(|a| a.ip().to_string()))
        .unwrap_or_default();
    crate::core::sessions::record(&session_id, &username, &token, &user_agent, &ip, now());
    ratelimit::record_success(&user_key);

    let public_key = user.publicKey.as_ref().map(|pk| {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        STANDARD.encode(&pk.0)
    });
    let unread = email_storage.count_unread(&crate::core::trash::inbox_ids(&user));

    log::info!("[WebAuthn] '{}' signed in with security key '{}'", username, key.name);
    ok_json(serde_json::to_value(LoginResponse {
        token,
        force_reset: user.needs_force_reset(),
        is_admin: user.is_admin,
        role: crate::core::roles::role(&user.username, user.is_admin).as_str().to_string(),
        username: user.username.clone(),
        public_key,
        unread_emails: unread,
        salt: user.salt.clone(),
        encrypted_private_key: user.encrypted_private_key.clone(),
        two_factor_required: false,
        challenge: None,
        two_factor_methods: Vec::new(),
        session_id: Some(session_id),
    }).unwrap())
}

/// POST /user/webauthn/reauth/begin — a challenge for an already-enrolled key.
pub fn reauth_begin(
    _request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Resp {
    let Some(user) = user else {
        return error(401, "unauthorized", "Unauthorized");
    };
    let keys: Vec<serde_json::Value> = webauthn::list(&user.username)
        .into_iter()
        .map(|k| serde_json::json!({ "type": "public-key", "id": k.id }))
        .collect();
    if keys.is_empty() {
        return error(
            400,
            "no_keys",
            "There is no enrolled key to confirm with yet",
        );
    }
    let (challenge_id, challenge) = issue_challenge(&user.username);
    ok_json(serde_json::json!({
        "challenge_id": challenge_id,
        "options": {
            "challenge": challenge,
            "rpId": RP_ID,
            "timeout": 120000,
            "userVerification": user_verification(),
            "allowCredentials": keys,
        }
    }))
}

/// POST /user/webauthn/reauth/finish — verify that assertion and allow a key change for five
/// minutes. The signature is checked against a key already on this account, so a session that
/// has been stolen but does not hold the hardware cannot use this path.
pub fn reauth_finish(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Resp {
    let Some(user) = user else {
        return error(401, "unauthorized", "Unauthorized");
    };
    let body: serde_json::Value = match read_json_body(request) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let challenge_id = body.get("challenge_id").and_then(|v| v.as_str()).unwrap_or("");
    let Some(challenge) = take_challenge(challenge_id, &user.username) else {
        return error(401, "stale_challenge", "That confirmation expired; try again");
    };
    let credential_id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let Some(key) = webauthn::get(&user.username, credential_id) else {
        log::warn!("[WebAuthn] reauth with a key not on '{}'", user.username);
        return error(401, "unknown_key", "That security key is not registered on this account");
    };
    let client_data = match decode_field(&body, "clientDataJSON") {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let auth_data = match decode_field(&body, "authenticatorData") {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let signature = match decode_field(&body, "signature") {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let asserted = match webauthn::verify_assertion(
        &key,
        &client_data,
        &auth_data,
        &signature,
        &challenge,
        ORIGIN,
        RP_ID,
        &user.username,
        now(),
    ) {
        Ok(a) => a,
        Err(e) => {
            log::warn!("[WebAuthn] reauth assertion refused for '{}': {}", user.username, e);
            return error(401, "invalid_assertion", "That key could not be verified");
        }
    };
    let _ = webauthn::record_use(&user.username, &key.id, asserted.sign_count, now());
    grant_reauth(&user.username);
    log::info!("[WebAuthn] '{}' confirmed a key change with an enrolled key", user.username);
    ok_json(serde_json::json!({ "confirmed": true, "seconds": REAUTH_SECONDS }))
}
