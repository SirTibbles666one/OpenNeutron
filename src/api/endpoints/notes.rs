//! Sealed notes over HTTP.
//!
//! Three public-ish pieces and one authenticated:
//! - `POST /api/note/create`  (session)  mint a note from armour the client built
//! - `GET  /api/note?t=…`     (public)   the page: a summary, then a button
//! - `POST /api/note/open`    (public)   hand over the armour, once
//! - `POST /api/note/status`  (session)  sender's view of their notes
//!
//! The page is separate from the open call on purpose. Providers and security
//! scanners fetch links to look at them; if a GET consumed the note, a robot
//! would burn it before the recipient ever saw it. Only the button burns it.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tiny_http::{Header, Request, Response, Method};
use std::io::Cursor;

use crate::api::dto::json_header;
use crate::api::request::read_json_body;
use crate::core::{notes, User, UserStorage, EmailStorage};

#[derive(Deserialize)]
struct CreateRequest {
    recipient: String,
    #[serde(default)]
    subject: String,
    /// PGP armour, produced by the sender's browser. Never logged.
    armored: String,
    /// Delete as soon as it is opened. A note is always single-use, so this only
    /// decides whether the *notification* says so.
    #[serde(default)]
    deletes_on_read: bool,
    /// "pgp" (default) seals to the recipient's key; "passphrase" seals to a
    /// phrase the sender shares separately, for recipients without a key.
    #[serde(default)]
    mode: Option<String>,
    /// Seconds until the timer clears it, regardless of opens.
    #[serde(default)]
    expires_in_seconds: Option<u64>,
    /// Attachments, each already encrypted to the same secret as the body. Only
    /// for passphrase notes: the page that can read the body can decrypt them in
    /// the same place, with the same phrase.
    #[serde(default)]
    files: Vec<FileInput>,
}

#[derive(Deserialize)]
struct FileInput {
    name: String,
    armored: String,
    #[serde(default)]
    size: u64,
}

/// Caps that keep one note from becoming a file host: five attachments, and the
/// armour of all of them together under six megabytes.
const MAX_FILES: usize = 5;
const MAX_FILES_ARMOR: usize = 6_000_000;

/// A display name, never a path: separators and control characters removed, and
/// short enough to render in a list.
fn safe_name(raw: &str) -> String {
    // Only the last segment survives: "../evil/x" and "C:\\tmp\\x" both reduce to
    // "x", so nothing here can name a path the recipient's browser would follow.
    let last = raw.rsplit(|c| c == '/' || c == '\\').next().unwrap_or(raw);
    let cleaned: String = last
        .chars()
        .filter(|c| !c.is_control() && *c != '/' && *c != '\\' && *c != ':')
        .collect();
    let trimmed = cleaned.trim().trim_start_matches('.').trim();
    let name = if trimmed.is_empty() { "attachment" } else { trimmed };
    name.chars().take(80).collect()
}

#[derive(Serialize)]
struct CreateResponse {
    token: String,
    url: String,
    expires_at: Option<u64>,
    deletes_on_read: bool,
    mode: String,
}

#[derive(Deserialize)]
struct OpenRequest {
    token: String,
}

#[derive(Deserialize)]
struct StatusRequest {
    tokens: Vec<String>,
}

#[derive(Serialize)]
struct StatusItem {
    token: String,
    state: String,
    subject: String,
    recipient: String,
    mode: String,
    created_at: u64,
    opened_at: Option<u64>,
    expires_at: Option<u64>,
    revoked_at: Option<u64>,
}

fn json_error(status: u16, code: &str, message: &str) -> Response<Cursor<Vec<u8>>> {
    let body = serde_json::to_vec(&json!({ "error": message, "code": code })).unwrap_or_default();
    Response::from_data(body).with_status_code(status).with_header(json_header())
}

fn html_header() -> Header {
    Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap()
}

fn no_store_header() -> Header {
    Header::from_bytes(&b"Cache-Control"[..], &b"no-store, no-cache, must-revalidate"[..]).unwrap()
}

/// Keeps the token out of any Referer header a link inside the page might set.
fn referrer_header() -> Header {
    Header::from_bytes(&b"Referrer-Policy"[..], &b"no-referrer"[..]).unwrap()
}

fn nosniff_header() -> Header {
    Header::from_bytes(&b"X-Content-Type-Options"[..], &b"nosniff"[..]).unwrap()
}

fn html(body: String, status: u16) -> Response<Cursor<Vec<u8>>> {
    Response::from_data(body.into_bytes())
        .with_status_code(status)
        .with_header(html_header())
        .with_header(no_store_header())
        .with_header(referrer_header())
        .with_header(nosniff_header())
}

/// Where the link should point. `server.public_url` wins because the API is
/// reached through a proxy whose Host header is not always the public name.
fn base_url(request: &Request) -> String {
    if let Some(url) = crate::config::get().server.public_url.as_ref() {
        let trimmed = url.trim().trim_end_matches('/');
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    for header in request.headers() {
        if header.field.equiv("Host") {
            let host = header.value.as_str().trim();
            if !host.is_empty() {
                return format!("https://{}", host);
            }
        }
    }
    format!("https://{}", crate::utils::emailutils::get_server_domain())
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn query_param(url: &str, key: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    for pair in query.split('&') {
        let (k, v) = match pair.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        if k == key {
            return Some(percent_decode(v));
        }
    }
    None
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Human date for the page. Deliberately UTC and unambiguous.
fn stamp(secs: u64) -> String {
    crate::utils::unix_to_iso(secs)
        .replace('T', " ")
        .chars()
        .take(16)
        .collect::<String>()
        + " UTC"
}

pub fn create(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return json_error(401, "unauthorized", "Unauthorized"),
    };

    let req: CreateRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    if req.recipient.trim().is_empty() {
        return json_error(400, "missing_recipient", "A sealed note needs a recipient");
    }
    let armored = req.armored.trim();
    if armored.is_empty() {
        return json_error(400, "empty_note", "A sealed note needs an encrypted body");
    }
    if !armored.starts_with("-----BEGIN PGP MESSAGE-----") {
        // Anything else is not armour we can protect: refuse rather than store
        // a body the sender believes is sealed and is not.
        return json_error(400, "not_armored", "The sealed body must be PGP armour");
    }
    if armored.len() > notes::MAX_ARMORED_BYTES {
        return json_error(413, "note_too_large", "A sealed note is a message body, not an attachment");
    }

    let mode = match req.mode.as_deref() {
        None | Some("") | Some("pgp") => "pgp".to_string(),
        Some("passphrase") => "passphrase".to_string(),
        Some(other) => {
            return json_error(400, "bad_mode", &format!("Unknown note mode '{}'", other));
        }
    };

    let now = notes::now();
    let expires_at = match req.expires_in_seconds {
        Some(secs) => {
            let secs = secs.clamp(notes::MIN_EXPIRY_SECONDS, notes::MAX_EXPIRY_SECONDS);
            Some(now + secs)
        }
        None => None,
    };

    // Attachments only travel with a passphrase note: in key mode the page hands
    // the recipient armour for their own client, and asking them to decrypt five
    // more files by hand would be worse than refusing.
    if !req.files.is_empty() && mode != "passphrase" {
        return json_error(
            400,
            "files_need_passphrase",
            "Attachments need the passphrase lock — switch the seal to a passphrase to send files",
        );
    }
    if req.files.len() > MAX_FILES {
        return json_error(400, "too_many_files", &format!("At most {} attachments per note", MAX_FILES));
    }
    let total_armor: usize = req.files.iter().map(|f| f.armored.len()).sum();
    if total_armor > MAX_FILES_ARMOR {
        return json_error(413, "files_too_large", "Those attachments are too large for one note");
    }

    if notes::active_count(user.uid) >= notes::MAX_ACTIVE_PER_SENDER {
        return json_error(429, "too_many_notes", "Too many unopened notes; open or cancel some first");
    }

    let token = notes::new_token();
    let note = notes::Note {
        token: token.clone(),
        owner: user.username.clone(),
        owner_uid: user.uid,
        recipient: req.recipient.trim().to_string(),
        subject: req.subject.clone(),
        mode: mode.clone(),
        fetches: 0,
        armored: armored.to_string(),
        files: req
            .files
            .iter()
            .map(|f| notes::NoteFile {
                name: safe_name(&f.name),
                armored: f.armored.clone(),
                size: f.size,
            })
            .collect(),
        created_at: now,
        expires_at,
        opened_at: None,
        expired_at: None,
        revoked_at: None,
        opens: 0,
        sender_uid: 0,
    };

    if let Err(e) = notes::create(note) {
        log::error!("[Notes] Could not store a note for {}: {}", user.username, e);
        return json_error(500, "store_failed", "Could not store the note");
    }

    let url = format!("{}/api/note?t={}", base_url(request), token);
    let body = serde_json::to_vec(&CreateResponse {
        mode,
        token,
        url,
        expires_at,
        deletes_on_read: req.deletes_on_read,
    })
    .unwrap_or_default();
    Response::from_data(body).with_status_code(200).with_header(json_header())
}

/// The page. Renders the current state without consuming anything.
pub fn page(
    request: &mut Request,
    _user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let token = match query_param(request.url(), "t") {
        Some(t) if !t.is_empty() => t,
        _ => return html(render_missing(), 404),
    };

    let note = match notes::get(&token) {
        Some(n) => n,
        None => return html(render_missing(), 404),
    };

    if note.is_revoked() {
        return html(render_gone("This note was withdrawn", "The sender took it back before it was read."), 410);
    }
    if note.expired_at.is_some() || (note.is_sealed() && note.is_expired(notes::now())) {
        let when = note.expires_at.map(stamp).unwrap_or_default();
        return html(render_gone("This note expired", &format!("It was closed on {}.", when)), 410);
    }
    if note.opened_at.is_some() {
        let when = note.opened_at.map(stamp).unwrap_or_default();
        return html(render_gone("This note has already been opened", &format!("It was opened on {} and deleted.", when)), 410);
    }

    let expiry = match note.expires_at {
        Some(at) => format!("This note closes on {}.", stamp(at)),
        None => "This note does not expire on its own; opening it deletes it.".to_string(),
    };
    html(render_sealed(&note.subject, &note.owner, &note.recipient, &expiry, &token, &note.mode), 200)
}

pub fn open(
    request: &mut Request,
    _user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let req: OpenRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    match notes::open(&req.token) {
        Ok(notes::Open::Served(note)) => {
            let body = serde_json::to_vec(&json!({
                "armored": note.armored,
                "from": note.owner,
                "subject": note.subject,
                "recipient": note.recipient,
                "created_at": note.created_at,
                "files": note
                    .files
                    .iter()
                    .map(|f| json!({ "name": f.name, "armored": f.armored, "size": f.size }))
                    .collect::<Vec<_>>(),
                "deleted": true,
            }))
            .unwrap_or_default();
            let mut response = Response::from_data(body).with_header(json_header());
            response.add_header(no_store_header());
            response
        }
        Ok(notes::Open::Spent) => json_error(410, "already_opened", "This note has already been opened and deleted"),
        Ok(notes::Open::Expired) => json_error(410, "expired", "This note expired before it was opened"),
        Ok(notes::Open::Missing) => json_error(404, "no_such_note", "There is no note at this address"),
        Err(e) => {
            log::error!("[Notes] Open failed: {}", e);
            json_error(500, "store_failed", "Could not open the note")
        }
    }
}

/// Clear a passphrase note once the recipient has read it. Called by the page
/// after a successful decrypt; harmless if it arrives twice.
pub fn burn(
    request: &mut Request,
    _user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    #[derive(Deserialize)]
    struct BurnRequest {
        token: String,
    }
    let req: BurnRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match notes::burn(&req.token) {
        Ok(_) => {
            let body = serde_json::to_vec(&json!({ "burned": true })).unwrap_or_default();
            Response::from_data(body).with_status_code(200).with_header(json_header())
        }
        Err(e) => {
            log::error!("[Notes] Burn failed: {}", e);
            json_error(500, "store_failed", "Could not burn the note")
        }
    }
}

/// Withdraw a note. Only the account that created it can, and only before it
/// has been read — after that there is nothing left to withdraw.
pub fn revoke(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return json_error(401, "unauthorized", "Unauthorized"),
    };
    #[derive(Deserialize)]
    struct RevokeRequest {
        token: String,
    }
    let req: RevokeRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    match notes::revoke(&req.token, user.uid) {
        Ok(true) => {
            let body = serde_json::to_vec(&json!({ "revoked": true })).unwrap_or_default();
            Response::from_data(body).with_status_code(200).with_header(json_header())
        }
        // Already opened, already revoked, or not the caller's: the same answer,
        // so a caller cannot use this to learn whether a token exists.
        Ok(false) => json_error(409, "not_revocable", "That note is already read, withdrawn, or not yours"),
        Err(e) => {
            log::error!("[Notes] Revoke failed: {}", e);
            json_error(500, "store_failed", "Could not withdraw the note")
        }
    }
}

pub fn status(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => return json_error(401, "unauthorized", "Unauthorized"),
    };
    let req: StatusRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if req.tokens.len() > 200 {
        return json_error(400, "too_many", "Ask about at most 200 notes at a time");
    }

    let items: Vec<StatusItem> = notes::statuses(user.uid, &req.tokens)
        .into_iter()
        .map(|n| StatusItem {
            state: n.state().to_string(),
            token: n.token,
            subject: n.subject,
            recipient: n.recipient,
            mode: n.mode,
            created_at: n.created_at,
            opened_at: n.opened_at,
            expires_at: n.expires_at,
            revoked_at: n.revoked_at,
        })
        .collect();

    let body = serde_json::to_vec(&json!({ "notes": items })).unwrap_or_default();
    Response::from_data(body).with_status_code(200).with_header(json_header())
}

// ---- page rendering -------------------------------------------------------

const PAGE_CSS: &str = r#"
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body {
  margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
  background: radial-gradient(circle at 50% 0%, #12261c 0%, #0a0f0c 55%, #060907 100%);
  color: #e7f0ea; font: 15px/1.5 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  padding: 20px;
}
.card {
  width: 100%; max-width: 520px; background: rgba(18, 26, 21, .92);
  border: 1px solid rgba(80, 220, 140, .18); border-radius: 18px;
  padding: 26px 22px; box-shadow: 0 24px 60px rgba(0,0,0,.55);
}
.seal {
  width: 46px; height: 46px; border-radius: 14px; display: grid; place-items: center;
  background: rgba(80, 220, 140, .12); border: 1px solid rgba(80, 220, 140, .3);
  margin-bottom: 16px; font-size: 22px;
}
h1 { font-size: 19px; margin: 0 0 6px; letter-spacing: -.01em; }
.sub { color: #9db3a6; font-size: 13px; margin: 0 0 18px; }
.meta { font-size: 12.5px; color: #8fa79a; border-top: 1px solid rgba(255,255,255,.07); padding-top: 14px; margin-top: 18px; }
.meta b { color: #cfe3d7; font-weight: 600; }
button {
  width: 100%; padding: 14px 16px; font-size: 15px; font-weight: 650; color: #05130b;
  background: linear-gradient(180deg, #56e29a, #2fbf7a); border: 0; border-radius: 12px;
  cursor: pointer; transition: transform .12s ease, filter .12s ease;
}
button:hover { filter: brightness(1.06); }
button:active { transform: scale(.985); }
button:disabled { opacity: .6; cursor: default; }
pre {
  white-space: pre-wrap; word-break: break-all; background: #0b120e; border: 1px solid rgba(255,255,255,.08);
  border-radius: 12px; padding: 14px; font-size: 11.5px; line-height: 1.45; color: #bfe6cd;
  max-height: 46vh; overflow: auto; margin: 0 0 14px;
}
.warn { color: #f3c07b; font-size: 12.5px; margin: 12px 0 0; }
.label { display: block; font-size: 12px; color: #9db3a6; margin: 0 0 6px; }
input[type=password], input[type=text] {
  width: 100%; padding: 13px 14px; font-size: 15px; color: #e7f0ea;
  background: #0b120e; border: 1px solid rgba(255,255,255,.12); border-radius: 12px;
  margin-bottom: 12px; outline: none;
}
input[type=password]:focus, input[type=text]:focus { border-color: rgba(80,220,140,.55); }
.row { display: flex; gap: 10px; margin-bottom: 6px; }
.row button { flex: 1; }
button.ghost {
  background: transparent; color: #56e29a; border: 1px solid rgba(80,220,140,.35);
}
.gone { color: #9db3a6; }
a { color: #56e29a; }
"#;

fn shell(title: &str, inner: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"robots\" content=\"noindex, nofollow\">\
         <title>{}</title><style>{}</style></head><body><div class=\"card\">{}</div></body></html>",
        escape(title),
        PAGE_CSS,
        inner
    )
}

fn render_missing() -> String {
    shell(
        "No such note",
        "<div class=\"seal\">🔒</div><h1>There is no note at this address</h1>\
         <p class=\"sub gone\">The link may be mistyped, or the note may have been deleted after it was read.</p>",
    )
}

fn render_gone(headline: &str, detail: &str) -> String {
    shell(
        headline,
        &format!(
            "<div class=\"seal\">🔒</div><h1>{}</h1><p class=\"sub gone\">{}</p>\
             <div class=\"meta\">Nothing is stored on the server: the content was deleted when the note was closed.</div>",
            escape(headline),
            escape(detail)
        ),
    )
}

/// Shared script: the open call, minus what each mode does with the armour.
const OPEN_JS: &str = r#"
async function fetchNote() {
  const r = await fetch('/api/note/open', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: '__TOKEN__' }),
  });
  const d = await r.json();
  if (!r.ok) throw new Error(d.error || 'Could not open the note');
  return d;
}
"#;

/// Key mode: the recipient already has a private key, so hand over the armour
/// and get out of the way — with a file they can hand to their PGP app.
const PGP_JS: &str = r#"
const btn = document.getElementById('reveal');
btn.addEventListener('click', async () => {
  btn.disabled = true; btn.textContent = 'Opening…';
  try {
    const d = await fetchNote();
    const armor = d.armored;
    document.getElementById('armor').textContent = armor;
    document.getElementById('out').hidden = false;
    btn.remove();
    document.getElementById('copy').addEventListener('click', async () => {
      const el = document.getElementById('copy');
      try { await navigator.clipboard.writeText(armor); el.textContent = 'Copied'; }
      catch (e) { el.textContent = 'Select the text and copy'; }
    });
    document.getElementById('save').addEventListener('click', () => {
      const blob = new Blob([armor], { type: 'application/pgp-encrypted' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'sealed-note.asc';
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    });
  } catch (e) {
    btn.disabled = false; btn.textContent = 'Try again';
    document.getElementById('msg').textContent = e.message;
  }
});
"#;

/// Passphrase mode: no key, no client — one field and the note is readable on
/// any device. The armour stays on the server until the phrase is right, so a
/// typo costs nothing, and is burned the moment the text appears.
const PASS_JS: &str = r#"
const btn = document.getElementById('reveal');
const phrase = document.getElementById('phrase');
btn.addEventListener('click', async () => {
  const pass = (phrase.value || '').trim();
  const msg = document.getElementById('msg');
  if (pass.length < 4) { msg.textContent = 'Type the passphrase you were given.'; return; }
  btn.disabled = true; btn.textContent = 'Opening…';
  try {
    const d = await fetchNote();
    let text;
    try {
      const message = await openpgp.readMessage({ armoredMessage: d.armored });
      const out = await openpgp.decrypt({ message, passwords: [pass] });
      text = out.data;
    } catch (e) {
      btn.disabled = false; btn.textContent = 'Read the note';
      msg.textContent = 'That is not the passphrase — check it and try again. The note is still here.';
      return;
    }
    document.getElementById('text').textContent = text;
    document.getElementById('out').hidden = false;
    document.getElementById('form').hidden = true;

    // Attachments came in the same response, encrypted to the same phrase. The
    // bytes are already here, so nothing is fetched after this: the note is
    // burned below and the page still holds everything it needs.
    const files = d.files || [];
    if (files.length) {
      const box = document.getElementById('files');
      const heading = document.createElement('p');
      heading.className = 'label';
      heading.textContent = files.length === 1 ? 'Attachment' : 'Attachments';
      box.appendChild(heading);
      for (const f of files) {
        const btn = document.createElement('button');
        const kb = f.size ? ' (' + Math.max(1, Math.round(f.size / 1024)) + ' KB)' : '';
        btn.textContent = 'Download ' + f.name + kb;
        btn.className = 'ghost file';
        btn.addEventListener('click', async () => {
          const label = btn.textContent;
          btn.disabled = true;
          btn.textContent = 'Opening…';
          try {
            const m = await openpgp.readMessage({ armoredMessage: f.armored });
            const out = await openpgp.decrypt({ message: m, passwords: [pass], format: 'binary' });
            const blob = new Blob([out.data], { type: 'application/octet-stream' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = f.name;
            document.body.appendChild(a);
            a.click();
            a.remove();
            setTimeout(() => URL.revokeObjectURL(url), 60000);
            btn.textContent = 'Saved';
          } catch (e) {
            btn.disabled = false;
            btn.textContent = label;
            document.getElementById('msg').textContent = 'That file could not be opened: ' + e.message;
          }
        });
        box.appendChild(btn);
      }
    }
    fetch('/api/note/burn', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: '__TOKEN__' }),
    });
  } catch (e) {
    btn.disabled = false; btn.textContent = 'Try again';
    msg.textContent = e.message;
  }
});
"#;

fn render_sealed(subject: &str, from: &str, to: &str, expiry: &str, token: &str, mode: &str) -> String {
    let subject_line = if subject.trim().is_empty() {
        "A sealed note".to_string()
    } else {
        subject.trim().to_string()
    };
    let token_js = serde_json::to_string(token).unwrap_or_else(|_| "\"\"".to_string());
    let script = if mode == "passphrase" { PASS_JS } else { PGP_JS };
    let script = format!("{}\n{}", OPEN_JS, script).replace("__TOKEN__", token_js.trim_matches('"'));

    let form = if mode == "passphrase" {
        r#"<div id="form">
             <label class="label" for="phrase">Passphrase</label>
             <input id="phrase" type="password" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="The phrase the sender gave you">
             <button id="reveal">Read the note</button>
             <p class="warn">The phrase is not in the email. Ask the sender for it if you do not have it.</p>
           </div>"#
    } else {
        r#"<button id="reveal">Open the note</button>"#
    };

    let out = if mode == "passphrase" {
        r#"<div id="out" hidden>
             <pre id="text"></pre>
             <div id="files"></div>
             <p class="warn">Read it now — it has been deleted from the server.</p>
           </div>
           <p class="warn" id="msg"></p>"#
    } else {
        r#"<div id="out" hidden>
             <pre id="armor"></pre>
             <div class="row"><button id="copy">Copy</button><button id="save" class="ghost">Download .asc</button></div>
             <p class="warn">This is OpenPGP armour for your key. Your mail client may open the .asc directly; otherwise <code>gpg --decrypt</code> does it.</p>
           </div>
           <p class="warn" id="msg"></p>"#
    };

    let lede = if mode == "passphrase" {
        format!("A sealed note from <b>{}</b>, locked with a passphrase. This server cannot read it, and neither can any mail provider.", escape(from))
    } else {
        format!("A sealed note from <b>{}</b>, encrypted to your key. This server cannot read it.", escape(from))
    };

    let lib = if mode == "passphrase" {
        r#"<script src="/openpgp.min.js"></script>"#
    } else {
        ""
    };

    let inner = format!(
        r#"<div class="seal">🔒</div>
           <h1>{subject}</h1>
           <p class="sub">{lede}</p>
           {form}
           <div class="meta">
             <div>To <b>{to}</b></div>
             <div>{expiry}</div>
           </div>
           {out}
           {lib}
           <script>{script}</script>"#,
        subject = escape(&subject_line),
        lede = lede,
        form = form,
        to = escape(to),
        expiry = escape(expiry),
        out = out,
        lib = lib,
        script = script,
    );
    shell(&subject_line, &inner)
}

/// The page is also reachable with HEAD, so a scanner sees the same status code
/// without a body. Registered separately in `main.rs`.
pub fn page_head(
    request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let _ = Method::Get;
    let response = page(request, user, user_storage, email_storage);
    let status = response.status_code().0;
    Response::from_data(Vec::new()).with_status_code(status)
}

#[allow(dead_code)]
fn _assert_value_is_used(_: Value) {}
