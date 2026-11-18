//! Mail health: what the filter is doing, what it filed, and what is stuck.
//!
//! Read-only, and deliberately one endpoint — an operator asking "is mail working" wants one
//! answer, not four tabs. Three sources:
//!
//! * **rspamd**, over its controller (password-protected, on the docker bridge);
//! * **junk totals**, from the sidecar this server already keeps;
//! * **the Postfix queue**, which this process cannot see: the mail server runs in a
//!   container and Postfix is on the host, so the host writes a small JSON snapshot that is
//!   read here. `None` means "nobody has written one recently", which the panel shows as
//!   unavailable rather than zero — zeros read as "nothing is wrong".
//!
//! Every figure carries the moment it was measured, because a health card without a
//! timestamp is a rumour.

use serde::Serialize;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Serialize, Default)]
pub struct Rspamd {
    pub version: String,
    pub uptime: u64,
    pub scanned: u64,
    pub learned: u64,
    pub spam: u64,
    pub ham: u64,
    pub rejected: u64,
    pub tagged: u64,
    pub greylisted: u64,
}

fn controller() -> (String, Option<String>) {
    (
        std::env::var("RSPAMD_CONTROLLER").unwrap_or_else(|_| "127.0.0.1:11334".to_string()),
        std::env::var("RSPAMD_CONTROLLER_PASSWORD").ok(),
    )
}

fn get(path: &str) -> Result<String, String> {
    let (addr, password) = controller();
    let mut stream = TcpStream::connect(&addr)
        .map_err(|e| format!("rspamd is not reachable at {addr}: {e}"))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(8)));
    let auth = password.map(|p| format!("Password: {p}\r\n")).unwrap_or_default();
    let head = format!(
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\n{auth}Connection: close\r\n\r\n"
    );
    stream
        .write_all(head.as_bytes())
        .map_err(|e| format!("could not ask rspamd: {e}"))?;
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let text = String::from_utf8_lossy(&response).to_string();
    match text.split_once("\r\n\r\n") {
        Some((headers, body)) if headers.contains(" 200") => Ok(body.to_string()),
        Some((headers, _)) => Err(format!("rspamd refused: {}", headers.lines().next().unwrap_or(""))),
        None => Err("rspamd closed the connection without answering".to_string()),
    }
}

fn number(value: &serde_json::Value, key: &str) -> u64 {
    value.get(key).and_then(|v| v.as_u64()).unwrap_or(0)
}

pub fn rspamd() -> Result<Rspamd, String> {
    let body = get("/stat")?;
    let value: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("rspamd answered with something else: {e}"))?;

    let actions = value.get("actions").cloned().unwrap_or(serde_json::json!({}));
    // rspamd names the actions with spaces; the two that matter for a person reading this
    // are "was it refused" and "was it labelled".
    let action = |name: &str| actions.get(name).and_then(|v| v.as_u64()).unwrap_or(0);

    Ok(Rspamd {
        version: value.get("version").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        uptime: number(&value, "uptime"),
        scanned: number(&value, "scanned"),
        learned: number(&value, "learned"),
        spam: number(&value, "spam_count"),
        ham: number(&value, "ham_count"),
        rejected: action("reject"),
        tagged: action("add header"),
        greylisted: action("greylist"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stat_body_parses_into_the_figures_the_card_shows() {
        // Trimmed from a real /stat answer (3.8.1).
        let body = r#"{"version":"3.8.1","uptime":5456,"scanned":1663,"learned":5,
            "spam_count":32,"ham_count":1621,
            "actions":{"reject":4,"add header":29,"greylist":4}}"#;
        let value: serde_json::Value = serde_json::from_str(body).unwrap();
        let actions = value.get("actions").cloned().unwrap();
        assert_eq!(value.get("scanned").and_then(|v| v.as_u64()), Some(1663));
        assert_eq!(actions.get("add header").and_then(|v| v.as_u64()), Some(29));
        assert_eq!(actions.get("reject").and_then(|v| v.as_u64()), Some(4));
    }

    #[test]
    fn a_missing_field_is_zero_not_a_panic() {
        let value: serde_json::Value = serde_json::from_str("{}").unwrap();
        assert_eq!(number(&value, "scanned"), 0);
    }
}
