//! Telling a suspended person why, when the only channel left is another mailbox.
//!
//! The account cannot read its own mail while switched off, and the mail server container
//! has no sendmail, so the notice cannot be sent from inside this process. Instead the
//! server writes a request into `data/notify-outbox/` and the host drains it — the same
//! pattern the owner console already uses to ask the watchdog for a test alert.
//!
//! **Only the recovery address is used.** If the account has none, nothing is written: this
//! is a courtesy, not a second channel to invent. Writing to the suspended mailbox itself
//! would be a message the person cannot read until the suspension is over, which is not a
//! notification at all.
//!
//! Files are written beside and renamed, so a half-written request can never be sent.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::PathBuf;

pub const DIR: &str = "data/notify-outbox";

#[derive(Serialize, Deserialize)]
pub struct Request {
    pub to: String,
    pub subject: String,
    pub body: String,
    /// Unix time it was written, so the host drain can drop anything stale rather than
    /// mail somebody about a suspension that ended days ago.
    pub at: u64,
}

/// Queue a suspension notice for the account's recovery address. Returns the address used,
/// or `None` when there is nothing to send to.
pub fn suspension(username: &str, reason: &str, until: Option<u64>) -> io::Result<Option<String>> {
    let entry = crate::core::recovery::store().get(username);
    let Some(to) = entry.email.filter(|e| !e.trim().is_empty()) else {
        return Ok(None);
    };

    // A recovery address on the account itself is undeliverable while the account is off:
    // the mail server refuses it at SMTP ("Mailbox is switched off"), which is exactly what
    // a real test of this did. The notice only has a route if it leaves this mailbox.
    if to.trim().to_ascii_lowercase().starts_with(&format!("{}@", username.to_ascii_lowercase())) {
        log::info!(
            "[Admin] Recovery address for '{}' is the account itself; no notice can be delivered",
            username
        );
        return Ok(None);
    }

    let mut body = format!(
        "The account '{username}' on this mail server has been switched off.\n\n"
    );
    if !reason.trim().is_empty() {
        body.push_str(&format!("Reason given: {}\n", reason.trim()));
    }
    match until {
        Some(stamp) => body.push_str(&format!(
            "It lifts automatically on {}.\n",
            crate::utils::dates::utc_date(stamp)
        )),
        None => body.push_str("It stays off until an administrator switches it back on.\n"),
    }
    body.push_str(
        "\nYour messages are not deleted and nothing has been lost: the mailbox, its key and \
         every message stay where they are.\n\n\
         If you believe this is a mistake, reply to this address.\n",
    );

    let request = Request {
        to: to.clone(),
        subject: format!("Your account {username} has been switched off"),
        body,
        at: crate::core::audit::now(),
    };

    let dir = PathBuf::from(DIR);
    fs::create_dir_all(&dir)?;
    let name = format!("{}-{}.json", crate::core::audit::now(), username);
    let path = dir.join(name);
    let tmp = path.with_extension("tmp");
    let bytes = serde_json::to_vec_pretty(&request)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, &path)?;
    Ok(Some(to))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_round_trips() {
        let dir = std::env::temp_dir().join(format!("notify-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("x.json");
        let req = Request {
            to: "a@b.c".into(),
            subject: "s".into(),
            body: "b".into(),
            at: 1,
        };
        fs::write(&path, serde_json::to_vec(&req).unwrap()).unwrap();
        let back: Request = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(back.to, "a@b.c");
        let _ = fs::remove_dir_all(&dir);
    }
}
