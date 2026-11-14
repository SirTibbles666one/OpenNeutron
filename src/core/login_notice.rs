//! Tell an account holder when a browser they have not used before signs in.
//!
//! The notice is composed and stored by the server, so it never reads the
//! account's mail — it writes one message of its own into the mailbox, through
//! the same encrypt-then-save path as a delivered message. If the account has no
//! public key there is nothing to encrypt to, and a security notice sitting on
//! disk in the clear is worse than no notice, so nothing is sent.

use std::fs;
use std::path::PathBuf;

use crate::core::{Email, EmailStorage, UserStorage};
use crate::smtp::ReceivedEmail;
use crate::utils::emailutils;
use crate::utils::mailer;

/// One notice an hour per account. A script that signs in repeatedly must not be
/// able to bury a real notice under its own noise.
const MIN_INTERVAL_SECS: u64 = 3600;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn stamp_path(username: &str) -> PathBuf {
    PathBuf::from(format!("data/login_notice/{}.last", username))
}

/// Send a sign-in notice, unless one went out in the last hour.
pub fn maybe_send(
    username: &str,
    user_agent: &str,
    ip: &str,
    user_storage: &UserStorage,
    email_storage: &EmailStorage,
) {
    let stamp = stamp_path(username);
    if let Ok(raw) = fs::read_to_string(&stamp) {
        if let Ok(last) = raw.trim().parse::<u64>() {
            if now().saturating_sub(last) < MIN_INTERVAL_SECS {
                return;
            }
        }
    }

    let Some(user) = user_storage.get_user(username) else {
        return;
    };
    if user.publicKey.is_none() {
        log::info!(
            "[Notice] '{}' signed in from a new device, but the account has no key - no notice stored",
            username
        );
        return;
    }

    let domain = emailutils::get_server_domain();
    let to = format!("{}@{}", username, user_storage.domain);
    let browser = describe(user_agent);
    let where_from = match crate::core::geoip::country(ip) {
        Some(country) => format!("{} ({})", ip, country),
        None => ip.to_string(),
    };

    let body = format!(
        "A browser that has not signed in to this mailbox before just did.\n\n\
         Browser:   {browser}\n\
         Address:   {where_from}\n\
         When:      {when}\n\n\
         If this was you, there is nothing to do.\n\n\
         If it was not, open Settings, then Signed-in devices, and end every session.\n\
         Then change your password: whoever signed in can read the mailbox until the\n\
         session is ended.\n",
        browser = browser,
        where_from = where_from,
        when = mailer::rfc2822_now(),
    );

    let msgid = crate::core::user::gen_setup_token();
    let raw = format!(
        "From: Sloth Mail <no-reply@{domain}>\r\n\
         To: {to}\r\n\
         Subject: New sign-in to your mailbox\r\n\
         Date: {date}\r\n\
         Message-ID: <notice-{msgid}@{domain}>\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: 8bit\r\n\
         Auto-Submitted: auto-generated\r\n\
         \r\n\
         {body}",
        domain = domain,
        to = to,
        date = mailer::rfc2822_now(),
        msgid = msgid,
        body = body,
    );

    let mut received = ReceivedEmail::new();
    received.from = format!("no-reply@{}", domain);
    received.to = vec![to];
    received.content = body;
    received.raw_data = raw.into_bytes();

    let email = match Email::try_new(received, &user) {
        Ok(e) => e,
        Err(e) => {
            log::warn!("[Notice] could not store the sign-in notice for '{}': {}", username, e);
            return;
        }
    };

    if let Err(e) = email_storage.save_email(&email) {
        log::warn!("[Notice] could not save the sign-in notice for '{}': {}", username, e);
        return;
    }

    user_storage.mutate_user(username, |u| {
        if !u.emailIds.contains(&email.uid) {
            u.emailIds.push(email.uid);
        }
    });
    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[Notice] stored the notice but could not persist '{}': {}", username, e);
    }

    if let Some(parent) = stamp.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&stamp, now().to_string());

    log::info!("[Notice] sign-in notice stored for '{}' ({})", username, browser);
}

/// A browser name a person recognises, from the user agent they sent.
fn describe(user_agent: &str) -> String {
    let ua = user_agent.to_ascii_lowercase();
    let browser = if ua.contains("edg/") {
        "Edge"
    } else if ua.contains("opr/") || ua.contains("opera") {
        "Opera"
    } else if ua.contains("firefox") {
        "Firefox"
    } else if ua.contains("chrome") || ua.contains("crios") {
        "Chrome"
    } else if ua.contains("safari") {
        "Safari"
    } else {
        "an unrecognised client"
    };
    let platform = if ua.contains("android") {
        "Android"
    } else if ua.contains("iphone") || ua.contains("ipad") || ua.contains("ios") {
        "iOS"
    } else if ua.contains("windows") {
        "Windows"
    } else if ua.contains("mac os") || ua.contains("macintosh") {
        "macOS"
    } else if ua.contains("linux") {
        "Linux"
    } else {
        "an unknown system"
    };
    format!("{} on {}", browser, platform)
}

#[cfg(test)]
mod tests {
    use super::describe;

    #[test]
    fn names_the_browser_and_the_platform() {
        let ua = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/131.0 Mobile Safari/537.36";
        assert_eq!(describe(ua), "Chrome on Android");
    }

    #[test]
    fn does_not_pretend_to_know_an_unknown_client() {
        assert_eq!(describe("curl/8.5.0"), "an unrecognised client on an unknown system");
    }
}
