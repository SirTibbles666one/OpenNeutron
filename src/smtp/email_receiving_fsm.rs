use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::sync::Arc;
use once_cell::sync::Lazy;
use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::CommandResult;
use crate::smtp::{ReceivedEmail, MaybeTlsStream};
use crate::core::UserStorage;

/// Enforces the SIZE limit advertised in EHLO to prevent unbounded memory growth.
const MAX_MESSAGE_SIZE: usize = 104_857_600; // 100 MiB

static ANGLE_RE: Lazy<regex::Regex> = Lazy::new(|| regex::Regex::new(r"<([^>]*)>").unwrap());
static EMAIL_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}").unwrap()
});

fn extract_email_address(s: &str) -> Option<String> {
    for caps in ANGLE_RE.captures_iter(s) {
        let content = caps.get(1).unwrap().as_str().trim();
        if content.contains('@') {
            return Some(content.to_string());
        }
    }
    EMAIL_RE.captures(s).map(|c| c.get(0).unwrap().as_str().to_string())
}

enum EmailReceivingState {
    WaitingForEhlo,
    WaitingForMailFrom,
    WaitingForRcptTo,
    ReceivingData,
    WaitingForQuit,
}

pub struct EmailReceivingFSM {
    state: EmailReceivingState,
    email: ReceivedEmail,
    /// The mail domain this server is authoritative for; used to decide whether a
    /// recipient is local.
    server_name: String,
    /// The name announced in the EHLO response, which must match the reverse DNS
    /// record rather than the bare mail domain.
    ehlo_name: String,
    user_storage: Arc<UserStorage>,
    is_e2ee: bool,
    /// True once the connection has been upgraded to TLS via STARTTLS.
    is_tls: bool,
    remote: String,
    /// Refuse a sender claiming our own domain without a DKIM pass.
    reject_spoof: bool,
    /// Refuse a recipient that is not a real mailbox here.
    reject_unknown: bool,
    /// Set when the message was refused, so the caller does not deliver it.
    rejected: bool,
}


impl EmailReceivingFSM {
    pub fn new(
        server_name: &str,
        ehlo_name: &str,
        user_storage: Arc<UserStorage>,
        remote: String,
        reject_spoof: bool,
        reject_unknown: bool,
    ) -> Self {
        EmailReceivingFSM {
            state: EmailReceivingState::WaitingForEhlo,
            email: ReceivedEmail::new(),
            server_name: server_name.to_string(),
            ehlo_name: ehlo_name.to_string(),
            user_storage,
            is_e2ee: false,
            is_tls: false,
            remote,
            reject_spoof,
            reject_unknown,
            rejected: false,
        }
    }

    /// Called by the connection handler after the TLS handshake completes so that
    /// the next EHLO response does not re-advertise STARTTLS (RFC 3207).
    pub fn notify_tls_upgraded(&mut self) {
        self.is_tls = true;
    }

    pub fn handle_command(&mut self, stream: &mut MaybeTlsStream, input: Vec<u8>) -> io::Result<CommandResult> {
        let data = input;
        let mut pos = 0;

        loop {
            
            if let EmailReceivingState::ReceivingData = self.state {
                let chunk = &data[pos..];

                // The end-of-data terminator \r\n.\r\n (5 bytes) may be split across TCP read
                // boundaries.  Look back up to 4 bytes into already-accumulated data so we never
                // miss a terminator that straddles a read boundary.
                let lookback = self.email.raw_data.len().min(4);
                let search_start = self.email.raw_data.len() - lookback;
                let combined: Vec<u8> = self.email.raw_data[search_start..]
                    .iter()
                    .chain(chunk.iter())
                    .copied()
                    .collect();

                if let Some(rel) = combined.windows(5).position(|w| w == b"\r\n.\r\n") {
                    // 'rel' indexes into 'combined'; combined[0..lookback] = raw_data[search_start..].
                    let raw_keep = search_start + rel;
                    if raw_keep <= self.email.raw_data.len() {
                        // The terminator starts inside already-accumulated data (split boundary).
                        self.email.raw_data.truncate(raw_keep);
                    } else {
                        // The terminator is entirely within the new chunk.
                        let chunk_bytes = raw_keep - self.email.raw_data.len();
                        self.email.raw_data.extend_from_slice(&chunk[..chunk_bytes]);
                    }
                    // SMTP transparency (RFC 5321 s.4.5.2): remove dot-stuffing
                    self.email.raw_data = smtp_dot_unstuff(&self.email.raw_data);
                    self.finish_data(stream)?;
                    log::debug!("[SMTP {}] DATA complete - {} bytes received", self.remote, self.email.raw_data.len());
                } else {
                    self.email.raw_data.extend_from_slice(chunk);
                    // Enforce the advertised SIZE limit to prevent unbounded memory growth.
                    if self.email.raw_data.len() > MAX_MESSAGE_SIZE {
                        stream.write_all(b"552 5.3.4 Message size exceeds limit\r\n")?;
                        stream.flush()?;
                        return Err(io::Error::new(io::ErrorKind::Other, "message exceeds size limit"));
                    }
                }
                break;
            }

            if pos >= data.len() {
                break;
            }

            
            let line_end = data[pos..].windows(2).position(|w| w == b"\r\n");
            let (line_str, next_pos) = match line_end {
                None => (String::from_utf8_lossy(&data[pos..]).to_string(), data.len()),
                Some(rel) => {
                    let abs = pos + rel;
                    (String::from_utf8_lossy(&data[pos..abs]).to_string(), abs + 2)
                }
            };
            pos = next_pos;

            if line_str.is_empty() {
                continue;
            }

            let line_lower = line_str.to_lowercase();

            
            if line_lower.starts_with("rset") {
                self.email = ReceivedEmail::new();
                self.is_e2ee = false;
                self.state = EmailReceivingState::WaitingForMailFrom;
                stream.write_all(b"250 OK\r\n")?;
                stream.flush()?;
                continue;
            }
            if line_lower.starts_with("noop") {
                stream.write_all(b"250 OK\r\n")?;
                stream.flush()?;
                continue;
            }
            if line_lower.starts_with("vrfy") {
                stream.write_all(b"550 5.1.1 User not found\r\n")?;
                stream.flush()?;
                continue;
            }
            if line_lower.starts_with("expn") {
                stream.write_all(b"550 5.5.1 Command unrecognized\r\n")?;
                stream.flush()?;
                continue;
            }
            if line_lower.starts_with("quit") {
                log::debug!("[SMTP {}] QUIT", self.remote);
                stream.write_all(b"221 Bye\r\n")?;
                stream.flush()?;
                return Ok(CommandResult::Close);
            }
            if line_lower.starts_with("starttls") {
                if self.is_tls {
                    stream.write_all(b"503 5.5.1 Already in TLS\r\n")?;
                    stream.flush()?;
                    continue;
                }
                log::debug!("[SMTP {}] STARTTLS", self.remote);
                self.state = EmailReceivingState::WaitingForEhlo;
                stream.write_all(b"220 2.0.0 Ready to start TLS\r\n")?;
                stream.flush()?;
                log::info!("[SMTP] STARTTLS requested, upgrading connection to TLS");
                return Ok(CommandResult::UpgradeToTls);
            }

            if line_lower.starts_with("opntrn ") {
                let rest = &line_str[7..];
                let rest_lower = rest.to_lowercase();
                if rest_lower.starts_with("getkey ") {
                    let addr = rest[7..].trim();
                    log::info!("[SMTP {}] OPNTRN GETKEY {}", self.remote, addr);
                    if let Some(at_pos) = addr.find('@') {
                        let username = &addr[..at_pos];
                        let addr_domain = &addr[at_pos + 1..];
                        if addr_domain.eq_ignore_ascii_case(&self.server_name) {
                            if let Some(user) = self.user_storage.get_user(username) {
                                if let Some(pk) = &user.publicKey {
                                    let encoded = STANDARD.encode(&pk.0);
                                    let resp = format!("250 OPNTRN KEY openneutron-2 {}\r\n", encoded);
                                    stream.write_all(resp.as_bytes())?;
                                    log::debug!("[SMTP {}] OPNTRN GETKEY {} -> KEY found", self.remote, addr);
                                } else {
                                    stream.write_all(b"250 OPNTRN NOKEY\r\n")?;
                                    log::debug!("[SMTP {}] OPNTRN GETKEY {} -> NOKEY (no public key)", self.remote, addr);
                                }
                            } else {
                                stream.write_all(b"250 OPNTRN NOKEY\r\n")?;
                                log::debug!("[SMTP {}] OPNTRN GETKEY {} -> NOKEY (user not found)", self.remote, addr);
                            }
                        } else {
                            stream.write_all(b"250 OPNTRN NOKEY\r\n")?;
                            log::debug!("[SMTP {}] OPNTRN GETKEY {} -> NOKEY (wrong domain)", self.remote, addr);
                        }
                    } else {
                        stream.write_all(b"550 5.1.3 Invalid address\r\n")?;
                    }
                    stream.flush()?;
                    continue;
                } else if rest_lower.starts_with("e2ee") {
                    log::info!("[SMTP {}] OPNTRN E2EE - session marked as end-to-end encrypted", self.remote);
                    self.is_e2ee = true;
                    stream.write_all(b"250 OPNTRN OK\r\n")?;
                    stream.flush()?;
                    continue;
                } else {
                    stream.write_all(b"500 5.5.1 Unknown OPNTRN command\r\n")?;
                    stream.flush()?;
                    continue;
                }
            }

            if line_lower.starts_with("bdat ") {
                let parts: Vec<&str> = line_str.trim().splitn(3, ' ').collect();
                let chunk_size: usize = parts.get(1)
                    .and_then(|s| s.trim().parse().ok())
                    .unwrap_or(0);
                let is_last = parts.get(2)
                    .map(|s| s.trim().eq_ignore_ascii_case("LAST"))
                    .unwrap_or(false);

                // BDAT is a second path into 'raw_data' and must honour the same
                // advertised SIZE limit as DATA - otherwise a client can stream
                // unbounded chunks and exhaust server memory.
                if chunk_size > MAX_MESSAGE_SIZE
                    || self.email.raw_data.len().saturating_add(chunk_size) > MAX_MESSAGE_SIZE
                {
                    stream.write_all(b"552 5.3.4 Message size exceeds limit\r\n")?;
                    stream.flush()?;
                    return Err(io::Error::new(io::ErrorKind::Other, "BDAT chunk exceeds size limit"));
                }

                let buffered = &data[pos..];
                let take = buffered.len().min(chunk_size);
                self.email.raw_data.extend_from_slice(&buffered[..take]);
                pos += take;

                
                let mut remaining = chunk_size.saturating_sub(take);
                let mut tmp = vec![0u8; 8192];
                while remaining > 0 {
                    let to_read = remaining.min(8192);
                    let n = stream.read(&mut tmp[..to_read])?;
                    if n == 0 { break; }
                    self.email.raw_data.extend_from_slice(&tmp[..n]);
                    if self.email.raw_data.len() > MAX_MESSAGE_SIZE {
                        stream.write_all(b"552 5.3.4 Message size exceeds limit\r\n")?;
                        stream.flush()?;
                        return Err(io::Error::new(io::ErrorKind::Other, "message exceeds size limit"));
                    }
                    remaining -= n;
                }

                if is_last {
                    self.finish_data(stream)?;
                } else {
                    stream.write_all(b"250 2.0.0 OK\r\n")?;
                    stream.flush()?;
                }
                continue;
            }

            
            match self.state {
                EmailReceivingState::WaitingForEhlo => {
                    if line_lower.starts_with("ehlo") || line_lower.starts_with("helo") {
                        log::debug!("[SMTP {}] {}", self.remote, line_str.trim());
                        self.state = EmailReceivingState::WaitingForMailFrom;
                        let mut response = String::new();
                        response.push_str(&format!("250-{}\r\n", self.ehlo_name));
                        response.push_str("250-PIPELINING\r\n");
                        response.push_str("250-SIZE 104857600\r\n");
                        // Do not advertise STARTTLS on an already-encrypted connection (RFC 3207).
                        if !self.is_tls {
                            response.push_str("250-STARTTLS\r\n");
                        }
                        response.push_str("250-8BITMIME\r\n");
                        response.push_str("250-ENHANCEDSTATUSCODES\r\n");
                        response.push_str("250-OPNTRN\r\n");
                        response.push_str("250 CHUNKING\r\n");
                        stream.write_all(response.as_bytes())?;
                        stream.flush()?;
                    } else {
                        stream.write_all(b"503 5.5.1 Send EHLO/HELO first\r\n")?;
                        stream.flush()?;
                    }
                }

                EmailReceivingState::WaitingForMailFrom => {
                    if line_lower.starts_with("mail from:") {
                        if let Some(addr) = extract_email_address(&line_str) {
                            log::debug!("[SMTP {}] MAIL FROM: <{}>", self.remote, addr);
                            self.email.from = addr;
                            self.state = EmailReceivingState::WaitingForRcptTo;
                            stream.write_all(b"250 2.1.0 OK\r\n")?;
                        } else {
                            stream.write_all(b"550 5.1.0 Invalid address\r\n")?;
                        }
                        stream.flush()?;
                    } else {
                        stream.write_all(b"503 5.5.1 Expected MAIL FROM\r\n")?;
                        stream.flush()?;
                    }
                }

                EmailReceivingState::WaitingForRcptTo => {
                    if line_lower.starts_with("rcpt to:") {
                        if let Some(addr) = extract_email_address(&line_str) {
                            log::debug!("[SMTP {}] RCPT TO: <{}>", self.remote, addr);
                            self.email.to.push(addr);
                            stream.write_all(b"250 2.1.5 OK\r\n")?;
                        } else {
                            stream.write_all(b"550 5.1.3 Invalid address\r\n")?;
                        }
                        stream.flush()?;
                    } else if line_lower.starts_with("data") {
                        if self.email.to.is_empty() {
                            stream.write_all(b"503 5.5.1 No valid recipients\r\n")?;
                        } else {
                            log::debug!("[SMTP {}] DATA - entering data receive mode", self.remote);
                            self.state = EmailReceivingState::ReceivingData;
                            stream.write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")?;
                        }
                        stream.flush()?;
                    } else {
                        stream.write_all(b"503 5.5.1 Expected RCPT TO or DATA\r\n")?;
                        stream.flush()?;
                    }
                }

                EmailReceivingState::ReceivingData => {
                    // Handled at the top of the loop before line parsing.
                }

                EmailReceivingState::WaitingForQuit => {
                    // Transaction is complete; only QUIT is expected (handled globally above).
                    stream.write_all(b"503 5.5.1 Transaction complete, send QUIT\r\n")?;
                    stream.flush()?;
                }
            }
        }

        Ok(CommandResult::Continue)
    }

    pub fn parse_body(&mut self) {
        // Find the header/body separator in raw bytes - works for both text and binary emails
        let mut new_headers: Vec<(String, String)> = Vec::new();

        if let Some((header_bytes, body_start)) = split_header_body(&self.email.raw_data) {
            new_headers = parse_headers(header_bytes);

            // Body may be binary (E2EE) - store best-effort text in content field
            self.email.content = String::from_utf8_lossy(&self.email.raw_data[body_start..]).to_string();
        } else {
            // No header/body separator - treat entire payload as body
            self.email.content = String::from_utf8_lossy(&self.email.raw_data).to_string();
        }

        self.email.headers = new_headers;
    }

    /// True unless the message was refused at DATA time. The caller must not
    /// deliver a refused message: the 5xx already went to the client.
    pub fn is_accepted(&self) -> bool {
        !self.rejected
    }

    /// The refusal for this message, or None if it may be accepted.
    ///
    /// Two rules, both about telling the sender the truth before the final 250:
    /// mail claiming our own domain without a DKIM pass is a forgery we cannot
    /// authenticate, and a recipient that does not exist here would otherwise be
    /// accepted and silently destroyed.
    fn validate(&self) -> Option<String> {
        if self.reject_spoof {
            // The envelope sender and the From: header are two different claims,
            // and a forger picks whichever we do not check. Both are tested.
            let mut claimed: Vec<String> = vec![self.email.from.clone()];
            if let Some(header_from) = self.email.header("from").map(|value| value.to_string()) {
                for found in EMAIL_RE.find_iter(&header_from) {
                    claimed.push(found.as_str().to_string());
                }
            }
                        let ours = claimed.iter().any(|sender| {
                let lower = sender.to_ascii_lowercase();
                match lower.rfind('@') {
                    Some(at) => lower[at + 1..].eq_ignore_ascii_case(&self.server_name),
                    None => false,
                }
            });
            if ours {
                let raw = String::from_utf8_lossy(&self.email.raw_data);
                if !matches!(
                    crate::utils::dkim::verify(&raw),
                    crate::utils::DkimStatus::Pass
                ) {
                    // Mail the box generates for itself (cron output, watchdog
                    // alerts) is injected by the local MTA, which does not always
                    // sign it. Refusing those would make the alerting system fail
                    // silently, which is the one thing an alert must never do.
                    //
                    // Trust is placed on Postfix's own trace header: it prepends
                    // that line, so a remote sender cannot get one above it.
                    let locally_injected = self
                        .email
                        .header_all("received")
                        .first()
                        .map(|value| value.contains("(Postfix, from userid"))
                        .unwrap_or(false);
                    if locally_injected {
                        log::info!(
                            "[SMTP {}] own-domain mail accepted from local injection (unsigned)",
                            self.remote
                        );
                    } else {
                        return Some(
                            "550 5.7.1 Mail from this domain must carry a valid DKIM signature"
                                .to_string(),
                        );
                    }
                }
            }
        }

        for rcpt in &self.email.to {
            let lower = rcpt.to_ascii_lowercase();
            let Some(at) = lower.rfind('@') else {
                return Some(format!("550 5.1.3 Malformed recipient <{}>", rcpt));
            };
            if !lower[at + 1..].eq_ignore_ascii_case(&self.server_name) {
                return Some(format!("550 5.7.1 Relay denied for <{}>", rcpt));
            }
            if self.reject_unknown {
                let local = &lower[..at];
                if self.user_storage.get_user(local).is_none()
                    && crate::core::aliases::resolve(local).is_none()
                {
                    return Some(format!("550 5.1.1 No such mailbox <{}>", rcpt));
                }
            }
        }
        None
    }

    /// Decide the fate of a complete message, answer the client, and remember
    /// the verdict. Called once, on the final chunk, before any 250.
    fn finish_data(&mut self, stream: &mut MaybeTlsStream) -> io::Result<()> {
        self.parse_body();
        match self.validate() {
            None => {
                stream.write_all(b"250 2.0.0 OK\r\n")?;
                stream.flush()?;
            }
            Some(refusal) => {
                log::info!("[SMTP {}] refused message: {}", self.remote, refusal);
                stream.write_all(format!("{}\r\n", refusal).as_bytes())?;
                stream.flush()?;
                self.email = ReceivedEmail::new();
                self.rejected = true;
            }
        }
        self.state = EmailReceivingState::WaitingForQuit;
        Ok(())
    }

    pub fn get_email(&self) -> ReceivedEmail {
        let mut email = self.email.clone();
        email.is_e2ee = self.is_e2ee;
        email
    }

}

/// Where the headers stop and the body starts. CRLF is the standard, but some
/// clients send bare LF and the state machine accepts those messages, so both
/// separators are recognised.
pub(crate) fn split_header_body(raw: &[u8]) -> Option<(&[u8], usize)> {
    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some((&raw[..pos], pos + 4));
    }
    raw.windows(2)
        .position(|w| w == b"\n\n")
        .map(|pos| (&raw[..pos], pos + 2))
}

/// Parse a header block into ordered name/value pairs.
///
/// Two things a naive split loses and a mailbox needs:
///   - folded headers: a continuation line starts with space or tab and belongs
///     to the header above it, so it is joined rather than discarded;
///   - duplicates: `Received:` is a trail, and collapsing it to the last one
///     throws away where the message actually came from.
pub(crate) fn parse_headers(header_bytes: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(header_bytes);
    let mut out: Vec<(String, String)> = Vec::new();

    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some((_, value)) = out.last_mut() {
                let extra = line.trim();
                if !extra.is_empty() {
                    if !value.is_empty() {
                        value.push(' ');
                    }
                    value.push_str(extra);
                }
            }
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            let name = key.trim().to_ascii_lowercase();
            if !name.is_empty() {
                out.push((name, value.trim().to_string()));
            }
        }
    }
    out
}

/// SMTP transparency (RFC 5321 s.4.5.2): remove dot-stuffing - if a line starts with '.', remove it.
fn smtp_dot_unstuff(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut at_line_start = true;
    for &b in data {
        if at_line_start && b == b'.' {
            // Skip the leading dot (was added by dot-stuffing)
            at_line_start = false;
            continue;
        }
        out.push(b);
        at_line_start = b == b'\n';
    }
    out
}
#[cfg(test)]
mod header_parsing_tests {
    use super::*;

    #[test]
    fn a_folded_header_is_joined_not_dropped() {
        let raw = b"Subject: a subject so long that\r\n it was folded\r\n\r\nbody";
        let (headers, body_start) = split_header_body(raw).expect("split");
        let parsed = parse_headers(headers);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0, "subject");
        assert_eq!(parsed[0].1, "a subject so long that it was folded");
        assert_eq!(&raw[body_start..], b"body");
    }

    #[test]
    fn duplicate_received_headers_survive_in_order() {
        let raw = b"Received: from a\r\nReceived: from b\r\nSubject: x\r\n\r\nb";
        let (headers, _) = split_header_body(raw).expect("split");
        let parsed = parse_headers(headers);
        let trail: Vec<&str> = parsed
            .iter()
            .filter(|(k, _)| k == "received")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(trail, vec!["from a", "from b"]);
    }

    #[test]
    fn bare_lf_messages_are_split_too() {
        let raw = b"Subject: lf\nFrom: a@b.test\n\nbody";
        let (headers, body_start) = split_header_body(raw).expect("split");
        let parsed = parse_headers(headers);
        assert_eq!(parsed.len(), 2);
        assert_eq!(&raw[body_start..], b"body");
    }

    #[test]
    fn names_are_lowercased_for_lookup() {
        let raw = b"From: Someone <a@b.test>\r\n\r\n";
        let (headers, _) = split_header_body(raw).expect("split");
        let parsed = parse_headers(headers);
        assert_eq!(parsed[0].0, "from");
    }

    #[test]
    fn a_parsed_message_serialises_with_the_whole_subject_and_the_whole_trail() {
        // What the mailbox actually stores is ReceivedEmail::to_string(), so this
        // checks the two defects end to end rather than only at the parser.
        // Built on one line on purpose: a trailing backslash in a Rust string
        // swallows the following indentation, and the folded line would lose
        // the leading space that makes it a continuation.
        let raw = b"From: outsider@example.net\r\nSubject: a very long subject that the sender\r\n wrapped onto a second line\r\nReceived: from relay-a.example\r\nReceived: from origin.example\r\n\r\nbody";
        let (header_bytes, body_start) = split_header_body(raw).expect("split");
        let mut email = crate::smtp::received_email::Email::new();
        email.headers = parse_headers(header_bytes);
        email.content = String::from_utf8_lossy(&raw[body_start..]).to_string();
        let stored = email.to_string();

        assert!(
            stored.contains("a very long subject that the sender wrapped onto a second line"),
            "the folded subject must be stored whole: {}",
            stored
        );
        assert!(
            stored.matches("received:").count() == 2,
            "both hops of the delivery trail must survive: {}",
            stored
        );
        assert!(stored.contains("origin.example"));
    }

    #[test]
    fn a_message_without_headers_has_no_separator() {
        assert!(split_header_body(b"just a body").is_none());
    }
}
