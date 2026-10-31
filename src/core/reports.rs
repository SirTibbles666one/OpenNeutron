//! Deliverability reports: DMARC aggregate (XML) and SMTP TLS-RPT (JSON).
//!
//! Both policies on this domain ask receivers to send reports
//! (`rua=mailto:…`), and until now nothing read them — the first sign that a
//! provider could not deliver was an audit months later, or never. This module
//! parses a report as it arrives, records it, and mails the owner only when the
//! report carries a failure.
//!
//! Why here and not a cron: the mail server has no IMAP. The only component that
//! can see a report without a human's browser session is the delivery path
//! itself, so the parse happens where the bytes already are.
//!
//! Rules that keep this safe:
//!   - the SMTP transaction never waits for the parse (callers use `ingest_async`);
//!   - every step is bounded — message, decompressed payload, records scanned —
//!     so a hostile attachment cannot exhaust memory;
//!   - a report that cannot be parsed is logged and dropped, never alerted on;
//!     a wrong alarm is worse than a missing one here;
//!   - nothing is written outside `data/reports.jsonl` and the owner's mailbox.

use std::io::Read;

use base64::Engine as _;

/// The whole message. Real reports are tens of KB; 8 MB is already generous.
const MAX_MESSAGE_BYTES: usize = 8 * 1024 * 1024;
/// A decompressed payload. Guards a zip bomb: stop reading past this.
const MAX_REPORT_BYTES: usize = 4 * 1024 * 1024;
/// DMARC files can carry thousands of records; scan a bounded prefix.
const MAX_SCAN_BYTES: usize = 2 * 1024 * 1024;
/// How much of a message `sniff` reads. Part headers of a report sit here.
const SNIFF_BYTES: usize = 16 * 1024;
const MAX_NOTES: usize = 8;

const RECORD_FILE: &str = "data/reports.jsonl";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// SMTP TLS Reporting (RFC 8460) — JSON or XML, usually gzipped.
    TlsRpt,
    /// DMARC aggregate (RFC 7489) — XML, usually zipped.
    Dmarc,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::TlsRpt => "tls-rpt",
            Kind::Dmarc => "dmarc",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    pub kind: Option<Kind>,
    /// Who sent the report (organization-name or email).
    pub reporter: String,
    /// The domain the report is about.
    pub domain: String,
    pub start: String,
    pub end: String,
    /// Messages/sessions covered by the report.
    pub total: u64,
    /// The subset that failed.
    pub failures: u64,
    /// Why, in the reporter's own vocabulary — bounded to MAX_NOTES.
    pub notes: Vec<String>,
}

impl Report {
    pub fn failed(&self) -> bool {
        self.failures > 0
    }
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/// Is this message a deliverability report?
///
/// The markers sit in the *parts*, not in the outer headers: a report arrives as
/// `multipart/report` and only the inner part says `application/tlsrpt+gzip`.
/// So this reads the first 16 KB — headers plus the start of the body — which is
/// where every part header of a real report lies. Ordinary mail pays one bounded
/// scan and stops.
pub fn sniff(raw: &[u8]) -> Option<Kind> {
    if raw.len() > MAX_MESSAGE_BYTES {
        return None;
    }
    let window = &raw[..raw.len().min(SNIFF_BYTES)];
    let text = String::from_utf8_lossy(window).to_ascii_lowercase();

    if text.contains("tlsrpt") || text.contains("tls-rpt") {
        return Some(Kind::TlsRpt);
    }
    if text.contains("<feedback") || text.contains("<policy_published") {
        return Some(Kind::Dmarc);
    }
    let subject_is_report = text.contains("report domain:") || text.contains("aggregate report");
    if subject_is_report
        && (text.contains("application/zip")
            || text.contains("application/x-zip")
            || text.contains("application/xml")
            || text.contains("text/xml"))
    {
        return Some(Kind::Dmarc);
    }
    if subject_is_report && text.contains("tls") {
        return Some(Kind::TlsRpt);
    }
    None
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Parse, record, and alert on failure. Runs on the caller's thread.
pub fn ingest(raw: &[u8]) -> Result<Report, String> {
    let kind = sniff(raw).ok_or_else(|| "not a deliverability report".to_string())?;
    let report = parse(raw, kind)?;
    if let Err(error) = append_record(&report) {
        log::warn!("[reports] could not record {} report: {}", kind.as_str(), error);
    }
    if report.failed() {
        if let Err(error) = alert(&report) {
            log::warn!("[reports] could not alert on {} report: {}", kind.as_str(), error);
        }
    } else {
        log::info!(
            "[reports] {} report from '{}' for '{}': {} ok, 0 failures",
            kind.as_str(), report.reporter, report.domain, report.total
        );
    }
    Ok(report)
}

/// Never let a report slow the SMTP transaction: the parse and the alert mail
/// both happen on their own thread, after the message is already stored.
pub fn ingest_async(raw: Vec<u8>) {
    std::thread::spawn(move || {
        if let Err(error) = ingest(&raw) {
            log::info!("[reports] could not read a report: {}", error);
        }
    });
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Pull the report payload out of the message and read it.
pub fn parse(raw: &[u8], kind: Kind) -> Result<Report, String> {
    if raw.len() > MAX_MESSAGE_BYTES {
        return Err("message too large to be a report".to_string());
    }
    let payload = locate_payload(raw, kind).ok_or_else(|| "no report payload found".to_string())?;
    let bytes = decompress(&payload)?;
    match kind {
        Kind::TlsRpt => parse_tls_rpt(&bytes),
        Kind::Dmarc => parse_dmarc(&bytes),
    }
}

/// Find the part that carries the report and undo its transfer encoding.
fn locate_payload(raw: &[u8], kind: Kind) -> Option<Vec<u8>> {
    let (head, body) = split_head_body(raw);
    let head_raw = String::from_utf8_lossy(head);
    let head_text = head_raw.to_ascii_lowercase();

    let wants = |ctype: &str| -> bool {
        match kind {
            Kind::TlsRpt => {
                ctype.contains("tlsrpt") || ctype.contains("gzip") || ctype.contains("x-gzip")
            }
            Kind::Dmarc => ctype.contains("zip") || ctype.contains("xml"),
        }
    };

    if let Some(boundary) = header_param(&head_raw, "boundary") {
        let parts = split_multipart(body, &boundary);
        // First pass: the part names itself. Second pass: the bytes give it away
        // (a gzip/zip magic number, or the document's own root element).
        for part in &parts {
            let (phead, pbody) = split_head_body(part);
            let phead_text = String::from_utf8_lossy(phead).to_ascii_lowercase();
            let ctype = header_value(&phead_text, "content-type").unwrap_or_default();
            if wants(&ctype) {
                return Some(decode_transfer(pbody, &phead_text));
            }
        }
        for part in &parts {
            let (phead, pbody) = split_head_body(part);
            let phead_text = String::from_utf8_lossy(phead).to_ascii_lowercase();
            let decoded = decode_transfer(pbody, &phead_text);
            let compressed = decoded.len() > 2 && ((decoded[0] == 0x1f && decoded[1] == 0x8b) || decoded.starts_with(b"PK"));
            if compressed || looks_like_report(&decoded, kind) {
                return Some(decoded);
            }
        }
        return None;
    }

    // Single part: the body is the payload, compressed or already text.
    let ctype = header_value(&head_text, "content-type").unwrap_or_default();
    let bytes = decode_transfer(body, &head_text);
    let compressed = bytes.len() > 2 && ((bytes[0] == 0x1f && bytes[1] == 0x8b) || bytes.starts_with(b"PK"));
    if compressed || looks_like_report(&bytes, kind) || wants(&ctype) {
        return Some(bytes);
    }
    None
}

fn looks_like_report(bytes: &[u8], kind: Kind) -> bool {
    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(2048)]).to_ascii_lowercase();
    match kind {
        Kind::TlsRpt => text.contains("\"policies\"") || text.contains("<policy-domain"),
        Kind::Dmarc => text.contains("<feedback>") || text.contains("<policy_published"),
    }
}

fn decompress(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() > 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(bytes)
            .take(MAX_REPORT_BYTES as u64)
            .read_to_end(&mut out)
            .map_err(|e| format!("gzip: {e}"))?;
        return Ok(out);
    }
    if bytes.starts_with(b"PK") {
        let reader = std::io::Cursor::new(bytes);
        let mut archive = zip::ZipArchive::new(reader).map_err(|e| format!("zip: {e}"))?;
        // A report archive holds one document; read the first, bounded.
        for index in 0..archive.len().min(4) {
            let mut file = archive.by_index(index).map_err(|e| format!("zip entry: {e}"))?;
            if file.is_dir() {
                continue;
            }
            let mut out = Vec::new();
            file.take(MAX_REPORT_BYTES as u64)
                .read_to_end(&mut out)
                .map_err(|e| format!("zip read: {e}"))?;
            return Ok(out);
        }
        return Err("zip archive holds no file".to_string());
    }
    Ok(bytes.to_vec())
}

/// SMTP TLS Reporting — Google and friends send JSON (RFC 8460 §3).
fn parse_tls_rpt(bytes: &[u8]) -> Result<Report, String> {
    let text = limited_text(bytes)?;
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("tls-rpt json: {e}"))?;

    let mut report = Report { kind: Some(Kind::TlsRpt), ..Default::default() };
    report.reporter = value
        .get("organization-name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown reporter")
        .to_string();
    report.start = value
        .pointer("/date-range/start-datetime")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    report.end = value
        .pointer("/date-range/end-datetime")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let policies = value
        .get("policies")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "tls-rpt json: no policies[]".to_string())?;

    for policy in policies.iter().take(64) {
        let kind_of_policy = policy
            .pointer("/policy/policy-type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        if report.domain.is_empty() {
            report.domain = policy
                .pointer("/policy/policy-domain")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
        }
        let ok = policy
            .pointer("/summary/total-successful-session-count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let failed = policy
            .pointer("/summary/total-failure-session-count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        report.total += ok + failed;
        report.failures += failed;
        if failed > 0 && report.notes.len() < MAX_NOTES {
            let reason = policy
                .pointer("/failure-details/0/failure-reason-code")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or("no reason code");
            report.notes.push(format!("{kind_of_policy}: {failed} failed ({reason})"));
        }
    }
    Ok(report)
}

/// DMARC aggregate — XML with one `<record>` per sender/result pair.
fn parse_dmarc(bytes: &[u8]) -> Result<Report, String> {
    let text = limited_text(bytes)?;
    let mut report = Report { kind: Some(Kind::Dmarc), ..Default::default() };
    report.reporter = first_tag(&text, "org_name").unwrap_or_else(|| "unknown reporter".to_string());
    report.domain = first_tag(&text, "domain").unwrap_or_default();
    if report.domain.is_empty() {
        report.domain = first_tag(&text, "policy_domain").unwrap_or_default();
    }
    report.start = first_uint_tag(&text, "begin").map(epoch_to_date).unwrap_or_default();
    report.end = first_uint_tag(&text, "end").map(epoch_to_date).unwrap_or_default();

    if !text.contains("<record") {
        return Err("dmarc: no <record> in the report".to_string());
    }
    let mut records = 0usize;
    for chunk in split_tag(&text, "record").into_iter().take(2000) {
        records += 1;
        let count = first_uint_tag(chunk, "count").unwrap_or(1);
        let disposition = first_tag(chunk, "disposition").unwrap_or_else(|| "none".to_string());
        report.total += count;
        let rejected = disposition == "reject";
        let quarantined = disposition == "quarantine";
        if rejected || quarantined {
            report.failures += count;
            if report.notes.len() < MAX_NOTES {
                let dkim = first_tag(chunk, "dkim").unwrap_or_else(|| "?".to_string());
                let spf = first_tag(chunk, "spf").unwrap_or_else(|| "?".to_string());
                report.notes.push(format!(
                    "{count} {disposition} (dkim {dkim}, spf {spf})"
                ));
            }
        }
    }
    if records == 0 {
        return Err("dmarc: records were empty".to_string());
    }
    Ok(report)
}

// ---------------------------------------------------------------------------
// Recording and alerting
// ---------------------------------------------------------------------------

fn append_record(report: &Report) -> Result<(), String> {
    let line = serde_json::json!({
        "kind": report.kind.map(|k| k.as_str()),
        "domain": report.domain,
        "reporter": report.reporter,
        "start": report.start,
        "end": report.end,
        "total": report.total,
        "failures": report.failures,
        "notes": report.notes,
        "seen_at": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    });
    let mut line = line.to_string();
    line.push('\n');
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(RECORD_FILE)
        .map_err(|e| format!("open {RECORD_FILE}: {e}"))?;
    use std::io::Write as _;
    file.write_all(line.as_bytes())
        .map_err(|e| format!("write {RECORD_FILE}: {e}"))?;
    Ok(())
}

/// Mail the owner. Only called when a report actually carries a failure.
fn alert(report: &Report) -> Result<(), String> {
    let owner = crate::config::role_owner_username()
        .ok_or_else(|| "no roles.owner configured, so there is nobody to tell".to_string())?;
    let domain = crate::utils::emailutils::get_server_domain();
    let to = format!("{owner}@{domain}");
    let from = format!("postmaster@{domain}");

    let kind = report.kind.map(|k| k.as_str()).unwrap_or("deliverability");
    let subject = format!(
        "{} report failure: {} ({} of {})",
        kind, report.domain, report.failures, report.total
    );
    let mut body = String::new();
    body.push_str(&format!("A {kind} report for {} carries failures.\n\n", report.domain));
    body.push_str(&format!("reporter: {}\n", report.reporter));
    body.push_str(&format!("window:   {} → {}\n", report.start, report.end));
    body.push_str(&format!("totals:   {} ok, {} failed\n\n", report.total.saturating_sub(report.failures), report.failures));
    for note in &report.notes {
        body.push_str(&format!("  - {note}\n"));
    }
    body.push_str("\nWhat this means:\n");
    body.push_str(match report.kind {
        Some(Kind::TlsRpt) => "  A provider could not establish TLS with this server for the sessions above.\n  Check the MTA-STS policy, the certificate and the MX records before it affects delivery.\n",
        Some(Kind::Dmarc) => "  Messages claiming this domain failed alignment and were quarantined or rejected.\n  If these are your own senders, their DKIM/SPF setup needs fixing; if not, someone is spoofing you.\n",
        None => "",
    });
    body.push_str("\nEvery report is recorded in data/reports.jsonl on the mail host.\n");

    crate::utils::mailer::send_plain(&from, &to, &subject, &body)
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|window| window == needle)
}

fn split_head_body(raw: &[u8]) -> (&[u8], &[u8]) {
    if let Some(pos) = find(raw, b"\r\n\r\n") {
        return (&raw[..pos], &raw[pos + 4..]);
    }
    if let Some(pos) = find(raw, b"\n\n") {
        return (&raw[..pos], &raw[pos + 2..]);
    }
    (raw, &[])
}

fn header_value(head_lowercased: &str, name: &str) -> Option<String> {
    for line in head_lowercased.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix(name) {
            if let Some(value) = rest.strip_prefix(':') {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

/// The header's value with its original casing — needed for MIME boundaries,
/// which are case-sensitive even though the header name is not.
fn raw_header_value(head_raw: &str, name: &str) -> Option<String> {
    for line in head_raw.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(colon) = line.find(':') {
            if line[..colon].trim().eq_ignore_ascii_case(name) {
                return Some(line[colon + 1..].trim().to_string());
            }
        }
    }
    None
}

fn header_param(head_raw: &str, param: &str) -> Option<String> {
    let value = raw_header_value(head_raw, "content-type")?;
    let needle = format!("{param}=");
    let lower = value.to_ascii_lowercase();
    let start = lower.find(&needle)? + needle.len();
    let rest = value[start..].trim_start_matches('"');
    let end = rest.find(|c| c == '"' || c == ';').unwrap_or(rest.len());
    let boundary = rest[..end].trim().to_string();
    if boundary.is_empty() { None } else { Some(boundary) }
}

fn split_multipart<'a>(body: &'a [u8], boundary: &str) -> Vec<Vec<u8>> {
    let delimiter = format!("--{boundary}");
    let text = body;
    let mut parts = Vec::new();
    let mut cursor = 0usize;
    let mut current: Option<usize> = None;
    while let Some(offset) = find(&text[cursor..], delimiter.as_bytes()) {
        let at = cursor + offset;
        if let Some(start) = current {
            parts.push(text[start..at].to_vec());
        }
        // Skip the delimiter line itself.
        let after = at + delimiter.len();
        if text[after..].trim_ascii_start().starts_with(b"--") {
            current = None;
            break;
        }
        let line_end = find(&text[after..], b"\n").map(|p| after + p + 1).unwrap_or(text.len());
        current = Some(line_end);
        cursor = line_end;
    }
    if let Some(start) = current {
        if start < text.len() {
            parts.push(text[start..].to_vec());
        }
    }
    parts
}

fn decode_transfer(body: &[u8], head_lowercased: &str) -> Vec<u8> {
    let encoding = header_value(head_lowercased, "content-transfer-encoding").unwrap_or_default();
    if encoding.contains("base64") {
        let cleaned: Vec<u8> = body
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&cleaned) {
            return decoded;
        }
    }
    if encoding.contains("quoted-printable") {
        return decode_quoted_printable(body);
    }
    body.to_vec()
}

fn decode_quoted_printable(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let mut index = 0usize;
    while index < body.len() {
        match body[index] {
            b'=' => {
                if index + 2 < body.len() && body[index + 1] == b'\r' && body[index + 2] == b'\n' {
                    index += 3;
                    continue;
                }
                if index + 2 < body.len() && body[index + 1] == b'\n' {
                    index += 2;
                    continue;
                }
                if index + 2 < body.len() {
                    let hex = std::str::from_utf8(&body[index + 1..index + 3]).ok();
                    if let Some(byte) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                        out.push(byte);
                        index += 3;
                        continue;
                    }
                }
                out.push(b'=');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    out
}

fn limited_text(bytes: &[u8]) -> Result<String, String> {
    if bytes.len() > MAX_REPORT_BYTES {
        return Err("report payload too large".to_string());
    }
    let slice = &bytes[..bytes.len().min(MAX_SCAN_BYTES)];
    String::from_utf8(slice.to_vec()).map_err(|e| format!("report is not utf-8: {e}"))
}

/// First `<tag>value</tag>` in the document.
fn first_tag(text: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = text.find(&open)? + open.len();
    let end = text[start..].find(&close)? + start;
    let value = text[start..end].trim();
    if value.is_empty() { None } else { Some(value.to_string()) }
}

fn first_uint_tag(text: &str, tag: &str) -> Option<u64> {
    first_tag(text, tag)?.trim().parse::<u64>().ok()
}

/// Every `<tag>…</tag>` inner slice, in document order.
fn split_tag<'a>(text: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(start) = text[cursor..].find(&open) {
        let after_open = cursor + start;
        // Skip past the opening tag's attributes and its '>'.
        let Some(gt) = text[after_open..].find('>') else { break };
        let body_start = after_open + gt + 1;
        let Some(end_rel) = text[body_start..].find(&close) else { break };
        let body_end = body_start + end_rel;
        out.push(&text[body_start..body_end]);
        cursor = body_end + close.len();
        if out.len() >= 2000 {
            break;
        }
    }
    out
}

/// `begin`/`end` are epoch seconds in DMARC aggregate reports.
fn epoch_to_date(seconds: u64) -> String {
    // Days since the epoch → civil date, without pulling in a date crate.
    let days = (seconds / 86_400) as i64;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real Google TLS-RPT payload for slothlee.xyz, 2026-10-30: six
    /// successful sessions, no failures. Kept verbatim: a report parser that
    /// only ever sees a hand-written fixture proves nothing.
    const GOOGLE_TLS_RPT: &str = r#"{"organization-name":"Google Inc.","date-range":{"start-datetime":"2026-10-30T00:00:00Z","end-datetime":"2026-10-30T23:59:59Z"},"contact-info":"smtp-tls-reporting@google.com","report-id":"2026-10-30T00:00:00Z_slothlee.xyz","policies":[{"policy":{"policy-type":"sts","policy-string":["version: STSv1","mode: enforce","mx: mail.slothlee.xyz","max_age: 604800"],"policy-domain":"slothlee.xyz","mx-host":["mail.slothlee.xyz"]},"summary":{"total-successful-session-count":5,"total-failure-session-count":0}},{"policy":{"policy-type":"no-policy-found","policy-domain":"slothlee.xyz"},"summary":{"total-successful-session-count":1,"total-failure-session-count":0}}]}"#;

    const TLS_RPT_WITH_FAILURE: &str = r#"{"organization-name":"Example Corp","date-range":{"start-datetime":"2026-11-01T00:00:00Z","end-datetime":"2026-11-01T23:59:59Z"},"policies":[{"policy":{"policy-type":"sts","policy-domain":"slothlee.xyz","mx-host":["mail.slothlee.xyz"]},"summary":{"total-successful-session-count":11,"total-failure-session-count":2},"failure-details":[{"result-type":"certificate-expired","sending-mta-ip":"198.51.100.7","failed-session-count":2,"failure-reason-code":"certificate-expired"}]}]}"#;

    const DMARC_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>1234567890</report_id>
    <date_range><begin>1793404800</begin><end>1793491199</end></date_range>
  </report_metadata>
  <policy_published><domain>slothlee.xyz</domain><adkim>s</adkim><aspf>s</aspf><p>reject</p></policy_published>
  <record>
    <row><source_ip>209.85.220.41</source_ip><count>100</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
  </record>
  <record>
    <row><source_ip>203.0.113.9</source_ip><count>20</count>
      <policy_evaluated><disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
    </row>
  </record>
  <record>
    <row><source_ip>198.51.100.3</source_ip><count>3</count>
      <policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>pass</spf></policy_evaluated>
    </row>
  </record>
</feedback>"#;

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use std::io::Write as _;
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    /// Build a message the way a receiver sends one: multipart/mixed, the report
    /// as a base64 part with its own content type.
    fn message(content_type: &str, payload: &[u8], subject: &str) -> Vec<u8> {
        let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
        let mut wrapped = String::new();
        for chunk in encoded.as_bytes().chunks(76) {
            wrapped.push_str(std::str::from_utf8(chunk).unwrap());
            wrapped.push_str("\r\n");
        }
        format!(
            "From: reporter@example.com\r\nTo: tibs@slothlee.xyz\r\nSubject: {subject}\r\nMIME-Version: 1.0\r\nContent-Type: multipart/report; boundary=\"b1\"\r\n\r\n--b1\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n--b1\r\nContent-Type: {content_type}\r\nContent-Transfer-Encoding: base64\r\n\r\n{wrapped}--b1--\r\n"
        )
        .into_bytes()
    }

    #[test]
    fn a_google_tls_report_is_sniffed_and_parsed() {
        let raw = message("application/tlsrpt+gzip", &gzip(GOOGLE_TLS_RPT.as_bytes()), "Report domain: slothlee.xyz");
        assert_eq!(sniff(&raw), Some(Kind::TlsRpt));
        let report = parse(&raw, Kind::TlsRpt).unwrap();
        assert_eq!(report.reporter, "Google Inc.");
        assert_eq!(report.domain, "slothlee.xyz");
        assert_eq!(report.total, 6, "5 sts sessions + 1 no-policy-found session");
        assert_eq!(report.failures, 0);
        assert!(!report.failed());
    }

    #[test]
    fn a_failing_tls_report_is_a_failure_with_its_reason() {
        let raw = message("application/tlsrpt+gzip", &gzip(TLS_RPT_WITH_FAILURE.as_bytes()), "TLS Report domain: slothlee.xyz");
        assert_eq!(sniff(&raw), Some(Kind::TlsRpt));
        let report = parse(&raw, Kind::TlsRpt).unwrap();
        assert_eq!(report.total, 13);
        assert_eq!(report.failures, 2);
        assert!(report.failed());
        assert!(report.notes.iter().any(|n| n.contains("certificate-expired")), "{:?}", report.notes);
    }

    #[test]
    fn a_zipped_dmarc_report_counts_the_rejected_and_quarantined_messages() {
        let mut zip_bytes = Vec::new();
        {
            use std::io::Write as _;
            let cursor = std::io::Cursor::new(&mut zip_bytes);
            let mut writer = zip::ZipWriter::new(cursor);
            let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
            writer.start_file("google.com!slothlee.xyz!1234567890.xml", options).unwrap();
            writer.write_all(DMARC_XML.as_bytes()).unwrap();
            writer.finish().unwrap();
        }
        let raw = message("application/zip", &zip_bytes, "Report domain: slothlee.xyz Submitter: google.com Report-ID: 1234567890");
        assert_eq!(sniff(&raw), Some(Kind::Dmarc));
        let report = parse(&raw, Kind::Dmarc).unwrap();
        assert_eq!(report.reporter, "google.com");
        assert_eq!(report.domain, "slothlee.xyz");
        assert_eq!(report.total, 123);
        assert_eq!(report.failures, 23, "20 quarantined + 3 rejected");
        assert_eq!(report.notes.len(), 2);
        assert!(report.notes[0].contains("quarantine"));
    }

    #[test]
    fn an_unzipped_xml_dmarc_report_is_read_too() {
        let raw = message("application/xml", DMARC_XML.as_bytes(), "Report domain: slothlee.xyz");
        assert_eq!(sniff(&raw), Some(Kind::Dmarc));
        let report = parse(&raw, Kind::Dmarc).unwrap();
        assert_eq!(report.total, 123);
        assert_eq!(report.start, "2026-10-31", "epoch seconds become a date");
    }

    #[test]
    fn a_boundary_with_uppercase_is_still_found() {
        // MIME boundaries are case-sensitive; the sniffing code lowercases the
        // headers, so the boundary has to come from the original bytes.
        let payload = gzip(GOOGLE_TLS_RPT.as_bytes());
        let encoded = base64::engine::general_purpose::STANDARD.encode(&payload);
        let raw = format!(
            "From: reporter@example.com\r\nTo: tibs@slothlee.xyz\r\nSubject: Report domain: slothlee.xyz\r\nContent-Type: multipart/report; boundary=\"AbC-123\"\r\n\r\n--AbC-123\r\nContent-Type: application/tlsrpt+gzip\r\nContent-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n--AbC-123--\r\n"
        )
        .into_bytes();
        let report = parse(&raw, Kind::TlsRpt).expect("uppercase boundary");
        assert_eq!(report.total, 6);
    }

    #[test]
    fn ordinary_mail_is_not_a_report() {
        let raw = b"From: a@b.example\r\nTo: tibs@slothlee.xyz\r\nSubject: lunch?\r\n\r\nTuesday, usual place.\r\n";
        assert_eq!(sniff(raw), None);
        assert!(ingest(raw).is_err(), "ingest refuses what sniff rejects");
    }

    #[test]
    fn a_broken_report_is_not_an_alert() {
        // A subject that claims to be a report but carries junk: sniff says yes,
        // parse says no — and ingest must surface the error instead of mailing
        // the owner about a failure that does not exist.
        let raw = message("application/xml", b"<html>not a report</html>", "Report domain: slothlee.xyz");
        assert_eq!(sniff(&raw), Some(Kind::Dmarc));
        let error = parse(&raw, Kind::Dmarc).unwrap_err();
        assert!(error.contains("no <record>") || error.contains("payload"), "{error}");
    }

    #[test]
    fn epoch_seconds_convert_without_a_date_crate() {
        assert_eq!(epoch_to_date(0), "1970-01-01");
        assert_eq!(epoch_to_date(1_793_404_800), "2026-10-31");
    }
}
