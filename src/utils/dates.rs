//! Dates, without a dependency.
//!
//! The crate has no date library, and the one place a date matters is telling a suspended
//! person when their account comes back. A raw unix timestamp there is not an answer.

/// `YYYY-MM-DD` for a unix timestamp, in UTC. Civil-from-days (Howard Hinnant), which is the
/// standard shift-based algorithm: no loops, no library, correct for the whole range we use.
pub fn utc_date(unix: u64) -> String {
    let z = (unix / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::utc_date;

    #[test]
    fn known_dates() {
        assert_eq!(utc_date(0), "1970-01-01");
        assert_eq!(utc_date(1_000_000_000), "2001-09-09");
        assert_eq!(utc_date(1_795_000_000), "2026-11-18");
    }

    #[test]
    fn a_leap_day_is_not_off_by_one() {
        // 2024-02-29 12:00 UTC
        assert_eq!(utc_date(1_709_208_000), "2024-02-29");
    }
}
