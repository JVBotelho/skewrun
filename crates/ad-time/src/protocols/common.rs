use crate::time_src::TimeSourceError;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Parse KerberosTime or LDAP GeneralizedTime (e.g. "20240115000000.0Z" or "20240115103000Z")
pub fn parse_generalized_time(s: &str) -> Result<SystemTime, TimeSourceError> {
    // Expected format: "YYYYMMDDHHmmssZ" (15 chars + Z = 16, or sometimes without Z = 15).
    if !s.is_ascii() {
        return Err(TimeSourceError::Parse("GeneralizedTime not ASCII".into()));
    }
    let s = s.trim_end_matches('Z');

    // Handle fractional seconds (e.g., .0, .123)
    let (s, _fraction) = if let Some(dot_idx) = s.find('.') {
        (&s[0..dot_idx], &s[dot_idx + 1..])
    } else {
        (s, "")
    };

    if s.len() < 14 {
        return Err(TimeSourceError::Parse(format!(
            "GeneralizedTime too short: {:?}",
            s
        )));
    }

    let year: i64 = s[0..4]
        .parse()
        .map_err(|_| TimeSourceError::Parse("invalid year".into()))?;
    let month: i64 = s[4..6]
        .parse()
        .map_err(|_| TimeSourceError::Parse("invalid month".into()))?;
    let day: i64 = s[6..8]
        .parse()
        .map_err(|_| TimeSourceError::Parse("invalid day".into()))?;
    let hour: i64 = s[8..10]
        .parse()
        .map_err(|_| TimeSourceError::Parse("invalid hour".into()))?;
    let min: i64 = s[10..12]
        .parse()
        .map_err(|_| TimeSourceError::Parse("invalid min".into()))?;
    let sec: i64 = s[12..14]
        .parse()
        .map_err(|_| TimeSourceError::Parse("invalid sec".into()))?;

    if !(0..24).contains(&hour) || !(0..60).contains(&min) || !(0..60).contains(&sec) {
        return Err(TimeSourceError::Parse(format!(
            "GeneralizedTime time-of-day out of range: {:02}:{:02}:{:02}",
            hour, min, sec
        )));
    }

    let days = civil_to_days(year, month, day)?;
    let unix_secs = days * 86400 + hour * 3600 + min * 60 + sec;

    if unix_secs < 0 {
        return Err(TimeSourceError::Parse(
            "GeneralizedTime predates Unix epoch".into(),
        ));
    }
    Ok(UNIX_EPOCH + Duration::from_secs(unix_secs as u64))
}

/// Days since Unix epoch (1970-01-01) from civil date. Valid for 1970–2199.
pub fn civil_to_days(y: i64, m: i64, d: i64) -> Result<i64, TimeSourceError> {
    if y < 1970 || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return Err(TimeSourceError::Parse(format!(
            "invalid date {}-{:02}-{:02}",
            y, m, d
        )));
    }
    // Algorithm from Howard Hinnant (public domain).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Ok(era * 146097 + doe - 719468)
}

/// Convert SystemTime to microseconds since Unix epoch.
pub fn system_time_to_us(t: SystemTime) -> Result<i64, TimeSourceError> {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .map_err(|_| TimeSourceError::Parse("time before unix epoch".into()))
}

pub fn filetime_to_system_time(filetime: u64) -> Result<SystemTime, TimeSourceError> {
    const FILETIME_TO_UNIX_SECS: u64 = 11_644_473_600;
    const EPOCH_OFFSET_100NS: u64 = FILETIME_TO_UNIX_SECS * 10_000_000;
    if filetime < EPOCH_OFFSET_100NS {
        return Err(TimeSourceError::Parse(format!(
            "FILETIME {} predates Unix epoch",
            filetime
        )));
    }
    let unix_100ns = filetime - EPOCH_OFFSET_100NS;
    let secs = unix_100ns / 10_000_000;
    let nanos = ((unix_100ns % 10_000_000) * 100) as u32;
    Ok(UNIX_EPOCH + Duration::new(secs, nanos))
}

pub fn map_io_err(e: std::io::Error, op: &str) -> TimeSourceError {
    use std::io::ErrorKind::*;
    match e.kind() {
        TimedOut | WouldBlock => TimeSourceError::Timeout,
        ConnectionRefused => TimeSourceError::Refused,
        _ => TimeSourceError::Protocol(format!("{}: {}", op, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn parse_generalized_time_never_panics(s in ".*") {
            // Must not panic on any string input. Err is fine.
            let _ = parse_generalized_time(&s);
        }

        #[test]
        fn parse_generalized_time_valid_range_accepted(
            year in 1970u32..2100,
            month in 1u32..=12,
            day in 1u32..=28,   // 28 safe across all months
            hour in 0u32..=23,
            min in 0u32..=59,
            sec in 0u32..=59,
        ) {
            let s = format!("{:04}{:02}{:02}{:02}{:02}{:02}Z", year, month, day, hour, min, sec);
            prop_assert!(parse_generalized_time(&s).is_ok(), "valid date rejected: {}", s);
        }

        #[test]
        fn parse_generalized_time_out_of_range_rejected(
            hour in 24u32..=99,
        ) {
            let s = format!("20240115{:02}0000Z", hour);
            prop_assert!(parse_generalized_time(&s).is_err());
        }

        #[test]
        fn civil_to_days_monotone(
            y in 1970i64..2100,
            m in 1i64..=11,  // m+1 always valid
            d in 1i64..=27,  // d+1 always valid
        ) {
            let d1 = civil_to_days(y, m, d).unwrap();
            let d2 = civil_to_days(y, m, d + 1).unwrap();
            prop_assert!(d1 < d2, "day+1 must produce larger day count");
        }

        #[test]
        fn civil_to_days_pre_epoch_rejected(y in 1900i64..=1969) {
            prop_assert!(civil_to_days(y, 6, 15).is_err());
        }
    }
}
