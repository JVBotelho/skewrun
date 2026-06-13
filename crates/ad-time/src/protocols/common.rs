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
