/// SNTP client (RFC 4330) — fallback time source on UDP/123.
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::time_src::{OffsetMicros, TimeSourceError, TimeSource};

pub struct NtpSource;

// Seconds between NTP epoch (1900-01-01) and Unix epoch (1970-01-01).
const NTP_TO_UNIX: u64 = 2_208_988_800;

impl TimeSource for NtpSource {
    fn name(&self) -> &'static str {
        "ntp"
    }

    fn fetch(&self, target: SocketAddr, timeout: Duration) -> Result<OffsetMicros, TimeSourceError> {
        let ntp_addr: SocketAddr = (target.ip(), 123).into();
        fetch_ntp(ntp_addr, timeout)
    }
}

fn fetch_ntp(addr: SocketAddr, timeout: Duration) -> Result<OffsetMicros, TimeSourceError> {
    let socket = UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
        .map_err(|e| TimeSourceError::Protocol(e.to_string()))?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|e| TimeSourceError::Protocol(e.to_string()))?;

    // Build 48-byte SNTP request: LI=0, VN=4, Mode=3.
    let mut req = [0u8; 48];
    req[0] = 0b00_100_011; // LI=0 VN=4 Mode=3

    // t1: local time before send, as NTP timestamp.
    let t1_sys = SystemTime::now();
    let t1_ntp = system_time_to_ntp(t1_sys);
    req[40..44].copy_from_slice(&t1_ntp.0.to_be_bytes());
    req[44..48].copy_from_slice(&t1_ntp.1.to_be_bytes());

    let t_send = Instant::now();
    socket
        .send_to(&req, addr)
        .map_err(|e| map_io_err(e, "send"))?;

    let mut buf = [0u8; 48];
    let (n, _) = socket
        .recv_from(&mut buf)
        .map_err(|e| map_io_err(e, "recv"))?;
    let rtt = t_send.elapsed();

    if n < 48 {
        return Err(TimeSourceError::Parse(format!("short NTP response: {} bytes", n)));
    }

    let mode = buf[0] & 0x07;
    if mode != 4 && mode != 5 {
        return Err(TimeSourceError::Protocol(format!("unexpected NTP mode: {}", mode)));
    }

    // t2 = receive timestamp (server received our packet), bytes 32..40
    let t2 = parse_ntp_timestamp(&buf[32..40])?;
    // t3 = transmit timestamp (server sent the response), bytes 40..48
    let t3 = parse_ntp_timestamp(&buf[40..48])?;

    // t4 = local time at receive; approximate as t1 + RTT.
    let t4_us = system_time_to_us(t1_sys) + rtt.as_micros() as i64;

    // RFC 4330 offset: ((t2 - t1) + (t3 - t4)) / 2
    let t1_us = system_time_to_us(t1_sys);
    let offset_us = ((t2 - t1_us) + (t3 - t4_us)) / 2;

    Ok(offset_us)
}

/// Parse 8-byte NTP timestamp (u32 seconds + u32 fraction) into Unix microseconds.
fn parse_ntp_timestamp(b: &[u8]) -> Result<i64, TimeSourceError> {
    if b.len() < 8 {
        return Err(TimeSourceError::Parse("NTP timestamp too short".into()));
    }
    let secs = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64;
    let frac = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);

    if secs < NTP_TO_UNIX as u32 as u64 {
        return Err(TimeSourceError::Parse(format!("NTP seconds {} predates Unix epoch", secs)));
    }
    let unix_secs = secs - NTP_TO_UNIX;
    // Integer-only: frac * 1_000_000 / 2^32 microseconds
    let frac_us = (frac as u64 * 1_000_000) >> 32;
    Ok((unix_secs * 1_000_000 + frac_us) as i64)
}

/// Convert SystemTime to (NTP seconds, NTP fraction).
fn system_time_to_ntp(t: SystemTime) -> (u32, u32) {
    let dur = t.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let ntp_secs = (dur.as_secs() + NTP_TO_UNIX) as u32;
    // fraction: subsec_nanos * 2^32 / 1_000_000_000
    let frac = ((dur.subsec_nanos() as u64) << 32) / 1_000_000_000;
    (ntp_secs, frac as u32)
}

/// Convert SystemTime to microseconds since Unix epoch.
fn system_time_to_us(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

fn map_io_err(e: std::io::Error, op: &str) -> TimeSourceError {
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

    #[test]
    fn parse_known_ntp_timestamp() {
        // NTP seconds 3913958400 = 2024-01-01 00:00:00 UTC
        // Unix = 3913958400 - 2208988800 = 1704969600
        let secs: u32 = 3_913_958_400;
        let frac: u32 = 0;
        let mut b = [0u8; 8];
        b[0..4].copy_from_slice(&secs.to_be_bytes());
        b[4..8].copy_from_slice(&frac.to_be_bytes());
        let us = parse_ntp_timestamp(&b).unwrap();
        assert_eq!(us, 1_704_969_600 * 1_000_000);
    }

    #[test]
    fn parse_ntp_with_fraction() {
        // NTP secs for Unix 0 = 2208988800, frac = 2^31 = 0.5s = 500_000us
        let secs: u32 = NTP_TO_UNIX as u32;
        let frac: u32 = 1 << 31;
        let mut b = [0u8; 8];
        b[0..4].copy_from_slice(&secs.to_be_bytes());
        b[4..8].copy_from_slice(&frac.to_be_bytes());
        let us = parse_ntp_timestamp(&b).unwrap();
        assert_eq!(us, 500_000);
    }

    #[test]
    fn roundtrip_ntp_conversion() {
        let now = SystemTime::now();
        let (secs, frac) = system_time_to_ntp(now);
        let mut b = [0u8; 8];
        b[0..4].copy_from_slice(&secs.to_be_bytes());
        b[4..8].copy_from_slice(&frac.to_be_bytes());
        let us = parse_ntp_timestamp(&b).unwrap();
        let expected = system_time_to_us(now);
        // Allow 1ms rounding error from integer division
        assert!((us - expected).abs() < 1000, "roundtrip error: {}us", us - expected);
    }
}
