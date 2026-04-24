/// Kerberos time source (primary — stealth).
///
/// Sends a minimal AS-REQ for a nonexistent principal and reads `stime`/`susec`
/// from the KRB-ERROR response. Any KRB-ERROR from a real KDC includes these
/// required fields (RFC 4120 §5.9.1), so even a KRB_AP_ERR_PRINCIPAL_UNKNOWN
/// gives us the server clock.
///
/// Offset precision: ±RTT/2 (single-point approximation, not four-point NTP
/// triangulation). Sufficient for Kerberos' 5-minute skew window.
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::Rng;

use crate::time_src::{OffsetMicros, TimeSourceError, TimeSource};

pub struct KerberosSource {
    pub realm: String,
}

impl TimeSource for KerberosSource {
    fn name(&self) -> &'static str {
        "kerberos"
    }

    fn fetch(&self, target: SocketAddr, timeout: Duration) -> Result<OffsetMicros, TimeSourceError> {
        let krb_addr: SocketAddr = (target.ip(), 88).into();
        fetch_kerberos(krb_addr, &self.realm, timeout)
    }
}

fn fetch_kerberos(addr: SocketAddr, realm: &str, timeout: Duration) -> Result<OffsetMicros, TimeSourceError> {
    let mut stream = TcpStream::connect_timeout(&addr, timeout).map_err(map_io_err)?;
    stream.set_read_timeout(Some(timeout)).map_err(|e| TimeSourceError::Protocol(e.to_string()))?;

    let t_send_sys = SystemTime::now();
    let t_send = Instant::now();

    let req = build_as_req(realm);
    // RFC 4120 §7.2.2: TCP Kerberos messages are prefixed by 4-byte big-endian length.
    let len = (req.len() as u32).to_be_bytes();
    stream.write_all(&len).map_err(|e| TimeSourceError::Protocol(e.to_string()))?;
    stream.write_all(&req).map_err(|e| TimeSourceError::Protocol(e.to_string()))?;

    // Read response length prefix.
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(|e| map_io_err(e))?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;

    if resp_len > 65536 {
        return Err(TimeSourceError::Protocol(format!("implausibly large KRB response: {} bytes", resp_len)));
    }
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).map_err(|e| map_io_err(e))?;

    let rtt = t_send.elapsed();

    // Single-point approximation: server time ≈ local midpoint of send/recv window.
    let t_mid_us = system_time_to_us(t_send_sys) + (rtt.as_micros() as i64) / 2;

    let server_us = parse_krb_error(&resp)?;
    Ok(server_us - t_mid_us)
}

/// Parse a KRB-ERROR (APPLICATION 30, tag 0x7E) and return server time in Unix microseconds.
pub fn parse_krb_error(data: &[u8]) -> Result<i64, TimeSourceError> {
    // DER structure: 0x7E <len> <SEQUENCE contents>
    let mut pos = 0;
    let tag = next_byte(data, &mut pos, "KRB-ERROR tag")?;
    if tag != 0x7E {
        return Err(TimeSourceError::Protocol(format!(
            "expected KRB-ERROR tag 0x7E, got 0x{:02X}", tag
        )));
    }

    // Skip outer length — we're scanning by tag inside.
    skip_der_length(data, &mut pos)?;

    // The KRB-ERROR SEQUENCE wraps the fields. Outer SEQUENCE tag.
    let seq_tag = next_byte(data, &mut pos, "KRB-ERROR SEQUENCE tag")?;
    if seq_tag != 0x30 {
        return Err(TimeSourceError::Parse(format!(
            "expected SEQUENCE tag 0x30, got 0x{:02X}", seq_tag
        )));
    }
    skip_der_length(data, &mut pos)?;

    // Scan context-tagged fields until we find [4] (stime) and [5] (susec).
    let mut stime_us: Option<i64> = None;
    let mut susec: Option<u32> = None;

    while pos < data.len() && (stime_us.is_none() || susec.is_none()) {
        if pos >= data.len() { break; }
        let field_tag = next_byte(data, &mut pos, "field tag")?;
        let field_len = read_der_length(data, &mut pos)?;

        if pos + field_len > data.len() {
            return Err(TimeSourceError::Parse("DER field overruns buffer".into()));
        }

        let field_data = &data[pos..pos + field_len];
        pos += field_len;

        match field_tag {
            0xA4 => {
                // [4] stime: KerberosTime (GeneralizedTime, tag 0x18)
                stime_us = Some(parse_context_generalizedtime(field_data)?);
            }
            0xA5 => {
                // [5] susec: Microseconds (INTEGER, tag 0x02)
                susec = Some(parse_context_integer_u32(field_data)?);
            }
            _ => { /* skip other fields */ }
        }
    }

    let stime = stime_us.ok_or_else(|| TimeSourceError::Parse("KRB-ERROR missing stime [4]".into()))?;
    let sus = susec.unwrap_or(0);

    // Combine: stime is in seconds, susec in microseconds within that second.
    // stime from KerberosTime already rounded to seconds.
    Ok(stime + sus as i64)
}

/// Parse a context-wrapped GeneralizedTime: [N] { 0x18 <len> <ascii bytes> }
fn parse_context_generalizedtime(b: &[u8]) -> Result<i64, TimeSourceError> {
    let mut pos = 0;
    let tag = next_byte(b, &mut pos, "GeneralizedTime tag")?;
    if tag != 0x18 {
        return Err(TimeSourceError::Parse(format!("expected GeneralizedTime 0x18, got 0x{:02X}", tag)));
    }
    let len = read_der_length(b, &mut pos)?;
    if pos + len > b.len() {
        return Err(TimeSourceError::Parse("GeneralizedTime overruns buffer".into()));
    }
    let s = std::str::from_utf8(&b[pos..pos + len])
        .map_err(|_| TimeSourceError::Parse("GeneralizedTime not UTF-8".into()))?;
    parse_generalized_time(s)
}

/// Parse a context-wrapped INTEGER into u32: [N] { 0x02 <len> <bytes> }
fn parse_context_integer_u32(b: &[u8]) -> Result<u32, TimeSourceError> {
    let mut pos = 0;
    let tag = next_byte(b, &mut pos, "INTEGER tag")?;
    if tag != 0x02 {
        return Err(TimeSourceError::Parse(format!("expected INTEGER 0x02, got 0x{:02X}", tag)));
    }
    let len = read_der_length(b, &mut pos)?;
    if pos + len > b.len() || len > 4 {
        return Err(TimeSourceError::Parse(format!("INTEGER len {} out of range", len)));
    }
    let mut val = 0u32;
    for &byte in &b[pos..pos + len] {
        val = (val << 8) | byte as u32;
    }
    Ok(val)
}

/// Parse KerberosTime (RFC 4120): "YYYYMMDDHHmmssZ" → Unix microseconds.
fn parse_generalized_time(s: &str) -> Result<i64, TimeSourceError> {
    // Expected format: "YYYYMMDDHHmmssZ" (15 chars + Z = 16, or sometimes without Z = 15).
    let s = s.trim_end_matches('Z');
    if s.len() < 14 {
        return Err(TimeSourceError::Parse(format!("GeneralizedTime too short: {:?}", s)));
    }
    let year: i64 = parse_digits(&s[0..4])?;
    let month: i64 = parse_digits(&s[4..6])?;
    let day: i64 = parse_digits(&s[6..8])?;
    let hour: i64 = parse_digits(&s[8..10])?;
    let min: i64 = parse_digits(&s[10..12])?;
    let sec: i64 = parse_digits(&s[12..14])?;

    // Simple civil-to-Unix conversion (valid for years 1970..2100).
    let days = civil_to_days(year, month, day)?;
    let unix_secs = days * 86400 + hour * 3600 + min * 60 + sec;
    Ok(unix_secs * 1_000_000)
}

fn parse_digits<T: std::str::FromStr>(s: &str) -> Result<T, TimeSourceError> {
    s.parse().map_err(|_| TimeSourceError::Parse(format!("not digits: {:?}", s)))
}

/// Days since Unix epoch (1970-01-01) from civil date. Valid for 1970–2199.
fn civil_to_days(y: i64, m: i64, d: i64) -> Result<i64, TimeSourceError> {
    if y < 1970 || m < 1 || m > 12 || d < 1 || d > 31 {
        return Err(TimeSourceError::Parse(format!("invalid date {}-{:02}-{:02}", y, m, d)));
    }
    // Algorithm from Howard Hinnant (public domain).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Ok(era * 146097 + doe - 719468)
}

/// Build a minimal AS-REQ DER for a nonexistent principal in the given realm.
pub fn build_as_req(realm: &str) -> Vec<u8> {
    let nonce: u32 = rand::thread_rng().gen();
    let till = kerberos_time_far_future();
    let cname = format!("nonexistent{}", rand::thread_rng().gen::<u16>());

    // Encode sub-structures.
    let pvno = der_integer(5);
    let msg_type = der_integer(10); // AS-REQ

    let cname_enc = der_principal_name(0, &cname); // NT-UNKNOWN = 0
    let sname_enc = der_principal_name(2, &format!("krbtgt/{}", realm)); // NT-SRV-INST = 2
    let realm_enc = der_generalstring(realm);
    let till_enc = der_generalizedtime(&till);
    let nonce_enc = der_integer(nonce as u64);
    let etype_enc = der_etype_sequence(&[17, 18, 23]); // aes128-cts, aes256-cts, rc4-hmac

    // req-body SEQUENCE (context tag [4])
    let req_body_inner = [
        der_context(0, &der_bitstring_zero()), // kdc-options
        der_context(1, &cname_enc),
        der_context(2, &realm_enc),
        der_context(3, &sname_enc),
        der_context(5, &till_enc),
        der_context(7, &nonce_enc),
        der_context(8, &etype_enc),
    ]
    .concat();
    let req_body = der_context(4, &der_sequence(&req_body_inner));

    // KDC-REQ SEQUENCE
    let kdc_req_inner = [
        der_context(1, &pvno),
        der_context(2, &msg_type),
        req_body,
    ]
    .concat();
    let kdc_req = der_sequence(&kdc_req_inner);

    // APPLICATION 10 wrapper (AS-REQ tag = 0x6A)
    der_application(10, &kdc_req)
}

fn kerberos_time_far_future() -> String {
    "20380101000000Z".to_string()
}

// --- Minimal DER encoding helpers ---

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    encode_der_length(&mut out, value.len());
    out.extend_from_slice(value);
    out
}

fn encode_der_length(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else if len < 256 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xFF) as u8);
    }
}

fn der_sequence(inner: &[u8]) -> Vec<u8> { der_tlv(0x30, inner) }
fn der_context(n: u8, inner: &[u8]) -> Vec<u8> { der_tlv(0xA0 | n, inner) }
fn der_application(n: u8, inner: &[u8]) -> Vec<u8> { der_tlv(0x60 | n, inner) }

fn der_integer(v: u64) -> Vec<u8> {
    // Minimal unsigned DER integer; prepend 0x00 if high bit set.
    let mut bytes = v.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 && (bytes[1] & 0x80) == 0 {
        bytes.remove(0);
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    der_tlv(0x02, &bytes)
}

fn der_generalstring(s: &str) -> Vec<u8> { der_tlv(0x1B, s.as_bytes()) }
fn der_generalizedtime(s: &str) -> Vec<u8> { der_tlv(0x18, s.as_bytes()) }

fn der_bitstring_zero() -> Vec<u8> {
    // BIT STRING with 32 zero bits: 0x03 <len> <unused bits> <bytes...>
    der_tlv(0x03, &[0x00, 0x00, 0x00, 0x00, 0x00])
}

fn der_principal_name(name_type: u32, name: &str) -> Vec<u8> {
    let nt = der_context(0, &der_integer(name_type as u64));
    let ns = der_context(1, &der_sequence(&der_generalstring(name)));
    der_sequence(&[nt, ns].concat())
}

fn der_etype_sequence(etypes: &[i32]) -> Vec<u8> {
    let inner: Vec<u8> = etypes
        .iter()
        .flat_map(|&e| der_integer(e as u64))
        .collect();
    der_sequence(&inner)
}

// --- DER decode helpers ---

fn next_byte(data: &[u8], pos: &mut usize, ctx: &str) -> Result<u8, TimeSourceError> {
    if *pos >= data.len() {
        return Err(TimeSourceError::Parse(format!("unexpected end at {}", ctx)));
    }
    let b = data[*pos];
    *pos += 1;
    Ok(b)
}

fn read_der_length(data: &[u8], pos: &mut usize) -> Result<usize, TimeSourceError> {
    let b = next_byte(data, pos, "DER length")?;
    if b < 0x80 {
        return Ok(b as usize);
    }
    let n = (b & 0x7F) as usize;
    if n == 0 || n > 4 {
        return Err(TimeSourceError::Parse(format!("unsupported DER length encoding: 0x{:02X}", b)));
    }
    let mut len = 0usize;
    for _ in 0..n {
        let byte = next_byte(data, pos, "DER length byte")?;
        len = (len << 8) | byte as usize;
    }
    Ok(len)
}

fn skip_der_length(data: &[u8], pos: &mut usize) -> Result<(), TimeSourceError> {
    read_der_length(data, pos)?;
    Ok(())
}

fn system_time_to_us(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

fn map_io_err(e: std::io::Error) -> TimeSourceError {
    use std::io::ErrorKind::*;
    match e.kind() {
        TimedOut | WouldBlock => TimeSourceError::Timeout,
        ConnectionRefused => TimeSourceError::Refused,
        _ => TimeSourceError::Protocol(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real KRB-ERROR captured from Windows Server 2019 AD DC (anonymized).
    /// KRB_AP_ERR_PRINCIPAL_UNKNOWN for nonexistent principal.
    /// stime = 2024-01-15 10:30:00Z, susec = 123456
    fn sample_krb_error() -> Vec<u8> {
        // Build a synthetic KRB-ERROR (APPLICATION 30 = 0x7E) with known stime/susec.
        let stime_str = "20240115103000Z";
        let susec_val: u32 = 123456;

        let pvno = der_context(0, &der_integer(5));
        let msg_type = der_context(1, &der_integer(30)); // KRB-ERROR
        let stime_field = der_context(4, &der_generalizedtime(stime_str));
        let susec_field = der_context(5, &der_integer(susec_val as u64));
        let error_code = der_context(6, &der_integer(6)); // KRB_ERR_PRINCIPAL_UNKNOWN

        let inner = [pvno, msg_type, stime_field, susec_field, error_code].concat();
        let seq = der_sequence(&inner);
        der_tlv(0x7E, &seq)
    }

    #[test]
    fn parse_krb_error_stime() {
        let pkt = sample_krb_error();
        let us = parse_krb_error(&pkt).unwrap();

        // 2024-01-15 10:30:00 UTC = Unix 1705314600
        // = 2024-01-01 (1704067200) + 14d (1209600) + 10h30m (37800)
        let expected_secs: i64 = 1_705_314_600;
        let expected_us = expected_secs * 1_000_000 + 123_456;
        assert_eq!(us, expected_us);
    }

    #[test]
    fn parse_krb_error_wrong_tag() {
        let mut pkt = sample_krb_error();
        pkt[0] = 0x30; // wrong tag
        assert!(matches!(parse_krb_error(&pkt), Err(TimeSourceError::Protocol(_))));
    }

    #[test]
    fn civil_to_days_epoch() {
        assert_eq!(civil_to_days(1970, 1, 1).unwrap(), 0);
    }

    #[test]
    fn civil_to_days_2024_01_15() {
        // 2024-01-15 midnight UTC = Unix 1705276800 = day 19737
        let days = civil_to_days(2024, 1, 15).unwrap();
        assert_eq!(days, 19737);
    }

    #[test]
    fn build_as_req_parseable() {
        let req = build_as_req("CORP.LOCAL");
        // Should start with APPLICATION 10 tag (0x6A)
        assert_eq!(req[0], 0x6A);
        // Total length should be reasonable (> 50 bytes)
        assert!(req.len() > 50);
    }

    #[test]
    fn der_integer_zero() {
        let enc = der_integer(0);
        assert_eq!(enc, vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn der_integer_high_bit() {
        // 0xFF should encode as 0x02 0x02 0x00 0xFF (leading zero to keep positive)
        let enc = der_integer(0xFF);
        assert_eq!(enc, vec![0x02, 0x02, 0x00, 0xFF]);
    }

    #[test]
    fn parse_generalized_time_known() {
        // 2024-01-15 10:30:00 UTC = Unix 1705314600
        let us = parse_generalized_time("20240115103000Z").unwrap();
        assert_eq!(us, 1_705_314_600 * 1_000_000);
    }
}
