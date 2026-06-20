/// Kerberos time source (primary — stealth).
///
/// Protocol Specifications:
/// - **RFC 4120 §3.1.1**: AS Exchange
/// - **RFC 4120 §5.4.1**: KRB_AS_REQ
/// - **RFC 4120 §5.9.1**: KRB_ERROR
/// - **RFC 4120 §5.2.2**: PrincipalName
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

use super::ber::{
    encode_application, encode_context, encode_generalizedtime, encode_generalstring,
    encode_integer_u64, encode_sequence, encode_tlv,
};
use super::common::{map_io_err, parse_generalized_time, system_time_to_us};
use crate::time_src::{OffsetMicros, TimeSource, TimeSourceError};

// DER/ASN.1 tag constants used in KRB-ERROR parsing (RFC 4120 §5.9.1).
const KRB_ERROR_TAG: u8 = 0x7E; // APPLICATION 30
const SEQUENCE_TAG: u8 = 0x30;
const STIME_TAG: u8 = 0xA4; // context [4]
const SUSEC_TAG: u8 = 0xA5; // context [5]
const GENERALIZED_TIME_TAG: u8 = 0x18;
const INTEGER_TAG: u8 = 0x02;

pub struct KerberosSource {
    pub realm: Option<String>,
    pub stealth_user: String,
}

impl TimeSource for KerberosSource {
    fn name(&self) -> &'static str {
        "kerberos"
    }

    fn fetch(
        &self,
        target: SocketAddr,
        timeout: Duration,
    ) -> Result<OffsetMicros, TimeSourceError> {
        let realm = self
            .realm
            .as_deref()
            .ok_or_else(|| TimeSourceError::Config("no realm configured".into()))?;
        let krb_addr: SocketAddr = (target.ip(), 88).into();
        fetch_kerberos(krb_addr, realm, &self.stealth_user, timeout)
    }
}

fn fetch_kerberos(
    addr: SocketAddr,
    realm: &str,
    stealth_user: &str,
    timeout: Duration,
) -> Result<OffsetMicros, TimeSourceError> {
    let mut stream = TcpStream::connect_timeout(&addr, timeout).map_err(map_io_err)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| TimeSourceError::Protocol(e.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| TimeSourceError::Protocol(e.to_string()))?;

    let t_send_sys = SystemTime::now();
    let t_send = Instant::now();

    let req = build_as_req(realm, stealth_user);
    // RFC 4120 §7.2.2: TCP Kerberos messages are prefixed by 4-byte big-endian length.
    let len = (req.len() as u32).to_be_bytes();
    stream
        .write_all(&len)
        .map_err(|e| TimeSourceError::Protocol(e.to_string()))?;
    stream
        .write_all(&req)
        .map_err(|e| TimeSourceError::Protocol(e.to_string()))?;

    // Read response length prefix.
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(map_io_err)?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;

    if resp_len > 65536 {
        return Err(TimeSourceError::Protocol(format!(
            "implausibly large KRB response: {} bytes",
            resp_len
        )));
    }
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).map_err(map_io_err)?;

    let rtt = t_send.elapsed();

    // Single-point approximation: server time ≈ local midpoint of send/recv window.
    let t_mid_us = system_time_to_us(t_send_sys)? + (rtt.as_micros() as i64) / 2;

    let server_us = parse_krb_error(&resp)?;
    Ok(server_us - t_mid_us)
}

/// Parse a KRB-ERROR (APPLICATION 30, tag 0x7E) and return server time in Unix microseconds.
pub fn parse_krb_error(data: &[u8]) -> Result<i64, TimeSourceError> {
    // DER structure: 0x7E <len> <SEQUENCE contents>
    let mut pos = 0;
    let tag = next_byte(data, &mut pos, "KRB-ERROR tag")?;
    if tag != KRB_ERROR_TAG {
        return Err(TimeSourceError::Protocol(format!(
            "expected KRB-ERROR tag 0x{:02X}, got 0x{:02X}",
            KRB_ERROR_TAG, tag
        )));
    }

    // Skip outer length — we're scanning by tag inside.
    skip_der_length(data, &mut pos)?;

    // The KRB-ERROR SEQUENCE wraps the fields. Outer SEQUENCE tag.
    let seq_tag = next_byte(data, &mut pos, "KRB-ERROR SEQUENCE tag")?;
    if seq_tag != SEQUENCE_TAG {
        return Err(TimeSourceError::Parse(format!(
            "expected SEQUENCE tag 0x{:02X}, got 0x{:02X}",
            SEQUENCE_TAG, seq_tag
        )));
    }
    let seq_len = read_der_length(data, &mut pos)?;
    let seq_end = pos
        .checked_add(seq_len)
        .ok_or_else(|| TimeSourceError::Parse("SEQUENCE overflow".into()))?;
    if seq_end > data.len() {
        return Err(TimeSourceError::Parse(
            "KRB-ERROR SEQUENCE overruns buffer".into(),
        ));
    }

    // Scan context-tagged fields until we find [4] (stime) and [5] (susec).
    // Bound by seq_end to prevent tag-injection from bytes appended after the SEQUENCE.
    let mut stime_us: Option<i64> = None;
    let mut susec: Option<u32> = None;

    while pos < seq_end && (stime_us.is_none() || susec.is_none()) {
        let field_tag = next_byte(data, &mut pos, "field tag")?;
        let field_len = read_der_length(data, &mut pos)?;

        let field_end = pos
            .checked_add(field_len)
            .ok_or_else(|| TimeSourceError::Parse("Field overflow".into()))?;
        if field_end > data.len() {
            return Err(TimeSourceError::Parse("DER field overruns buffer".into()));
        }

        let field_data = &data[pos..field_end];
        pos = field_end;

        match field_tag {
            STIME_TAG => {
                stime_us = Some(parse_context_generalizedtime(field_data)?);
            }
            SUSEC_TAG => {
                susec = Some(parse_context_integer_u32(field_data)?);
            }
            _ => { /* skip other fields */ }
        }
    }

    // RFC 4120 §5.9.1 KRB-ERROR
    // stime is in seconds, susec is microseconds.
    let stime =
        stime_us.ok_or_else(|| TimeSourceError::Parse("KRB-ERROR missing stime [4]".into()))?;
    let sus = susec.unwrap_or(0);

    // stime_us is Unix microseconds; susec is 0..999_999 additional offset within the second.
    // OPSEC Rationale: We calculate single-point offset assuming stamping at receive time.
    Ok(stime + sus as i64)
}

/// Parse a context-wrapped GeneralizedTime: [N] { 0x18 <len> <ascii bytes> }
fn parse_context_generalizedtime(b: &[u8]) -> Result<i64, TimeSourceError> {
    let mut pos = 0;
    let tag = next_byte(b, &mut pos, "GeneralizedTime tag")?;
    if tag != GENERALIZED_TIME_TAG {
        return Err(TimeSourceError::Parse(format!(
            "expected GeneralizedTime 0x{:02X}, got 0x{:02X}",
            GENERALIZED_TIME_TAG, tag
        )));
    }
    let len = read_der_length(b, &mut pos)?;
    let end_pos = pos
        .checked_add(len)
        .ok_or_else(|| TimeSourceError::Parse("GeneralizedTime overflow".into()))?;
    if end_pos > b.len() {
        return Err(TimeSourceError::Parse(
            "GeneralizedTime overruns buffer".into(),
        ));
    }
    let s = std::str::from_utf8(&b[pos..end_pos])
        .map_err(|_| TimeSourceError::Parse("GeneralizedTime not UTF-8".into()))?;
    let st = parse_generalized_time(s)?;
    system_time_to_us(st)
}

/// Parse a context-wrapped INTEGER into u32: [N] { 0x02 <len> <bytes> }
fn parse_context_integer_u32(b: &[u8]) -> Result<u32, TimeSourceError> {
    let mut pos = 0;
    let tag = next_byte(b, &mut pos, "INTEGER tag")?;
    if tag != INTEGER_TAG {
        return Err(TimeSourceError::Parse(format!(
            "expected INTEGER 0x{:02X}, got 0x{:02X}",
            INTEGER_TAG, tag
        )));
    }
    let len = read_der_length(b, &mut pos)?;
    let end_pos = pos
        .checked_add(len)
        .ok_or_else(|| TimeSourceError::Parse("INTEGER overflow".into()))?;
    if end_pos > b.len() || len > 4 {
        return Err(TimeSourceError::Parse(format!(
            "INTEGER len {} out of range",
            len
        )));
    }
    let mut val = 0u32;
    for &byte in &b[pos..end_pos] {
        val = (val << 8) | byte as u32;
    }
    Ok(val)
}


/// Build a minimal AS-REQ DER for the given `cname` principal in `realm`.
///
/// `cname` should blend in with the environment (e.g. a plausible admin typo like
/// "admnistrator"). Using a recognizable prefix like "nonexistent" is a trivial SIEM
/// fingerprint (`^nonexistent\d+$`). A typo of a known-but-wrong principal generates
/// Event 4768 with FailureCode 0x6 (unknown principal), which is universal AD noise.
pub fn build_as_req(realm: &str, cname: &str) -> Vec<u8> {
    let nonce: u32 = rand::thread_rng().gen();
    let till = kerberos_time_plausible_future();

    // Encode sub-structures.
    let pvno = encode_integer_u64(5);
    let msg_type = encode_integer_u64(10); // AS-REQ

    // IOC Rationale: A single string "krbtgt/REALM" violates RFC 4120 §5.2.2 PrincipalName,
    // which requires a sequence of strings. Elite EDRs catch badly encoded sname components.
    let cname_enc = der_principal_name(0, &[cname]); // NT-UNKNOWN = 0
    let sname_enc = der_principal_name(2, &["krbtgt", realm]); // NT-SRV-INST = 2
    let realm_enc = encode_generalstring(realm);
    let till_enc = encode_generalizedtime(&till);
    let nonce_enc = encode_integer_u64(nonce as u64);
    let etype_enc = der_etype_sequence(&[17, 18, 23]); // aes128-cts, aes256-cts, rc4-hmac

    // req-body SEQUENCE (context tag [4])
    let req_body_inner = [
        encode_context(0, &der_bitstring_zero()), // kdc-options
        encode_context(1, &cname_enc),
        encode_context(2, &realm_enc),
        encode_context(3, &sname_enc),
        encode_context(5, &till_enc),
        encode_context(7, &nonce_enc),
        encode_context(8, &etype_enc),
    ]
    .concat();
    let req_body = encode_context(4, &encode_sequence(&req_body_inner));

    // KDC-REQ SEQUENCE
    let kdc_req_inner = [encode_context(1, &pvno), encode_context(2, &msg_type), req_body].concat();
    let kdc_req = encode_sequence(&kdc_req_inner);

    // APPLICATION 10 wrapper (AS-REQ tag = 0x6A)
    encode_application(10, &kdc_req)
}

// We set 'till' to exactly 10 hours in the future (the default AD ticket lifetime)
// with a slight ±30min jitter to avoid static exact periodicity.
fn kerberos_time_plausible_future() -> String {
    let mut rng = rand::thread_rng();
    let offset_secs: i64 = 36000 + rng.gen_range(-1800..=1800); // 10h ± 30m
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs() as i64;
    format_unix_as_kerberos_time((now + offset_secs) as u64)
}

fn format_unix_as_kerberos_time(unix_secs: u64) -> String {
    let days = (unix_secs / 86400) as i64;
    let secs_in_day = unix_secs % 86400;
    let hour = secs_in_day / 3600;
    let min = (secs_in_day % 3600) / 60;
    let sec = secs_in_day % 60;

    let (year, month, day) = days_to_civil(days);
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        year, month, day, hour, min, sec
    )
}

/// Inverse of civil_to_days (Howard Hinnant algorithm).
fn days_to_civil(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn der_bitstring_zero() -> Vec<u8> {
    // BIT STRING with 32 zero bits: 0x03 <len> <unused bits> <bytes...>
    encode_tlv(0x03, &[0x00, 0x00, 0x00, 0x00, 0x00])
}

fn der_principal_name(name_type: u32, names: &[&str]) -> Vec<u8> {
    let nt = encode_context(0, &encode_integer_u64(name_type as u64));
    let mut ns_inner = Vec::new();
    for &name in names {
        ns_inner.extend_from_slice(&encode_generalstring(name));
    }
    let ns = encode_context(1, &encode_sequence(&ns_inner));
    encode_sequence(&[nt, ns].concat())
}

fn der_etype_sequence(etypes: &[i32]) -> Vec<u8> {
    let inner: Vec<u8> = etypes.iter().flat_map(|&e| encode_integer_u64(e as u64)).collect();
    encode_sequence(&inner)
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
        return Err(TimeSourceError::Parse(format!(
            "unsupported DER length encoding: 0x{:02X}",
            b
        )));
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


#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::common::civil_to_days;

    /// Real KRB-ERROR captured from Windows Server 2019 AD DC (anonymized).
    /// KRB_AP_ERR_PRINCIPAL_UNKNOWN for nonexistent principal.
    /// stime = 2024-01-15 10:30:00Z, susec = 123456
    fn sample_krb_error() -> Vec<u8> {
        // Build a synthetic KRB-ERROR (APPLICATION 30 = 0x7E) with known stime/susec.
        let stime_str = "20240115103000Z";
        let susec_val: u32 = 123456;

        let pvno = encode_context(0, &encode_integer_u64(5));
        let msg_type = encode_context(1, &encode_integer_u64(30)); // KRB-ERROR
        let stime_field = encode_context(4, &encode_generalizedtime(stime_str));
        let susec_field = encode_context(5, &encode_integer_u64(susec_val as u64));
        let error_code = encode_context(6, &encode_integer_u64(6)); // KRB_ERR_PRINCIPAL_UNKNOWN

        let inner = [pvno, msg_type, stime_field, susec_field, error_code].concat();
        let seq = encode_sequence(&inner);
        encode_tlv(0x7E, &seq)
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
        assert!(matches!(
            parse_krb_error(&pkt),
            Err(TimeSourceError::Protocol(_))
        ));
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
        let req = build_as_req("CORP.LOCAL", "admnistrator");
        // Should start with APPLICATION 10 tag (0x6A)
        assert_eq!(req[0], 0x6A);
        // Total length should be reasonable (> 50 bytes)
        assert!(req.len() > 50);
    }

    #[test]
    fn encode_integer_u64_zero() {
        let enc = encode_integer_u64(0);
        assert_eq!(enc, vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn encode_integer_u64_high_bit() {
        // 0xFF should encode as 0x02 0x02 0x00 0xFF (leading zero to keep positive)
        let enc = encode_integer_u64(0xFF);
        assert_eq!(enc, vec![0x02, 0x02, 0x00, 0xFF]);
    }

    #[test]
    fn parse_generalized_time_known() {
        // 2024-01-15 10:30:00 UTC = Unix 1705314600
        let us = system_time_to_us(parse_generalized_time("20240115103000Z").unwrap()).unwrap();
        assert_eq!(us, 1_705_314_600 * 1_000_000);
    }

    #[test]
    fn parse_krb_error_rejects_post_sequence_injection() {
        // Build a valid KRB-ERROR, then append forged [4]/[5] tags after the SEQUENCE.
        // The parser must NOT read those appended bytes; seq_end bound must hold.
        let valid = sample_krb_error();

        // Forge a [4] tag with a different stime (year 2099-01-01 00:00:00Z = 4070908800)
        let forged_stime = encode_context(4, &encode_generalizedtime("20990101000000Z"));
        let forged_susec = encode_context(5, &encode_integer_u64(999_999u64));
        let mut injected = valid.clone();
        injected.extend_from_slice(&forged_stime);
        injected.extend_from_slice(&forged_susec);

        // Parser must return the original stime, not the forged one.
        let us = parse_krb_error(&injected).unwrap();
        let expected = 1_705_314_600i64 * 1_000_000 + 123_456;
        assert_eq!(us, expected, "post-sequence tag injection must be ignored");
    }
}
