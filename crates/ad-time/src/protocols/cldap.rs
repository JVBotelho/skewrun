//! CLDAP (UDP/389) rootDSE time extraction.
//!
//! Protocol Specifications:
//! - **RFC 4511 §4.5**: Search Operation
//! - **RFC 4512 §5.1**: rootDSE
//! - **MS-ADTS §3.1.1.3.2.1**: root DSE (currentTime attribute)
//!
//! Windows domain controllers reply to connectionless LDAP (CLDAP) queries on UDP 389.
//! This is typically used for "DC Locator Pings" by Windows workstations. We mimic
//! this legitimate background noise to stealthily request the `currentTime` attribute
//! from the `rootDSE`.
//!
//! OPSEC:
//! - UDP/389 is practically invisible to typical EDRs and is rarely DPI'd or rate-limited.
//! - The query pattern (rootDSE `objectClass=*` base search) matches the baseline of
//!   `ldapsearch`, PowerShell AD cmdlets, and monitoring agents — not DC Locator Pings,
//!   which use a different filter and attribute set.
//! - The attribute list is diluted with common admin attrs so `currentTime` does not appear
//!   as a surgical probe.
//! - `messageID` and `timeLimit` are randomized to break static NDR signatures.

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime};

use rand::Rng;

use super::ber::{encode_integer_i32, encode_tlv};
use super::common::{map_io_err, parse_generalized_time, system_time_to_us};
use crate::time_src::{OffsetMicros, TimeSource, TimeSourceError};

pub struct CldapSource;

impl TimeSource for CldapSource {
    fn name(&self) -> &'static str {
        "cldap"
    }

    fn fetch(
        &self,
        target: SocketAddr,
        timeout: Duration,
    ) -> Result<OffsetMicros, TimeSourceError> {
        let addr: SocketAddr = (target.ip(), 389).into();
        fetch_cldap(addr, timeout)
    }
}

fn fetch_cldap(addr: SocketAddr, timeout: Duration) -> Result<OffsetMicros, TimeSourceError> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| map_io_err(e, "bind"))?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|e| map_io_err(e, "set_read_timeout"))?;
    socket
        .set_write_timeout(Some(timeout))
        .map_err(|e| map_io_err(e, "set_write_timeout"))?;

    // OPSEC: Randomize message ID (1..1000)
    let msg_id = rand::thread_rng().gen_range(1..=1000);

    let req = build_cldap_search_request(msg_id);

    let t_send = Instant::now();
    let t_send_sys = SystemTime::now();

    socket
        .send_to(&req, addr)
        .map_err(|e| map_io_err(e, "send_to"))?;

    // Enforce an overall deadline across the receive loop. Without it, an on-path
    // attacker or a UDP flood with spoofed source IPs could keep the loop spinning
    // indefinitely (each non-matching packet returns within the per-call timeout).
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 4096];
    let len = loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(TimeSourceError::Timeout)?;
        socket
            .set_read_timeout(Some(remaining))
            .map_err(|e| map_io_err(e, "set_read_timeout"))?;

        let (len, src) = socket
            .recv_from(&mut buf)
            .map_err(|e| map_io_err(e, "recv_from"))?;
        if src.ip() == addr.ip() {
            break len;
        }
    };

    let rtt = t_send.elapsed();
    let resp = &buf[..len];

    let server_time = parse_cldap_search_response(resp, msg_id)?;

    let t_mid_us = system_time_to_us(t_send_sys)? + (rtt.as_micros() as i64) / 2;
    let server_us = system_time_to_us(server_time)?;

    Ok(server_us - t_mid_us)
}

fn build_cldap_search_request(msg_id: i32) -> Vec<u8> {
    // timeLimit = 0: no client-imposed limit. Standard per RFC 4511 §4.5.1 and
    // the observed behavior of ldapsearch, PowerShell AD cmdlets, and monitoring tools.
    // A randomized 10-30 range has no documented baseline and is self-generated noise.
    let time_limit_enc = encode_integer_i32(0);

    let base_object = encode_tlv(0x04, b""); // LDAPDN ""
    let scope = encode_tlv(0x0a, &[0]); // ENUMERATED 0 (baseObject)
    let deref = encode_tlv(0x0a, &[0]); // ENUMERATED 0 (neverDerefAliases)
    let size_limit = encode_integer_i32(1); // INTEGER 1
    let types_only = encode_tlv(0x01, &[0x00]); // BOOLEAN FALSE

    // Filter: (objectClass=*)
    // RFC 4511 4.5.1: present is context-specific, primitive, tag 7
    let filter = encode_tlv(0x87, b"objectClass");

    // Attributes to request
    let attrs = vec![
        "schemaNamingContext",
        "namingContexts",
        "currentTime",
        "dnsHostName",
        "supportedLDAPVersion",
    ];
    let mut attrs_seq = Vec::new();
    for a in attrs {
        attrs_seq.extend_from_slice(&encode_tlv(0x04, a.as_bytes()));
    }
    let attributes = encode_tlv(0x30, &attrs_seq); // SEQUENCE OF LDAPString

    let mut search_req_seq = Vec::new();
    search_req_seq.extend_from_slice(&base_object);
    search_req_seq.extend_from_slice(&scope);
    search_req_seq.extend_from_slice(&deref);
    search_req_seq.extend_from_slice(&size_limit);
    search_req_seq.extend_from_slice(&time_limit_enc);
    search_req_seq.extend_from_slice(&types_only);
    search_req_seq.extend_from_slice(&filter);
    search_req_seq.extend_from_slice(&attributes);

    let protocol_op = encode_tlv(0x63, &search_req_seq); // [APPLICATION 3] (searchRequest)

    let mut ldap_msg_seq = Vec::new();
    ldap_msg_seq.extend_from_slice(&encode_integer_i32(msg_id));
    ldap_msg_seq.extend_from_slice(&protocol_op);

    encode_tlv(0x30, &ldap_msg_seq) // SEQUENCE (LDAPMessage)
}

/// Simple BER decoder struct for scanning LDAP responses.
struct BerReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> BerReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_tlv(&mut self) -> Result<(u8, &'a [u8]), TimeSourceError> {
        if self.pos >= self.buf.len() {
            return Err(TimeSourceError::Parse("Unexpected EOF in BER".into()));
        }
        let tag = self.buf[self.pos];
        self.pos += 1;

        if self.pos >= self.buf.len() {
            return Err(TimeSourceError::Parse(
                "Unexpected EOF reading BER length".into(),
            ));
        }
        let mut len = self.buf[self.pos] as usize;
        self.pos += 1;

        if len & 0x80 != 0 {
            let len_bytes = len & 0x7F;
            let end_bytes = self
                .pos
                .checked_add(len_bytes)
                .ok_or_else(|| TimeSourceError::Parse("BER length overflow".into()))?;
            if len_bytes == 0 || end_bytes > self.buf.len() {
                return Err(TimeSourceError::Parse(
                    "Invalid BER long form length".into(),
                ));
            }
            let mut actual_len = 0;
            for i in 0..len_bytes {
                actual_len = (actual_len << 8) | (self.buf[self.pos + i] as usize);
            }
            self.pos += len_bytes;
            len = actual_len;
        }

        let end_pos = self
            .pos
            .checked_add(len)
            .ok_or_else(|| TimeSourceError::Parse("BER value length overflow".into()))?;
        if end_pos > self.buf.len() {
            return Err(TimeSourceError::Parse(
                "BER value length exceeds buffer".into(),
            ));
        }

        let val = &self.buf[self.pos..end_pos];
        self.pos = end_pos;

        Ok((tag, val))
    }

    fn has_more(&self) -> bool {
        self.pos < self.buf.len()
    }
}

fn parse_cldap_search_response(
    resp: &[u8],
    expected_msg_id: i32,
) -> Result<SystemTime, TimeSourceError> {
    let mut msg_reader = BerReader::new(resp);
    let (tag, msg_val) = msg_reader.read_tlv()?;
    if tag != 0x30 {
        return Err(TimeSourceError::Parse(
            "Expected LDAPMessage SEQUENCE".into(),
        ));
    }

    let mut inner = BerReader::new(msg_val);

    // 1. messageID
    let (id_tag, id_val) = inner.read_tlv()?;
    if id_tag != 0x02 {
        return Err(TimeSourceError::Parse("Expected messageID INTEGER".into()));
    }
    if id_val.len() > 4 {
        return Err(TimeSourceError::Parse("messageID too long".into()));
    }
    let mut msg_id = 0;
    for &b in id_val {
        msg_id = (msg_id << 8) | (b as i32);
    }
    if msg_id != expected_msg_id {
        return Err(TimeSourceError::Protocol("Message ID mismatch".into()));
    }

    // 2. protocolOp (SearchResultEntry [APPLICATION 4])
    let (op_tag, op_val) = inner.read_tlv()?;
    if op_tag != 0x64 {
        // SearchResEntry
        return Err(TimeSourceError::Protocol(format!(
            "Expected SearchResEntry (0x64), got 0x{:02X}",
            op_tag
        )));
    }

    let mut entry = BerReader::new(op_val);
    let (_dn_tag, _dn_val) = entry.read_tlv()?; // objectName LDAPDN

    let (attr_tag, attr_val) = entry.read_tlv()?; // attributes PartialAttributeList (SEQUENCE)
    if attr_tag != 0x30 {
        return Err(TimeSourceError::Parse(
            "Expected attributes SEQUENCE".into(),
        ));
    }

    let mut attrs = BerReader::new(attr_val);
    while attrs.has_more() {
        let (seq_tag, seq_val) = attrs.read_tlv()?;
        if seq_tag != 0x30 {
            continue;
        }

        let mut attr = BerReader::new(seq_val);
        let (type_tag, type_val) = attr.read_tlv()?;
        if type_tag != 0x04 {
            continue;
        } // OCTET STRING

        if type_val == b"currentTime" {
            let (set_tag, set_val) = attr.read_tlv()?;
            if set_tag != 0x31 {
                // SET OF
                return Err(TimeSourceError::Parse(
                    "Expected SET OF for attribute values".into(),
                ));
            }

            let mut vals = BerReader::new(set_val);
            let (v_tag, v_val) = vals.read_tlv()?;
            if v_tag != 0x04 {
                return Err(TimeSourceError::Parse(
                    "Expected OCTET STRING for currentTime".into(),
                ));
            }

            let time_str = std::str::from_utf8(v_val)
                .map_err(|_| TimeSourceError::Parse("currentTime is not valid UTF-8".into()))?;

            return parse_generalized_time(time_str);
        }
    }

    Err(TimeSourceError::Parse(
        "currentTime attribute not found in CLDAP response".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    #[test]
    fn parse_generalized_time_works() {
        // Active Directory often returns ".0Z" fractional seconds
        let t1 = parse_generalized_time("20240115000000.0Z").unwrap();
        let t2 = parse_generalized_time("20240115000000Z").unwrap();
        assert_eq!(t1, t2);

        let d = t1.duration_since(UNIX_EPOCH).unwrap().as_secs();
        // 2024-01-15 00:00:00 UTC = 1705276800
        assert_eq!(d, 1_705_276_800);
    }

    #[test]
    fn build_cldap_search_request_structure() {
        let req = build_cldap_search_request(123);
        // Should be a SEQUENCE
        assert_eq!(req[0], 0x30);
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn parse_cldap_search_response_never_panics(
            data in proptest::collection::vec(any::<u8>(), 0..512),
        ) {
            let _ = parse_cldap_search_response(&data, 1);
        }
    }
}

#[cfg(feature = "fuzzing")]
pub fn fuzz_parse_cldap_response(
    resp: &[u8],
    msg_id: i32,
) -> Result<std::time::SystemTime, crate::time_src::TimeSourceError> {
    parse_cldap_search_response(resp, msg_id)
}
