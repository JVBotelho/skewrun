//! NTLM Type 2 Challenge time source — stealthy extraction over SMB TCP/445.
//!
//! Protocol Specifications:
//! - **MS-SMB2 §2.2.5**: SMB2 SESSION_SETUP Request
//! - **MS-SMB2 §2.2.6**: SMB2 SESSION_SETUP Response
//! - **MS-NLMP §2.2.1.1**: NTLMSSP_NEGOTIATE Message (Type 1)
//! - **MS-NLMP §2.2.1.2**: CHALLENGE_MESSAGE (Type 2)
//! - **MS-NLMP §2.2.2.1**: AV_PAIR Structure
//!
//! Sends an SMB2 NEGOTIATE, followed by an SMB2 SESSION_SETUP containing an NTLM Type 1
//! (Negotiate) message. The server responds with STATUS_MORE_PROCESSING_REQUIRED and an
//! NTLM Type 2 (Challenge) message. We extract the `MsvAvTimestamp` (AV_PAIR ID 7) from
//! the TargetInfo structure.
//!
//! This provides 100ns precision. Crucially, we disconnect immediately after receiving
//! the Type 2 challenge, without ever sending a Type 3 (Authenticate) message. Because
//! no credentials are submitted, the LSA does not log a logon attempt, preventing
//! Event IDs 4624/4625.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant, SystemTime};

use super::common::{filetime_to_system_time, system_time_to_us};
use crate::time_src::{OffsetMicros, TimeSource, TimeSourceError};

pub struct NtlmSource;

// SMB2 capabilities
const SMB2_CAPABILITIES: u32 = 0x7F;

impl TimeSource for NtlmSource {
    fn name(&self) -> &'static str {
        "ntlm"
    }

    fn fetch(
        &self,
        target: SocketAddr,
        timeout: Duration,
    ) -> Result<OffsetMicros, TimeSourceError> {
        let smb_addr: SocketAddr = (target.ip(), 445).into();
        fetch_ntlm(smb_addr, timeout)
    }
}

fn fetch_ntlm(addr: SocketAddr, timeout: Duration) -> Result<OffsetMicros, TimeSourceError> {
    let mut stream = TcpStream::connect_timeout(&addr, timeout).map_err(map_io_err)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| TimeSourceError::Protocol(e.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| TimeSourceError::Protocol(e.to_string()))?;

    let t_send = Instant::now();
    let t_send_sys = SystemTime::now();

    // 1. Send SMB2 NEGOTIATE
    let negotiate_req = build_negotiate_request();
    stream
        .write_all(&negotiate_req)
        .map_err(|e| TimeSourceError::Protocol(e.to_string()))?;

    // Read NEGOTIATE response (ignore contents, we just need to consume it)
    let _neg_resp = read_smb_message(&mut stream)?;

    // 2. Send SMB2 SESSION_SETUP with NTLM Type 1
    let session_setup_req = build_session_setup_type1();
    stream
        .write_all(&session_setup_req)
        .map_err(|e| TimeSourceError::Protocol(e.to_string()))?;

    // Read SESSION_SETUP response (contains NTLM Type 2)
    let setup_resp = read_smb_message(&mut stream)?;

    // 3. IMPORTANT OPSEC: Disconnect immediately! Do not send Type 3.
    // This aborts the NTLM handshake before the DC's LSA validates credentials,
    // avoiding Event ID 4625 (Logon Failure).
    drop(stream);

    let rtt = t_send.elapsed();

    let server_time = parse_session_setup_response(&setup_resp)?;

    let t_mid_us = system_time_to_us(t_send_sys)? + (rtt.as_micros() as i64) / 2;
    let server_us = system_time_to_us(server_time)?;

    Ok(server_us - t_mid_us)
}

fn build_negotiate_request() -> Vec<u8> {
    let dialects: &[u16] = &[0x0300, 0x0210, 0x0202];
    let dialect_count = dialects.len() as u16;

    let body_size = 36 + (2 * dialect_count as usize);
    let smb2_header_size = 64usize;
    let total = smb2_header_size + body_size;

    let mut pkt = vec![0u8; 4 + total];
    pkt[1] = ((total >> 16) & 0xFF) as u8;
    pkt[2] = ((total >> 8) & 0xFF) as u8;
    pkt[3] = (total & 0xFF) as u8;

    let h = &mut pkt[4..4 + smb2_header_size];
    h[0..4].copy_from_slice(b"\xfeSMB");
    h[4..6].copy_from_slice(&64u16.to_le_bytes());
    h[12..14].copy_from_slice(&0u16.to_le_bytes()); // NEGOTIATE
    h[18..20].copy_from_slice(&1u16.to_le_bytes()); // CreditRequest
    h[28..36].copy_from_slice(&1u64.to_le_bytes()); // MessageId

    let b = &mut pkt[4 + smb2_header_size..];
    b[0..2].copy_from_slice(&36u16.to_le_bytes());
    b[2..4].copy_from_slice(&dialect_count.to_le_bytes());
    b[4..6].copy_from_slice(&1u16.to_le_bytes()); // SecurityMode=1
    b[8..12].copy_from_slice(&SMB2_CAPABILITIES.to_le_bytes());

    // OPSEC: Random ClientGuid (UUIDv4)
    let mut guid = [0u8; 16];
    for b_out in guid.iter_mut() {
        *b_out = rand::random();
    }
    guid[6] = (guid[6] & 0x0F) | 0x40; // Version 4
    guid[8] = (guid[8] & 0x3F) | 0x80; // Variant 10xx
    b[12..28].copy_from_slice(&guid);

    for (i, &d) in dialects.iter().enumerate() {
        let off = 36 + i * 2;
        b[off..off + 2].copy_from_slice(&d.to_le_bytes());
    }

    pkt
}

fn build_session_setup_type1() -> Vec<u8> {
    // Build NTLMSSP Type 1 (MS-NLMP §2.2.1.1)
    let mut ntlm = vec![];
    ntlm.extend_from_slice(b"NTLMSSP\0");
    ntlm.extend_from_slice(&1u32.to_le_bytes()); // MessageType = 1 (Negotiate)

    // OPSEC Rationale: Generic minimal client flags. Real bitmask choice
    // requires Phase 5 packet captures to match observed Windows traffic.
    // Current set: NEGOTIATE_56 | NEGOTIATE_KEY_EXCH | NEGOTIATE_128 |
    // NEGOTIATE_NTLM | REQUEST_TARGET | NEGOTIATE_UNICODE.
    let flags: u32 = 0xE0000205;
    ntlm.extend_from_slice(&flags.to_le_bytes());

    // DomainName/WorkstationName omitted (empty fields)
    ntlm.extend_from_slice(&[0u8; 16]); // 8 bytes domain, 8 bytes workstation

    let ntlm_len = ntlm.len();

    // SMB2 SESSION_SETUP body size is 24 + length of security buffer
    // But structure size field is always 25.
    let body_size = 24 + ntlm_len;
    let smb2_header_size = 64usize;
    let total = smb2_header_size + body_size;

    let mut pkt = vec![0u8; 4 + total];
    pkt[1] = ((total >> 16) & 0xFF) as u8;
    pkt[2] = ((total >> 8) & 0xFF) as u8;
    pkt[3] = (total & 0xFF) as u8;

    let h = &mut pkt[4..4 + smb2_header_size];
    h[0..4].copy_from_slice(b"\xfeSMB");
    h[4..6].copy_from_slice(&64u16.to_le_bytes());
    h[12..14].copy_from_slice(&1u16.to_le_bytes()); // SESSION_SETUP (0x0001)
    h[18..20].copy_from_slice(&1u16.to_le_bytes()); // CreditRequest
    h[28..36].copy_from_slice(&2u64.to_le_bytes()); // MessageId = 2

    let b = &mut pkt[4 + smb2_header_size..];
    b[0..2].copy_from_slice(&25u16.to_le_bytes()); // StructureSize = 25
    b[2] = 0; // Flags
    b[3] = 1; // SecurityMode
    b[4..8].copy_from_slice(&0u32.to_le_bytes()); // Capabilities
    b[8..12].copy_from_slice(&0u32.to_le_bytes()); // Channel
    b[12..14].copy_from_slice(&88u16.to_le_bytes()); // SecurityBufferOffset = 64 + 24
    b[14..16].copy_from_slice(&(ntlm_len as u16).to_le_bytes()); // SecurityBufferLength
    b[16..24].copy_from_slice(&0u64.to_le_bytes()); // PreviousSessionId

    b[24..24 + ntlm_len].copy_from_slice(&ntlm);

    pkt
}

/// Parse SMB2 SESSION_SETUP_RESPONSE and extract NTLM Type 2 TargetInfo MsvAvTimestamp.
fn parse_session_setup_response(b: &[u8]) -> Result<SystemTime, TimeSourceError> {
    // Check SMB2 Header Status (offset 8)
    if b.len() < 64 {
        return Err(TimeSourceError::Parse("SMB2 response too short".into()));
    }
    let status = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
    if status != 0xC0000016 {
        // STATUS_MORE_PROCESSING_REQUIRED
        return Err(TimeSourceError::Protocol(format!(
            "Expected MORE_PROCESSING_REQUIRED, got 0x{:08X}",
            status
        )));
    }

    // SMB2 SESSION_SETUP_RESPONSE body starts at offset 64
    let body = &b[64..];
    if body.len() < 9 {
        return Err(TimeSourceError::Parse(
            "SMB2 SESSION_SETUP_RESPONSE body too short".into(),
        ));
    }

    let struct_size = u16::from_le_bytes([body[0], body[1]]);
    if struct_size != 9 {
        return Err(TimeSourceError::Protocol(
            "Unexpected SESSION_SETUP_RESPONSE structure size".into(),
        ));
    }

    let sec_offset = u16::from_le_bytes([body[4], body[5]]) as usize;
    let sec_len = u16::from_le_bytes([body[6], body[7]]) as usize;

    let sec_end = sec_offset
        .checked_add(sec_len)
        .ok_or_else(|| TimeSourceError::Parse("SecurityBuffer overflow".into()))?;
    if sec_offset < 64 || sec_end > b.len() {
        return Err(TimeSourceError::Parse(
            "SecurityBuffer out of bounds".into(),
        ));
    }

    let ntlm = &b[sec_offset..sec_end];
    parse_ntlm_type2(ntlm)
}

/// MS-NLMP §2.2.1.2 CHALLENGE_MESSAGE
fn parse_ntlm_type2(ntlm: &[u8]) -> Result<SystemTime, TimeSourceError> {
    if ntlm.len() < 48 {
        return Err(TimeSourceError::Parse(
            "NTLM Type 2 too short for TargetInfoFields".into(),
        ));
    }
    if &ntlm[0..8] != b"NTLMSSP\0" {
        return Err(TimeSourceError::Parse("Invalid NTLMSSP signature".into()));
    }
    let msg_type = u32::from_le_bytes([ntlm[8], ntlm[9], ntlm[10], ntlm[11]]);
    if msg_type != 2 {
        return Err(TimeSourceError::Parse(format!(
            "Expected NTLM Type 2, got {}",
            msg_type
        )));
    }

    // TargetInfoFields is at offset 40
    let target_info_len = u16::from_le_bytes([ntlm[40], ntlm[41]]) as usize;
    let target_info_offset = u32::from_le_bytes([ntlm[44], ntlm[45], ntlm[46], ntlm[47]]) as usize;

    let target_info_end = target_info_offset
        .checked_add(target_info_len)
        .ok_or_else(|| TimeSourceError::Parse("TargetInfo overflow".into()))?;
    if target_info_end > ntlm.len() {
        return Err(TimeSourceError::Parse(
            "TargetInfo out of bounds in NTLM".into(),
        ));
    }

    let target_info = &ntlm[target_info_offset..target_info_end];

    // MS-NLMP §2.2.2.1 AV_PAIR
    let mut pos: usize = 0;
    while let Some(end_check) = pos.checked_add(4) {
        if end_check > target_info.len() {
            break;
        }

        let av_id = u16::from_le_bytes([target_info[pos], target_info[pos + 1]]);
        let av_len = u16::from_le_bytes([target_info[pos + 2], target_info[pos + 3]]) as usize;
        pos += 4;

        let av_end = pos
            .checked_add(av_len)
            .ok_or_else(|| TimeSourceError::Parse("AV_PAIR overflow".into()))?;
        if av_end > target_info.len() {
            return Err(TimeSourceError::Parse(
                "AV_PAIR length out of bounds".into(),
            ));
        }

        if av_id == 7 {
            // MsvAvTimestamp
            if av_len != 8 {
                return Err(TimeSourceError::Parse(
                    "MsvAvTimestamp has invalid length".into(),
                ));
            }
            let filetime = u64::from_le_bytes([
                target_info[pos],
                target_info[pos + 1],
                target_info[pos + 2],
                target_info[pos + 3],
                target_info[pos + 4],
                target_info[pos + 5],
                target_info[pos + 6],
                target_info[pos + 7],
            ]);
            return filetime_to_system_time(filetime);
        } else if av_id == 0 {
            // MsvAvEOL
            break;
        }

        pos += av_len;
    }

    Err(TimeSourceError::Parse(
        "MsvAvTimestamp (AV_PAIR 7) not found in NTLM TargetInfo".into(),
    ))
}

fn read_smb_message(stream: &mut TcpStream) -> Result<Vec<u8>, TimeSourceError> {
    let mut nb_header = [0u8; 4];
    stream.read_exact(&mut nb_header).map_err(map_io_err)?;
    let msg_len = u32::from_be_bytes(nb_header) & 0x00FF_FFFF;
    if msg_len > 65536 {
        return Err(TimeSourceError::Protocol(format!(
            "SMB2 response too large: {}",
            msg_len
        )));
    }
    let mut body = vec![0u8; msg_len as usize];
    stream.read_exact(&mut body).map_err(map_io_err)?;
    Ok(body)
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
    use std::time::UNIX_EPOCH;

    #[test]
    fn build_session_setup_type1_has_correct_structure() {
        let req = build_session_setup_type1();
        // NetBIOS length
        assert_eq!(req[0], 0);
        let len = u32::from_be_bytes([0, req[1], req[2], req[3]]);
        assert_eq!(len as usize, req.len() - 4);

        // SMB2 Header
        assert_eq!(&req[4..8], b"\xfeSMB");
        // Command == 1
        assert_eq!(&req[16..18], &[1, 0]);

        // SecurityBufferOffset = 88
        assert_eq!(&req[80..82], &[88, 0]);
        // NTLMSSP
        assert_eq!(&req[92..100], b"NTLMSSP\0");
    }

    // Mocking a real NTLM Type 2 parsing requires a real packet structure.
    // For now, we verify the logic manually with synthetic data.
    #[test]
    fn parse_ntlm_type2_extracts_timestamp() {
        let mut ntlm = vec![0u8; 60];
        ntlm[0..8].copy_from_slice(b"NTLMSSP\0");
        ntlm[8..12].copy_from_slice(&2u32.to_le_bytes()); // Type 2

        // TargetInfoFields
        ntlm[40..42].copy_from_slice(&12u16.to_le_bytes()); // Len = 12
        ntlm[42..44].copy_from_slice(&12u16.to_le_bytes()); // MaxLen = 12
        ntlm[44..48].copy_from_slice(&48u32.to_le_bytes()); // Offset = 48

        // TargetInfoBuffer at 48: AvId 7, AvLen 8, Value = 133485408000000000 (2024-01-01)
        ntlm[48..50].copy_from_slice(&7u16.to_le_bytes());
        ntlm[50..52].copy_from_slice(&8u16.to_le_bytes());
        let ft: u64 = 133_485_408_000_000_000;
        ntlm[52..60].copy_from_slice(&ft.to_le_bytes());

        let st = parse_ntlm_type2(&ntlm).unwrap();
        let unix_secs = st.duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(unix_secs, 1_704_067_200);
    }
}
