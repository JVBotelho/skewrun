/// SMB2 NEGOTIATE time source — fallback on TCP/445.
/// Sends SMB2 NEGOTIATE request and reads SystemTime from the response.
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::time_src::{OffsetMicros, TimeSourceError, TimeSource};

pub struct SmbSource;

// Seconds between Windows FILETIME epoch (1601-01-01) and Unix epoch (1970-01-01).
const FILETIME_TO_UNIX_SECS: u64 = 11_644_473_600;

impl TimeSource for SmbSource {
    fn name(&self) -> &'static str {
        "smb"
    }

    fn fetch(&self, target: SocketAddr, timeout: Duration) -> Result<OffsetMicros, TimeSourceError> {
        let smb_addr: SocketAddr = (target.ip(), 445).into();
        fetch_smb(smb_addr, timeout)
    }
}

fn fetch_smb(addr: SocketAddr, timeout: Duration) -> Result<OffsetMicros, TimeSourceError> {
    let mut stream = TcpStream::connect_timeout(&addr, timeout).map_err(map_io_err)?;
    stream.set_read_timeout(Some(timeout)).map_err(|e| TimeSourceError::Protocol(e.to_string()))?;

    let t_send = Instant::now();
    let t_send_sys = SystemTime::now();

    let request = build_negotiate_request();
    stream.write_all(&request).map_err(|e| TimeSourceError::Protocol(e.to_string()))?;

    // Read NetBIOS header (4 bytes) to know response length.
    let mut nb_header = [0u8; 4];
    stream.read_exact(&mut nb_header).map_err(|e| map_io_err(e))?;
    // NetBIOS session message: byte 0 = 0x00, bytes 1..4 = 24-bit big-endian length.
    let msg_len = u32::from_be_bytes(nb_header) & 0x00FF_FFFF;
    if msg_len < 64 + 65 {
        return Err(TimeSourceError::Parse(format!("SMB2 response too short: {} bytes", msg_len)));
    }

    let mut body = vec![0u8; msg_len as usize];
    stream.read_exact(&mut body).map_err(|e| map_io_err(e))?;

    let rtt = t_send.elapsed();

    // body[0..64] is SMB2 header; body[64..] is NEGOTIATE_RESPONSE.
    let negotiate = &body[64..];
    let server_time = parse_negotiate_response(negotiate)?;

    // Single-point approximation: server timestamp ≈ midpoint of our send/recv window.
    // Precision: ±RTT/2 — sufficient for Kerberos 5-minute skew window.
    let t_mid_us = system_time_to_us(t_send_sys) + (rtt.as_micros() as i64) / 2;
    let server_us = system_time_to_us(server_time);

    Ok(server_us - t_mid_us)
}

/// Build SMB2 NEGOTIATE request wrapped in a NetBIOS session message.
fn build_negotiate_request() -> Vec<u8> {
    // Dialects: SMB 3.1.1, 3.0, 2.1, 2.0.2 — include 3.1.1 to avoid "Legacy Protocol" alerts.
    let dialects: &[u16] = &[0x0311, 0x0300, 0x0210, 0x0202];
    let dialect_count = dialects.len() as u16;

    // SMB2 NEGOTIATE request body (MS-SMB2 §2.2.3):
    // StructureSize (2) + DialectCount (2) + SecurityMode (2) + Reserved (2) +
    // Capabilities (4) + ClientGuid (16) + ClientStartTime/NegotiateContextOffset/Count (8) +
    // Dialects (2*n)
    let body_size = 2 + 2 + 2 + 2 + 4 + 16 + 8 + (2 * dialect_count as usize);
    let smb2_header_size = 64usize;
    let total = smb2_header_size + body_size;

    let mut pkt = vec![0u8; 4 + total]; // 4-byte NetBIOS prefix

    // NetBIOS session message header (type=0x00, 24-bit big-endian length)
    pkt[1] = ((total >> 16) & 0xFF) as u8;
    pkt[2] = ((total >> 8) & 0xFF) as u8;
    pkt[3] = (total & 0xFF) as u8;

    let h = &mut pkt[4..4 + smb2_header_size];
    // ProtocolId: 0xFE 'S' 'M' 'B'
    h[0..4].copy_from_slice(b"\xfeSMB");
    // StructureSize = 64
    h[4..6].copy_from_slice(&64u16.to_le_bytes());
    // Command = NEGOTIATE (0x0000)
    h[12..14].copy_from_slice(&0u16.to_le_bytes());
    // Flags = 0 (client)
    // CreditRequest = 1
    h[18..20].copy_from_slice(&1u16.to_le_bytes());
    // MessageId = 1
    h[28..36].copy_from_slice(&1u64.to_le_bytes());

    let b = &mut pkt[4 + smb2_header_size..];
    // StructureSize = 36
    b[0..2].copy_from_slice(&36u16.to_le_bytes());
    // DialectCount
    b[2..4].copy_from_slice(&dialect_count.to_le_bytes());
    // SecurityMode = 0 (signing not required from client side)
    b[4..6].copy_from_slice(&0u16.to_le_bytes());
    // Capabilities = 0x7F (all common caps)
    b[8..12].copy_from_slice(&0x7Fu32.to_le_bytes());
    // Dialects start at offset 36 from body start
    for (i, &d) in dialects.iter().enumerate() {
        let off = 36 + i * 2;
        b[off..off + 2].copy_from_slice(&d.to_le_bytes());
    }

    pkt
}

/// Parse SMB2 NEGOTIATE_RESPONSE (MS-SMB2 §2.2.4) and extract SystemTime.
fn parse_negotiate_response(b: &[u8]) -> Result<SystemTime, TimeSourceError> {
    // Field layout (all little-endian):
    //   0: StructureSize (u16) = 65
    //   2: SecurityMode (u16)
    //   4: DialectRevision (u16)
    //   6: NegotiateContextCount/Reserved (u16)
    //   8: ServerGuid ([u8; 16])
    //  24: Capabilities (u32)
    //  28: MaxTransactSize (u32)
    //  32: MaxReadSize (u32)
    //  36: MaxWriteSize (u32)
    //  40: SystemTime (u64, FILETIME)
    const SYSTEM_TIME_OFFSET: usize = 40;

    if b.len() < SYSTEM_TIME_OFFSET + 8 {
        return Err(TimeSourceError::Parse(format!(
            "NEGOTIATE_RESPONSE too short: {} bytes",
            b.len()
        )));
    }

    let structure_size = u16::from_le_bytes([b[0], b[1]]);
    if structure_size != 65 {
        return Err(TimeSourceError::Protocol(format!(
            "unexpected SMB2 NEGOTIATE_RESPONSE StructureSize: {}",
            structure_size
        )));
    }

    let filetime = u64::from_le_bytes(
        b[SYSTEM_TIME_OFFSET..SYSTEM_TIME_OFFSET + 8]
            .try_into()
            .unwrap(),
    );

    filetime_to_system_time(filetime)
}

/// Convert Windows FILETIME (100ns ticks since 1601-01-01 UTC) to SystemTime.
fn filetime_to_system_time(filetime: u64) -> Result<SystemTime, TimeSourceError> {
    // Offset from FILETIME epoch to Unix epoch in 100ns ticks.
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

    #[test]
    fn filetime_unix_epoch() {
        // FILETIME of Unix epoch = 116444736000000000
        let ft: u64 = 116_444_736_000_000_000;
        let st = filetime_to_system_time(ft).unwrap();
        assert_eq!(st, UNIX_EPOCH);
    }

    #[test]
    fn filetime_2024_01_01() {
        // 2024-01-01 00:00:00 UTC as FILETIME
        // Unix timestamp = 1704067200
        // FILETIME = (1704067200 + 11644473600) * 10_000_000 = 133485408000000000
        let ft: u64 = 133_485_408_000_000_000;
        let st = filetime_to_system_time(ft).unwrap();
        let unix_secs = st.duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(unix_secs, 1_704_067_200);
    }

    #[test]
    fn filetime_before_unix_epoch_errors() {
        assert!(filetime_to_system_time(0).is_err());
        assert!(filetime_to_system_time(100).is_err());
    }

    #[test]
    fn negotiate_response_too_short() {
        assert!(parse_negotiate_response(&[0u8; 10]).is_err());
    }

    #[test]
    fn negotiate_response_bad_structure_size() {
        let mut b = vec![0u8; 50];
        // StructureSize = 99 (wrong)
        b[0..2].copy_from_slice(&99u16.to_le_bytes());
        assert!(parse_negotiate_response(&b).is_err());
    }
}
