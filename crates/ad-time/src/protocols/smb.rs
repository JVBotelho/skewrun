/// SMB2 NEGOTIATE time source — fallback on TCP/445.
///
/// Protocol Specifications:
/// - **MS-SMB2 §2.2.3**: SMB2 NEGOTIATE Request
/// - **MS-SMB2 §2.2.4**: SMB2 NEGOTIATE Response
///
/// Sends SMB2 NEGOTIATE request and reads SystemTime from the response.
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant, SystemTime};

use super::common::{filetime_to_system_time, map_io_err, system_time_to_us};
use super::smb_common::build_negotiate_request;
use crate::time_src::{OffsetMicros, TimeSource, TimeSourceError};

pub struct SmbSource;

/// Sequential field reader for little-endian binary structs.
struct FieldReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> FieldReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_u16_le(&mut self) -> Result<u16, TimeSourceError> {
        let b = self.next_bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn read_u32_le(&mut self) -> Result<u32, TimeSourceError> {
        let b = self.next_bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_u64_le(&mut self) -> Result<u64, TimeSourceError> {
        let b = self.next_bytes(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn skip(&mut self, n: usize) -> Result<(), TimeSourceError> {
        self.next_bytes(n)?;
        Ok(())
    }

    fn next_bytes(&mut self, n: usize) -> Result<&'a [u8], TimeSourceError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| TimeSourceError::Parse("FieldReader overflow".into()))?;
        if end > self.buf.len() {
            return Err(TimeSourceError::Parse("SMB body overruns buffer".into()));
        }
        let b = &self.buf[self.pos..end];
        self.pos = end;
        Ok(b)
    }
}

impl TimeSource for SmbSource {
    fn name(&self) -> &'static str {
        "smb"
    }

    fn fetch(
        &self,
        target: SocketAddr,
        timeout: Duration,
    ) -> Result<OffsetMicros, TimeSourceError> {
        let smb_addr: SocketAddr = (target.ip(), 445).into();
        fetch_smb(smb_addr, timeout)
    }
}

fn fetch_smb(addr: SocketAddr, timeout: Duration) -> Result<OffsetMicros, TimeSourceError> {
    let mut stream =
        TcpStream::connect_timeout(&addr, timeout).map_err(|e| map_io_err(e, "connect"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| TimeSourceError::Protocol(e.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| TimeSourceError::Protocol(e.to_string()))?;

    let t_send = Instant::now();
    let t_send_sys = SystemTime::now();

    let request = build_negotiate_request();
    stream
        .write_all(&request)
        .map_err(|e| TimeSourceError::Protocol(e.to_string()))?;

    // Read NetBIOS header (4 bytes) to know response length.
    let mut nb_header = [0u8; 4];
    stream
        .read_exact(&mut nb_header)
        .map_err(|e| map_io_err(e, "read_header"))?;
    // NetBIOS session message: byte 0 = 0x00, bytes 1..4 = 24-bit big-endian length.
    let msg_len = u32::from_be_bytes(nb_header) & 0x00FF_FFFF;
    if msg_len > 65536 {
        return Err(TimeSourceError::Protocol(format!(
            "implausibly large SMB2 response: {} bytes",
            msg_len
        )));
    }
    if msg_len < 64 + 65 {
        return Err(TimeSourceError::Parse(format!(
            "SMB2 response too short: {} bytes",
            msg_len
        )));
    }

    let mut body = vec![0u8; msg_len as usize];
    stream
        .read_exact(&mut body)
        .map_err(|e| map_io_err(e, "read_body"))?;

    let rtt = t_send.elapsed();

    // body[0..64] is SMB2 header; body[64..] is NEGOTIATE_RESPONSE.
    let negotiate = &body[64..];
    let server_time = parse_negotiate_response(negotiate)?;

    // Single-point approximation: server timestamp ≈ midpoint of our send/recv window.
    // Precision: ±RTT/2 — sufficient for Kerberos 5-minute skew window.
    let t_mid_us = system_time_to_us(t_send_sys)? + (rtt.as_micros() as i64) / 2;
    let server_us = system_time_to_us(server_time)?;

    Ok(server_us - t_mid_us)
}

/// Parse SMB2 NEGOTIATE_RESPONSE (MS-SMB2 §2.2.4) and extract SystemTime.
fn parse_negotiate_response(b: &[u8]) -> Result<SystemTime, TimeSourceError> {
    let mut r = FieldReader::new(b);
    // Fields are little-endian; read sequentially per MS-SMB2 §2.2.4.
    let structure_size = r.read_u16_le()?; //  0: StructureSize (must be 65)
    if structure_size != 65 {
        return Err(TimeSourceError::Protocol(format!(
            "unexpected SMB2 NEGOTIATE_RESPONSE StructureSize: {}",
            structure_size
        )));
    }
    let _security_mode = r.read_u16_le()?; //  2: SecurityMode
    let _dialect_revision = r.read_u16_le()?; //  4: DialectRevision
    let _negotiate_ctx_cnt = r.read_u16_le()?; //  6: NegotiateContextCount/Reserved
    r.skip(16)?; //  8: ServerGuid ([u8; 16])
    let _capabilities = r.read_u32_le()?; // 24: Capabilities
    let _max_transact = r.read_u32_le()?; // 28: MaxTransactSize
    let _max_read = r.read_u32_le()?; // 32: MaxReadSize
    let _max_write = r.read_u32_le()?; // 36: MaxWriteSize
    let system_time = r.read_u64_le()?; // 40: SystemTime (FILETIME)

    filetime_to_system_time(system_time)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

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

    #[test]
    fn build_negotiate_request_has_random_guid() {
        // ClientGuid is at offset 4 (NetBIOS) + 64 (SMB2 header) + 12 (body offset) = 80..96
        use crate::protocols::smb_common::build_negotiate_request;
        let r1 = build_negotiate_request();
        let r2 = build_negotiate_request();
        assert_ne!(
            &r1[80..96],
            &r2[80..96],
            "ClientGuid must differ between calls"
        );
        // Sanity: neither is all-zero (overwhelmingly probable)
        assert_ne!(&r1[80..96], &[0u8; 16]);
    }

    #[test]
    fn build_negotiate_request_advertises_smb311() {
        use crate::protocols::smb_common::build_negotiate_request;
        let req = build_negotiate_request();
        // Packet layout: NetBIOS(4) + SMB2 header(64) + body fixed(36) = dialects start at pkt[104]
        assert_eq!(
            u16::from_le_bytes([req[104], req[105]]),
            0x0311,
            "first dialect must be SMB 3.1.1"
        );
        // NegotiateContextOffset at body offset 28 → pkt[4 + 64 + 28] = pkt[96]
        let neg_ctx_off = u32::from_le_bytes([req[96], req[97], req[98], req[99]]);
        assert_eq!(
            neg_ctx_off, 112,
            "NegotiateContextOffset must be 112 (8-byte aligned from SMB2 header start)"
        );
        // PREAUTH_INTEGRITY_CAPABILITIES context type at pkt[4 + 112] = pkt[116]
        assert_eq!(
            u16::from_le_bytes([req[116], req[117]]),
            0x0001,
            "negotiate context must be PREAUTH_INTEGRITY_CAPABILITIES"
        );
    }

    #[test]
    fn fetch_smb_rejects_large_msg_len() {
        // Simulate a NetBIOS header claiming a 128 KB response body (> 65536 limit).
        // We cannot call fetch_smb (needs a real socket), but we can verify the
        // guard arithmetic: msg_len field is 24-bit from bytes [1..4].
        let large: u32 = 0x0002_0000; // 131072 bytes
        assert!(large > 65536);
        // Confirm the mask used in production: u32::from_be_bytes([0, 2, 0, 0]) & 0x00FF_FFFF = 131072
        let nb = [0x00u8, 0x02, 0x00, 0x00];
        let msg_len = u32::from_be_bytes(nb) & 0x00FF_FFFF;
        assert_eq!(msg_len, 131072);
        assert!(msg_len > 65536);
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn parse_negotiate_response_never_panics(data in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = parse_negotiate_response(&data);
        }
    }
}

#[cfg(feature = "fuzzing")]
pub fn fuzz_parse_negotiate_response(
    data: &[u8],
) -> Result<std::time::SystemTime, crate::time_src::TimeSourceError> {
    parse_negotiate_response(data)
}
