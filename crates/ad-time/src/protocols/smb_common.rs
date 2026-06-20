//! Shared SMB2 utilities.

// SMB2 capabilities: DFS | LEASING | LARGE_MTU | MULTI_CHANNEL | PERSISTENT_HANDLES | DIR_LEASING | ENCRYPTION
pub const SMB2_CAPABILITIES: u32 = 0x7F;

/// Build SMB2 NEGOTIATE request wrapped in a NetBIOS session message.
pub fn build_negotiate_request() -> Vec<u8> {
    // Dialects: SMB 3.0, 2.1, 2.0.2. Dropped 3.1.1 because it requires Negotiate Contexts to be OPSEC safe.
    let dialects: &[u16] = &[0x0300, 0x0210, 0x0202];
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
    // SecurityMode = 1 (signing enabled, but not required - matches Windows default)
    b[4..6].copy_from_slice(&1u16.to_le_bytes());
    b[8..12].copy_from_slice(&SMB2_CAPABILITIES.to_le_bytes());
    
    // OPSEC: Random ClientGuid (UUIDv4)
    let mut guid = [0u8; 16];
    for b_out in guid.iter_mut() {
        *b_out = rand::random();
    }
    guid[6] = (guid[6] & 0x0F) | 0x40; // Version 4
    guid[8] = (guid[8] & 0x3F) | 0x80; // Variant 10xx
    b[12..28].copy_from_slice(&guid);
    
    // Dialects start at offset 36 from body start
    for (i, &d) in dialects.iter().enumerate() {
        let off = 36 + i * 2;
        b[off..off + 2].copy_from_slice(&d.to_le_bytes());
    }

    pkt
}
