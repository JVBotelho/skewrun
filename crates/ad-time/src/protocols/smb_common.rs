//! Shared SMB2 utilities.

// SMB2 capabilities: DFS | LEASING | LARGE_MTU | MULTI_CHANNEL | PERSISTENT_HANDLES | DIR_LEASING | ENCRYPTION
const SMB2_CAPABILITIES: u32 = 0x7F;

// PREAUTH_INTEGRITY_CAPABILITIES negotiate context (MS-SMB2 §2.2.3.1.1).
// Required for SMB 3.1.1. SHA-512 (0x0001) is the only defined integrity algorithm.
// SaltLength = 0 is the correct client value (salt is server-to-client only).
const PREAUTH_INTEGRITY_CTX: &[u8] = &[
    0x01, 0x00, // ContextType: PREAUTH_INTEGRITY_CAPABILITIES
    0x06, 0x00, // DataLength: 6
    0x00, 0x00, 0x00, 0x00, // Reserved
    0x01, 0x00, // HashAlgorithmCount: 1
    0x00, 0x00, // SaltLength: 0
    0x01, 0x00, // HashAlgorithms[0]: SHA-512
];

/// Build SMB2 NEGOTIATE request wrapped in a NetBIOS session message.
pub fn build_negotiate_request() -> Vec<u8> {
    // Dialects: SMB 3.1.1, 3.0, 2.1, 2.0.2.
    // Windows 10/11 always advertises 3.1.1; its absence is a reliable fingerprint
    // for scanners and non-Windows tools. 3.1.1 mandates a PREAUTH_INTEGRITY_CAPABILITIES
    // negotiate context, which we include with the mandatory minimum (SHA-512).
    let dialects: &[u16] = &[0x0311, 0x0300, 0x0210, 0x0202];
    let dialect_count = dialects.len() as u16;
    let smb2_header_size: usize = 64;
    let dialects_size = 2 * dialect_count as usize; // 8 bytes

    // NegotiateContexts must start on an 8-byte boundary relative to the SMB2 header.
    // body-fixed (36) + dialects (8) = 44 bytes past the body start
    //   → 64 (header) + 44 = 108 bytes from the SMB2 header start.
    // Next 8-byte boundary: 112. Padding needed: 4 bytes.
    let after_dialects = smb2_header_size + 36 + dialects_size; // 108
    let neg_ctx_offset = ((after_dialects + 7) & !7) as u32; // 112
    let padding_size = neg_ctx_offset as usize - after_dialects; // 4

    let body_size = 36 + dialects_size + padding_size + PREAUTH_INTEGRITY_CTX.len();
    let total = smb2_header_size + body_size; // 126

    let mut pkt = vec![0u8; 4 + total]; // 4-byte NetBIOS prefix

    // NetBIOS session message header (type=0x00, 24-bit big-endian length)
    pkt[1] = ((total >> 16) & 0xFF) as u8;
    pkt[2] = ((total >> 8) & 0xFF) as u8;
    pkt[3] = (total & 0xFF) as u8;

    {
        let h = &mut pkt[4..4 + smb2_header_size];
        h[0..4].copy_from_slice(b"\xfeSMB"); // ProtocolId
        h[4..6].copy_from_slice(&64u16.to_le_bytes()); // StructureSize
        h[12..14].copy_from_slice(&0u16.to_le_bytes()); // Command: NEGOTIATE
        h[18..20].copy_from_slice(&1u16.to_le_bytes()); // CreditRequest
        h[28..36].copy_from_slice(&1u64.to_le_bytes()); // MessageId
    }

    {
        let b = &mut pkt[4 + smb2_header_size..];
        b[0..2].copy_from_slice(&36u16.to_le_bytes()); // StructureSize
        b[2..4].copy_from_slice(&dialect_count.to_le_bytes()); // DialectCount
        b[4..6].copy_from_slice(&1u16.to_le_bytes()); // SecurityMode (signing enabled, not required)
                                                      // b[6..8] Reserved = 0
        b[8..12].copy_from_slice(&SMB2_CAPABILITIES.to_le_bytes()); // Capabilities

        // OPSEC: Random ClientGuid (UUIDv4)
        let mut guid = [0u8; 16];
        for byte in guid.iter_mut() {
            *byte = rand::random();
        }
        guid[6] = (guid[6] & 0x0F) | 0x40; // Version 4
        guid[8] = (guid[8] & 0x3F) | 0x80; // Variant 10xx
        b[12..28].copy_from_slice(&guid);

        // SMB 3.1.1 negotiate context location fields (MS-SMB2 §2.2.3)
        b[28..32].copy_from_slice(&neg_ctx_offset.to_le_bytes()); // NegotiateContextOffset
        b[32..34].copy_from_slice(&1u16.to_le_bytes()); // NegotiateContextCount
                                                        // b[34..36] Reserved2 = 0

        // Dialects at body offset 36
        for (i, &d) in dialects.iter().enumerate() {
            let off = 36 + i * 2;
            b[off..off + 2].copy_from_slice(&d.to_le_bytes());
        }
        // Padding to 8-byte alignment per MS-SMB2 §2.2.3: MUST be zero when sent.
        // Already zero from the outer vec! initialization — no explicit fill needed.

        // PREAUTH_INTEGRITY_CAPABILITIES negotiate context at body offset 48
        let ctx_off = 36 + dialects_size + padding_size;
        b[ctx_off..ctx_off + PREAUTH_INTEGRITY_CTX.len()].copy_from_slice(PREAUTH_INTEGRITY_CTX);
    }

    pkt
}
