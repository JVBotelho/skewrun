//! Shared BER/DER encoding and decoding utilities.

pub fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    encode_length(&mut out, value.len());
    out.extend_from_slice(value);
    out
}

pub fn encode_length(buf: &mut Vec<u8>, len: usize) {
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

pub fn encode_sequence(inner: &[u8]) -> Vec<u8> {
    encode_tlv(0x30, inner)
}

pub fn encode_context(n: u8, inner: &[u8]) -> Vec<u8> {
    encode_tlv(0xA0 | n, inner)
}

pub fn encode_application(n: u8, inner: &[u8]) -> Vec<u8> {
    encode_tlv(0x60 | n, inner)
}

pub fn encode_integer_u64(v: u64) -> Vec<u8> {
    // Minimal unsigned DER integer; prepend 0x00 if high bit set.
    let mut bytes = v.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 && (bytes[1] & 0x80) == 0 {
        bytes.remove(0);
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    encode_tlv(0x02, &bytes)
}

pub fn encode_integer_i32(val: i32) -> Vec<u8> {
    let mut v = val;
    let mut bytes = Vec::new();
    if v == 0 {
        bytes.push(0);
    } else {
        while v > 0 {
            bytes.push((v & 0xff) as u8);
            v >>= 8;
        }
        // If high bit is set, we need a 0x00 prefix to keep it positive in two's complement
        if let Some(&last) = bytes.last() {
            if last & 0x80 != 0 {
                bytes.push(0x00);
            }
        }
        bytes.reverse();
    }
    encode_tlv(0x02, &bytes)
}

pub fn encode_generalstring(s: &str) -> Vec<u8> {
    encode_tlv(0x1B, s.as_bytes())
}

pub fn encode_generalizedtime(s: &str) -> Vec<u8> {
    encode_tlv(0x18, s.as_bytes())
}
