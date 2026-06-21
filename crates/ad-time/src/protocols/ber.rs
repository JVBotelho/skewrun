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
    } else if len < 65536 {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xFF) as u8);
    } else {
        buf.push(0x83);
        buf.push((len >> 16) as u8);
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
    let bytes = val.to_be_bytes();
    let mut start = 0;
    while start < bytes.len() - 1 {
        let curr = bytes[start];
        let next_msb = bytes[start + 1] & 0x80;
        if (curr == 0x00 && next_msb == 0) || (curr == 0xFF && next_msb != 0) {
            start += 1;
        } else {
            break;
        }
    }
    encode_tlv(0x02, &bytes[start..])
}

pub fn encode_generalstring(s: &str) -> Vec<u8> {
    encode_tlv(0x1B, s.as_bytes())
}

pub fn encode_generalizedtime(s: &str) -> Vec<u8> {
    encode_tlv(0x18, s.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn encode_integer_i32_der_structure(v in i32::MIN..=i32::MAX) {
            let enc = encode_integer_i32(v);
            prop_assert_eq!(enc[0], 0x02);
            let len = enc[1] as usize;
            prop_assert_eq!(enc.len(), 2 + len);
            prop_assert!((1..=4).contains(&len));
            if len > 1 {
                let b0 = enc[2];
                let b1 = enc[3];
                prop_assert!(
                    !((b0 == 0x00 && (b1 & 0x80) == 0)
                    || (b0 == 0xFF && (b1 & 0x80) != 0)),
                    "non-minimal DER encoding for {}", v
                );
            }
        }

        #[test]
        fn encode_integer_i32_negative_preserves_sign(v in -128i32..=-1) {
            let enc = encode_integer_i32(v);
            prop_assert_ne!(enc[2] & 0x80, 0, "sign lost for etype {}", v);
        }
    }
}
