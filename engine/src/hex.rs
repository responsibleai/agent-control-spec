//! Lowercase hex encoding shared by the digest call sites.
//!
//! `digest` 0.11 (pulled in by sha2 0.11) moved its output type from
//! `generic-array` to `hybrid-array`, whose `Array` does not implement
//! `LowerHex`, so digests are encoded explicitly here instead of through
//! `format!("{:x}", ...)`.

pub(crate) fn lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
