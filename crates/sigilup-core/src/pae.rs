use alloc::vec::Vec;
use core::fmt::Write as _;

/// Encode a payload type and raw payload bytes using DSSEv1 Pre-Authentication Encoding (PAE).
///
/// Format: `"DSSEv1 " + len(type) + " " + type + " " + len(body) + " " + body`
///
/// Length-prefixing both the type and the body ensures unambiguous domain separation:
/// signatures created for one payload type can never be replayed as another.
#[must_use]
pub fn pae_encode(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut header = alloc::string::String::with_capacity(32 + payload_type.len());
    let _ = write!(
        header,
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    );
    let mut out = Vec::with_capacity(header.len() + payload.len());
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pae_matches_dsse_specification() {
        assert_eq!(
            pae_encode("http://example.com/HelloWorld", b"hello world"),
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
        );
    }

    #[test]
    fn pae_prevents_boundary_ambiguity() {
        let a = pae_encode("a", b"b c");
        let b = pae_encode("a b", b"c");
        assert_ne!(a, b);
    }
}
