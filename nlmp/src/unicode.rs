use bytes::Bytes;

pub fn unicode(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .map(|wc| wc.to_le_bytes())
        .flatten()
        .collect()
}

pub fn unicode_bytes(s: &str) -> Bytes {
    s.encode_utf16()
        .map(|wc| wc.to_le_bytes())
        .flatten()
        .collect()
}

pub fn unicode_generic<B: FromIterator<u8>>(s: &str) -> B {
    s.encode_utf16()
        .map(|wc| wc.to_le_bytes())
        .flatten()
        .collect()
}
#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    #[test]
    fn unicode_works() {
        assert_eq!(unicode("test"), b"t\0e\0s\0t\0");
        assert_eq!(
            unicode(&("test".to_uppercase() + "WORKGROUP")),
            hex!("540045005300540057004f0052004b00470052004f0055005000")
        );
    }
}