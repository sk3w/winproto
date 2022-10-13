use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::str::Utf8Error;

use crate::records::ElementRecord;

/// # .NET Binary Format: XML Data Structure
///
/// The .NET Binary Format: XML Data Structure is composed of zero or more records, each of which
/// represents some characters in the XML document. The complete XML document represented by the
/// format is simply the concatenation of the characters represented by each of the records. The
/// resulting document is not necessarily a valid XML document.
///
/// Unless otherwise noted, records can appear in any order.
#[repr(transparent)]
pub struct NbfxData {
    records: Vec<ElementRecord>,
}

/// MC-NBFX 2.1.2 MultiByteInt31
///
/// This structure describes an unsigned 31-bit integer value in a variable- length packet.
#[derive(Clone, Debug, PartialEq)]
#[repr(transparent)]
pub struct MultiByteInt31(u32);

impl MultiByteInt31 {
    pub fn encode(&self) -> Vec<u8> {
        let size = self.0.clone();
        match size {
            0..=0x7f => vec![size as u8 & 0x7f],
            0x80..=0x3fff => {
                vec![size as u8 & 0x7f | 0x80, (size >> 7) as u8 & 0x7f]
            }
            0x4000..=0x1f_ffff => {
                vec![
                    size as u8 & 0x7f | 0x80,
                    (size >> 7) as u8 & 0x7f | 0x80,
                    (size >> 14) as u8 & 0x7f,
                ]
            }
            0x20_0000..=0x0fff_ffff => {
                vec![
                    size as u8 & 0x7f | 0x80,
                    (size >> 7) as u8 & 0x7f | 0x80,
                    (size >> 14) as u8 & 0x7f | 0x80,
                    (size >> 21) as u8 & 0x7f,
                ]
            }
            0x1000_0000..=0x7fff_ffff => {
                vec![
                    size as u8 & 0x7f | 0x80,
                    (size >> 7) as u8 & 0x7f | 0x80,
                    (size >> 14) as u8 & 0x7f | 0x80,
                    (size >> 21) as u8 & 0x7f | 0x80,
                    (size >> 28) as u8 & 0x7f,
                ]
            }
            _ => panic!("Size too large"),
        }
    }
}

/// # MC-NBFX 2.1.3 String
///
/// The String structure describes a set of characters encoded in UTF-8, as specified in RFC2279.
#[derive(Clone, Debug, PartialEq)]
#[repr(transparent)]
pub struct NbfxString(pub(crate) String);

impl NbfxString {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn from_utf8(bytes: &[u8]) -> Result<Self, Utf8Error> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = MultiByteInt31(self.0.len().try_into().unwrap()).encode();
        encoded.extend(self.0.as_bytes());
        encoded
    }
}

/// # MC-NBFX 2.1.4 DictionaryString
///
/// The DictionaryString structure describes a reference to a set of characters.
#[derive(Clone, Debug, PartialEq)]
#[repr(transparent)]
pub struct DictionaryString {
    value: MultiByteInt31,
}

#[cfg(test)]
mod tests {
    use alloc::borrow::ToOwned;

    use super::*;

    #[test]
    fn encode_mbi31_1byte() {
        assert_eq!(&MultiByteInt31(17u32).encode(), &[0x11],);
        assert_eq!(&MultiByteInt31(0x7fu32).encode(), &[0x7f],);
    }

    #[test]
    fn encode_mbi31_2bytes() {
        assert_eq!(&MultiByteInt31(145u32).encode(), &[0x91, 0x01],);
        assert_eq!(&MultiByteInt31(5521u32).encode(), &[0x91, 0x2b],);
    }

    #[test]
    fn encode_mbi31_3bytes() {
        assert_eq!(&MultiByteInt31(16384u32).encode(), &[0x80, 0x80, 0x01],);
    }

    #[test]
    fn encode_mbi31_4bytes() {
        assert_eq!(
            &MultiByteInt31(2_097_152u32).encode(),
            &[0x80, 0x80, 0x80, 0x01],
        );
    }

    #[test]
    fn encode_mbi31_5bytes() {
        assert_eq!(
            &MultiByteInt31(268_435_456u32).encode(),
            &[0x80, 0x80, 0x80, 0x80, 0x01],
        );
    }

    #[test]
    fn encode_string() {
        assert_eq!(
            &NbfxString("abc".to_owned()).encode(),
            &[0x03, 0x61, 0x62, 0x63]
        )
    }
}
