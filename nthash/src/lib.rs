#![no_std]

use md4::{Digest, Md4};

#[derive(Debug, PartialEq)]
#[repr(transparent)]
pub struct NtHash {
    bytes: [u8; 16],
}

impl AsRef<[u8; 16]> for NtHash {
    fn as_ref(&self) -> &[u8; 16] {
        &self.bytes
    }
}

impl From<[u8; 16]> for NtHash {
    fn from(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }
}

impl From<&str> for NtHash {
    fn from(item: &str) -> Self {
        let mut hasher = Md4::new();
        // A buffer of length 2 is large enough to encode any `char`
        // https://doc.rust-lang.org/std/primitive.char.html#panics-4
        let mut buf = [0u16; 2];
        for char in item.chars() {
            let result = char.encode_utf16(&mut buf);
            hasher.update(&result[0].to_le_bytes());
            if result.len() == 2 {
                hasher.update(&result[1].to_le_bytes());
            }
        }
        //hasher.update(plaintext);
        let result = hasher.finalize();
        NtHash {
            bytes: result.into(),
        }
    }
}

impl NtHash {
    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    #[test]
    fn nthash_matches_expected() {
        // values taken from https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/8c5c1438-1807-4d19-9f4e-66290f214a63
        let password = "NEWPASSWORD";
        let hash = NtHash {
            bytes: hex!("25 67 81 a6 20 31 28 9d 3c 2c 98 c1 4f 1e fc 8c"),
        };
        assert_eq!(NtHash::from(password), hash);

        let password = "Summer2020";
        let hash = NtHash {
            bytes: hex!("ACBFC03DF96E93CF7294A01A6ABBDA33"),
        };
        assert_eq!(NtHash::from(password), hash);

        // values taken from https://hashcat.net/wiki/doku.php?id=example_hashes
        let password = "hashcat";
        let hash = NtHash {
            bytes: hex!("b4b9b02e6f09a9bd760f388b67351e2b"),
        };
        assert_eq!(NtHash::from(password), hash);
    }

    #[test]
    fn nthash_blank_password() {
        let password = "";
        let hash = NtHash {
            bytes: hex!("31d6cfe0d16ae931b73c59d7e0c089c0"),
        };
        assert_eq!(NtHash::from(password), hash);
    }
}
