use kerberos_crypto::rc4_hmac_md5;
use pretty_hex::PrettyHex;
use rasn_kerberos::EncryptedData;

use crate::constants::{ETYPE_RC4_HMAC_MD5, KEY_USAGE_PA_ENC_TIMESTAMP};

mod rc4_md4;

#[derive(Debug)]
pub enum Algorithm {
    Aes128CtsHmacSha1, // 0x17
    Aes256CtsHmacSha1, // 0x18
    Rc4HmacMd5,        // 0x23
    Rc4HmacMd5Exp,     // 0x24
    Rc4Md4,            // 0x80
}

pub fn decrypt_rc4(ciphertext: &[u8], password: &str, key_usage: i32) -> Option<Vec<u8>> {
    let key = rc4_hmac_md5::generate_key_from_string(password);
    dbg!(ciphertext.hex_dump());
    let plaintext = rc4_hmac_md5::decrypt(&key, key_usage, ciphertext).unwrap();
    dbg!(plaintext.hex_dump());
    Some(plaintext)
}

pub fn encrypt_timestamp(plaintext: &[u8], password: &str) -> EncryptedData {
    let key = rc4_hmac_md5::generate_key_from_string(password);
    let preamble = rc4_hmac_md5::generate_preamble();
    let cipher =
        rc4_hmac_md5::encrypt(&key, KEY_USAGE_PA_ENC_TIMESTAMP, plaintext, &preamble).into();
    EncryptedData {
        etype: ETYPE_RC4_HMAC_MD5,
        kvno: None,
        cipher,
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::constants::KEY_USAGE_TGS_REP_ENC_PART;

    use super::*;

    #[test]
    fn decrypt_rc4_works() {
        let ciphertext: &[u8] = hex!(
            "ad a5 ee fd  66 81 69 6b  0b fa 9a d7  e8 9a 66 a0"
            "8d 93 ff 67  45 55 66 71  4d 10 2f 69  35 5b 70 1a"
            "2a 5d e1 6a  be a3 28 63  a9 17 e4 d9  b1 52 d0 3e"
            "65 c4 43 e1  6c af ba fc  b3 0d 94 a6  3a 0b 9e d0"
            "93 f6 c5 fc  27 0b 3c 46  7d fb 35 81  c6 ad 46 ac"
            "b5 0c 20 3b  a4 a9 63 b3  58 2c 63 fe  2a 24 c3 01"
            "ff 3e 9e bc  f4 35 8b 9c  6c a8 d9 4f  a4 aa b2 46"
            "78 bb 1b 07  aa 5e 2f c8  59 9b 11 13  de f5 79 6c"
            "2d 96 e8 e6  22 01 7f 4c  92 7d 6b 94  5e 25 6a 55"
            "54 bc 45 91  fa 16 4e 70  b6 47 12 3c  da fd b3 9a"
            "25 04 86 2c  88 66 fc b2  0c 55 46 44  33 25 8f 67"
            "c9 e8 c2 f6  01 76 46 7c  da 46 6c bd  8e 92 d6 93"
            "85 f9 02 0f  cf 6f 8b af  ad 6e 16 f4  4d 38 74 ce"
            "df 9b 8f 38  14 a4 76 29  14 ea 4a 74  86 bb 84 9b"
            "d8 92 48 e8  b7 e6 6f ea  ee b3 6d 3b  a1 6e 25 d9"
            "6c 58 bd b8  cb 12 35 fd  63 68 cf 43  08 3d 25 1b"
            "64 75 d3 85  62 38 f2 c1  61 dd ff bb  e2 e6 76 6e"
            "b5 8b 90 f2  e1 75 0e 03  a1 4a 6a f3  b7 fd 44 07"
            "4f 7a f7 5e  e1 d0 8d 4e  6c"
        )
        .as_slice();
        let password = "vagrant";
        // NOTE: MS Windows uses this here instead of KEY_USAGE_AS_REP_ENC_PART
        let key_usage = KEY_USAGE_TGS_REP_ENC_PART;
        let plaintext = decrypt_rc4(ciphertext, password, key_usage).unwrap();
        assert_eq!(&plaintext[..4], &[0x79, 0x82, 0x01, 0x0d])
    }
}
