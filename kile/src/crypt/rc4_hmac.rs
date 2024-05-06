/// RFC4757 RC4-HMAC Kerberos Encryption Types Used by Microsoft Windows
use hmac::{Hmac, Mac};
use md5::Md5;
use nthash::NtHash;
use rand::{rngs::OsRng, Fill};
use rc4::{consts::U16, Key, KeyInit, Rc4, StreamCipher};

type HmacMd5 = Hmac<Md5>;

fn generate_key(password: &str) -> NtHash {
    NtHash::from(password)
}

pub fn encrypt(plaintext: &[u8], password: &str) -> Option<Vec<u8>> {
    const MESSAGE_TYPE: &[u8; 4] = b"\x02\0\0\0";
    let nt_hash = NtHash::from(password);
    let mac = <HmacMd5 as Mac>::new_from_slice(nt_hash.as_slice()).unwrap();
    let k1 = mac.chain_update(MESSAGE_TYPE).finalize().into_bytes();
    let mut nonce = [0u8; 8];
    nonce.try_fill(&mut OsRng).ok()?;
    let mac = <HmacMd5 as Mac>::new_from_slice(&k1).unwrap();
    let checksum = mac
        .chain_update(nonce)
        .chain_update(plaintext)
        .finalize()
        .into_bytes();
    let mac = <HmacMd5 as Mac>::new_from_slice(&k1).unwrap();
    let k3 = mac.chain_update(checksum).finalize().into_bytes();
    let key = Key::<U16>::from_slice(&k3);
    let mut output = checksum.to_vec();
    output.extend_from_slice(&nonce);
    output.extend_from_slice(plaintext);
    let mut rc4 = Rc4::new(key);
    rc4.apply_keystream(&mut output[16..]);
    Some(output)
}

pub fn decrypt(edata: &mut [u8], password: &str) -> Option<()> {
    const MESSAGE_TYPE: &[u8; 4] = b"\x02\0\0\0";
    let checksum = &edata[..16];
    let confounder = &edata[16..24];
    let data = &edata[24..];
    let nt_hash = NtHash::from(password);
    let mac = <HmacMd5 as Mac>::new_from_slice(nt_hash.as_slice()).unwrap();
    let k1 = mac.chain_update(MESSAGE_TYPE).finalize().into_bytes();
    let mac = <HmacMd5 as Mac>::new_from_slice(&k1).unwrap();
    let k3 = mac.chain_update(checksum).finalize().into_bytes();
    let key = Key::<U16>::from_slice(&k3);
    let mut rc4 = Rc4::new(key);
    rc4.apply_keystream(&mut edata[16..]);
    Some(())
}

#[cfg(test)]
mod tests {
    use pretty_hex::PrettyHex;

    use super::*;

    #[test]
    fn encrypt_decrypt_is_idempotent() {
        let plaintext = b"THIS IS A TEST".as_slice();
        let mut edata = encrypt(plaintext, "Password").unwrap();
        dbg!(&edata.hex_dump());
        decrypt(&mut edata, "Password").unwrap();
        dbg!(&edata.hex_dump());
        assert_eq!(&edata[24..].as_ref(), &plaintext)
    }
}
