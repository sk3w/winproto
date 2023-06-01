use bytes::Bytes;
use rasn::der;
use rasn_kerberos::{AsRep, EncAsRepPart, EncryptedData, EncryptionKey};

use crate::{
    constants::{ETYPE_RC4_HMAC_MD5, ETYPE_RC4_MD4, KEY_USAGE_TGS_REP_ENC_PART},
    crypt::decrypt_rc4,
};

pub trait AsRepExt {
    fn get_crealm(&self) -> &str;
    fn get_cname(&self) -> &str;
    fn get_etype(&self) -> i32;
    fn get_rc4_md4_enc_part(&self) -> Option<Bytes>;
    fn get_enc_part(&self, password: &str) -> Option<EncAsRepPart>;
    fn get_session_key(&self, password: &str) -> Option<EncryptionKey>;
}

impl AsRepExt for AsRep {
    fn get_crealm(&self) -> &str {
        self.0.crealm.as_str()
    }

    fn get_cname(&self) -> &str {
        self.0.cname.string.iter().next().unwrap().as_str()
    }

    fn get_session_key(&self, password: &str) -> Option<EncryptionKey> {
        assert_eq!(self.0.enc_part.etype, ETYPE_RC4_HMAC_MD5);
        dbg!(self);
        let ciphertext = &self.0.enc_part.cipher;
        let plaintext = decrypt_rc4(ciphertext, password, KEY_USAGE_TGS_REP_ENC_PART).unwrap();
        let enc_as_rep_part: EncAsRepPart = der::decode(&plaintext).unwrap();
        Some(enc_as_rep_part.0.key)
    }

    fn get_etype(&self) -> i32 {
        self.0.enc_part.etype
    }

    fn get_enc_part(&self, password: &str) -> Option<EncAsRepPart> {
        assert_eq!(self.0.enc_part.etype, ETYPE_RC4_HMAC_MD5);
        let ciphertext = self.0.enc_part.cipher.as_ref();
        let plaintext = decrypt_rc4(ciphertext, password, KEY_USAGE_TGS_REP_ENC_PART)?;
        let enc_as_rep_part: EncAsRepPart = der::decode(&plaintext).ok()?;
        Some(enc_as_rep_part)
    }

    fn get_rc4_md4_enc_part(&self) -> Option<Bytes> {
        match &self.0.enc_part {
            EncryptedData {
                etype: ETYPE_RC4_MD4,
                kvno: _,
                cipher,
            } => Some(cipher.clone()),
            _ => None,
        }
    }
}
