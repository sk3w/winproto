use chrono::Utc;
use rasn::der;
use rasn_kerberos::{KerberosTime, PaData, PaEncTsEnc};

use crate::{constants::PA_ENC_TIMESTAMP, crypt::encrypt_timestamp};

pub trait PaDataExt {
    //fn new() -> Self;
    fn pa_enc_timestamp_now(password: &str) -> Self;
    fn pa_enc_timestamp_now_extended(password: &str) -> Self;
}

impl PaDataExt for PaData {
    fn pa_enc_timestamp_now(password: &str) -> Self {
        let timestamp = PaEncTsEnc {
            patimestamp: KerberosTime(Utc::now().into()),
            pausec: Some(65536.into()),
        };
        let plaintext = der::encode(&timestamp).unwrap();
        let cipher = encrypt_timestamp(&plaintext, password);
        let value = der::encode(&cipher).unwrap().into();
        Self {
            r#type: PA_ENC_TIMESTAMP,
            value,
        }
    }

    /// Temporary function for testing
    fn pa_enc_timestamp_now_extended(password: &str) -> Self {
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(b"\x30\x84\x00\x00\x00\x2c");
        plaintext.extend_from_slice(b"\xa0\x84\x00\x00\x00\x16");
        plaintext.extend_from_slice(b"\x18\x84\x00\x00\x00\x10");
        let ascii = format!("{}", Utc::now().format("%Y%m%d%H%M%SZ\0")).into_bytes();
        plaintext.extend(ascii);
        plaintext
            .extend_from_slice(b"\xa1\x84\x00\x00\x00\x0a\x02\x84\x00\x00\x00\x04\x00\x00\x03\xe7");
        let cipher = encrypt_timestamp(&plaintext, password);
        let value = der::encode(&cipher).unwrap().into();
        Self {
            r#type: PA_ENC_TIMESTAMP,
            value,
        }
    }
}
