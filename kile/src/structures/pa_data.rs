use bytes::Bytes;
use chrono::Utc;
use rasn::der;
use rasn_kerberos::{KerberosTime, PaData, PaEncTsEnc};

use crate::{
    constants::{PA_ENC_TIMESTAMP, PA_PAC_REQUEST},
    crypt::{encrypt_timestamp, rc4_hmac},
};

pub trait PaDataExt {
    fn include_pac() -> Self;
    fn exclude_pac() -> Self;
    fn pa_enc_timestamp_now(password: &str) -> Self;
    fn pa_enc_timestamp_now_extended(password: &str) -> Self;
}

impl PaDataExt for PaData {
    fn include_pac() -> Self {
        Self {
            r#type: PA_PAC_REQUEST,
            value: Bytes::from_static(b"\x30\x05\xa0\x03\x01\x01\xff".as_ref()),
        }
    }

    fn exclude_pac() -> Self {
        Self {
            r#type: PA_PAC_REQUEST,
            value: Bytes::from_static(b"\x30\x05\xa0\x03\x01\x01\x00".as_ref()),
        }
    }

    fn pa_enc_timestamp_now(password: &str) -> Self {
        let timestamp = PaEncTsEnc {
            patimestamp: KerberosTime(Utc::now().into()),
            pausec: Some(65536.into()),
        };
        let plaintext = der::encode(&timestamp).unwrap();
        //let cipher = encrypt_timestamp(&plaintext, password);
        let cipher = rc4_hmac::encrypt(&plaintext, password).unwrap();
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
