use chrono::{TimeZone, Utc};
use rand::{rngs::OsRng, RngCore};
use rasn::der;
use rasn_kerberos::{
    AsReq, HostAddress, KdcOptions, KdcReq, KdcReqBody, KerberosFlags, KerberosString,
    KerberosTime, PaData, PaEncTimestamp, PrincipalName,
};

use crate::constants::{ETYPE_RC4_HMAC_MD5, PA_ENC_TIMESTAMP, PA_PAC_REQUEST};

use super::PaDataExt;

pub trait AsReqExt {
    fn new(cname: String, realm: String) -> Self;
    fn new_rc4(realm: String, hostname: String, username: String, password: &str) -> Self;
    fn get_pa_enc_timestamp(&self) -> Option<PaEncTimestamp>;
    fn get_pa_etype(&self) -> Option<i32>;
    fn get_cname(&self) -> Option<&str>;
    fn get_realm(&self) -> &str;
    fn replace_etypes(self, etype: i32) -> Self;
}

impl AsReqExt for AsReq {
    fn new(cname: String, realm: String) -> Self {
        Self(KdcReq {
            pvno: 5.into(),
            msg_type: 10.into(),
            padata: None,
            req_body: KdcReqBody {
                kdc_options: KdcOptions(KerberosFlags::from_slice(b"\x40\x81\x00\x10")),
                cname: Some(PrincipalName {
                    r#type: PA_PAC_REQUEST,
                    string: vec![KerberosString::new(cname)],
                }),
                realm: KerberosString::new(realm),
                sname: None,
                from: None,
                till: KerberosTime(Utc.timestamp_nanos(2136422885_000_000_000).into()),
                rtime: Some(KerberosTime(
                    Utc.timestamp_nanos(2136422885_000_000_000).into(),
                )),
                nonce: OsRng.next_u32(),
                etype: vec![ETYPE_RC4_HMAC_MD5],
                addresses: Some(vec![HostAddress {
                    addr_type: HostAddress::NET_BIOS,
                    address: b"WIN10".as_ref().into(),
                }]),
                enc_authorization_data: None,
                additional_tickets: None,
            },
        })
    }

    /// Generate a new AS-REQ with current timestamp and RC4-HMAC-MD5 encrypted preauth
    fn new_rc4(realm: String, hostname: String, username: String, password: &str) -> Self {
        Self(KdcReq {
            pvno: 5.into(),
            msg_type: 10.into(),
            padata: Some(vec![
                PaData::pa_enc_timestamp_now(password),
                PaData {
                    r#type: PA_PAC_REQUEST,
                    value: b"\x30\x05\xa0\x03\x01\x01\xff".as_ref().into(),
                },
            ]),
            req_body: KdcReqBody {
                kdc_options: KdcOptions(KerberosFlags::from_slice(b"\x40\x81\x00\x10")),
                cname: Some(PrincipalName {
                    r#type: 1,
                    string: vec![KerberosString::new(username)],
                }),
                realm: KerberosString::new(realm.to_owned()),
                sname: Some(PrincipalName {
                    r#type: 2,
                    string: vec![
                        KerberosString::new("krbtgt".to_owned()),
                        KerberosString::new(realm),
                    ],
                }),
                from: None,
                // default timestamp value used by Microsoft clients
                till: KerberosTime(Utc.timestamp_nanos(2136422885_000_000_000).into()),
                rtime: Some(KerberosTime(
                    Utc.timestamp_nanos(2136422885_000_000_000).into(),
                )),
                nonce: OsRng.next_u32(),
                etype: vec![ETYPE_RC4_HMAC_MD5],
                addresses: Some(vec![HostAddress {
                    addr_type: HostAddress::NET_BIOS,
                    address: hostname.into(),
                }]),
                enc_authorization_data: None,
                additional_tickets: None,
            },
        })
    }

    fn get_pa_enc_timestamp(&self) -> Option<PaEncTimestamp> {
        let padata_entries = self.0.padata.as_ref()?;
        let entry = padata_entries
            .iter()
            .filter(|e| e.r#type == PA_ENC_TIMESTAMP)
            .next()?;
        let pa_enc_timestamp: PaEncTimestamp = der::decode(&entry.value).ok()?;
        Some(pa_enc_timestamp)
    }

    fn get_pa_etype(&self) -> Option<i32> {
        let padata_entries = self.0.padata.as_ref()?;
        let entry = padata_entries
            .iter()
            .filter(|e| e.r#type == PA_ENC_TIMESTAMP)
            .next()?;
        let pa_enc_timestamp: PaEncTimestamp = der::decode(&entry.value).ok()?;
        Some(pa_enc_timestamp.etype)
    }

    fn get_cname(&self) -> Option<&str> {
        Some(
            self.0
                .req_body
                .cname
                .as_ref()?
                .string
                .iter()
                .next()?
                .as_str(),
        )
    }

    fn get_realm(&self) -> &str {
        self.0.req_body.realm.as_str()
    }

    fn replace_etypes(mut self, etype: i32) -> Self {
        self.0.req_body.etype = vec![etype];
        self
    }
}
