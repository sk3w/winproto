use chrono::{TimeZone, Utc};
use rand::{rngs::OsRng, RngCore};
use rasn::{der, types::SequenceOf};
use rasn_kerberos::{
    AsReq, HostAddress, KdcOptions, KdcReq, KdcReqBody, KerberosFlags, KerberosString,
    KerberosTime, PaData, PaEncTimestamp, PrincipalName,
};

use crate::constants::{ETYPE_RC4_HMAC_MD5, PA_ENC_TIMESTAMP, PA_PAC_REQUEST};

pub use self::builder::AsReqBuilder;
use self::builder::{NoCname, NoEtype, NoOptions, NoRealm};

use super::PaDataExt;

pub trait AsReqExt {
    fn builder() -> AsReqBuilder<NoOptions, NoCname, NoRealm, NoEtype>;
    fn new(cname: String, realm: String) -> Self;
    fn new_rc4(realm: String, hostname: String, username: String, password: &str) -> Self;
    fn get_pa_enc_timestamp(&self) -> Option<PaEncTimestamp>;
    fn get_pa_etype(&self) -> Option<i32>;
    fn get_cname(&self) -> Option<&str>;
    fn get_realm(&self) -> &str;
    fn replace_pa_pac_request(self, include_pac: bool) -> Self;
    fn replace_spn(self, spn: SequenceOf<KerberosString>) -> Self;
    fn replace_etypes(self, etype: i32) -> Self;
}

impl AsReqExt for AsReq {
    fn builder() -> AsReqBuilder<NoOptions, NoCname, NoRealm, NoEtype> {
        AsReqBuilder::new()
    }

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
                // nonce: OsRng.next_u32(),
                nonce: 12345678,
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

    /// Replace any PA-PAC-REQUEST entries in PA-DATA with one new entry
    fn replace_pa_pac_request(mut self, include_pac: bool) -> Self {
        let include_pac = match include_pac {
            true => PaData {
                r#type: PA_PAC_REQUEST,
                value: b"\x30\x05\xa0\x03\x01\x01\xff".as_ref().into(),
            },
            false => PaData {
                r#type: PA_PAC_REQUEST,
                value: b"\x30\x05\xa0\x03\x01\x01\x00".as_ref().into(),
            },
        };
        let mut new_padata = Vec::new();
        if let Some(padata_entries) = self.0.padata {
            new_padata.extend(
                padata_entries
                    .into_iter()
                    .filter(|e| e.r#type != PA_PAC_REQUEST),
            )
        }
        new_padata.push(include_pac);
        self.0.padata = Some(new_padata);
        self
    }

    /// Replace the sname field in the request body
    fn replace_spn(mut self, spn: SequenceOf<KerberosString>) -> Self {
        self.0.req_body.sname = Some(PrincipalName {
            r#type: 2,
            string: spn,
        });
        self
    }

    /// Replace all etype entries in the request body with a single entry
    fn replace_etypes(mut self, etype: i32) -> Self {
        self.0.req_body.etype = vec![etype];
        self
    }
}

mod builder {
    use chrono::{TimeZone, Utc};
    use rand::{rngs::OsRng, RngCore};
    use rasn::types::{Integer, SequenceOf};
    use rasn_kerberos::{
        AsReq, HostAddress, HostAddresses, KdcOptions, KdcReq, KdcReqBody, KerberosString,
        KerberosTime, PaData, PrincipalName,
    };

    use crate::constants::NT_SRV_INST;

    pub struct AsReqBuilder<O, C, R, E> {
        kdc_options: O,
        cname: C,
        realm: R,
        etype: E,
        padata: Option<SequenceOf<PaData>>,
        addresses: Option<HostAddresses>,
    }

    pub struct NoOptions;
    pub struct Options(KdcOptions);

    pub struct NoCname;
    pub struct Cname(PrincipalName);

    pub struct NoRealm;
    pub struct Realm(KerberosString);

    pub struct NoEtype;
    pub struct Etype(Vec<i32>);

    impl AsReqBuilder<NoOptions, NoCname, NoRealm, NoEtype> {
        pub const fn new() -> AsReqBuilder<NoOptions, NoCname, NoRealm, NoEtype> {
            AsReqBuilder {
                kdc_options: NoOptions,
                cname: NoCname,
                realm: NoRealm,
                etype: NoEtype,
                padata: None,
                addresses: None,
            }
        }
    }

    impl<C, R, E> AsReqBuilder<NoOptions, C, R, E> {
        pub fn kdc_options(self, kdc_options: KdcOptions) -> AsReqBuilder<Options, C, R, E> {
            AsReqBuilder {
                kdc_options: Options(kdc_options),
                cname: self.cname,
                realm: self.realm,
                etype: self.etype,
                padata: self.padata,
                addresses: self.addresses,
            }
        }
    }

    impl<O, R, E> AsReqBuilder<O, NoCname, R, E> {
        pub fn cname(self, cname: PrincipalName) -> AsReqBuilder<O, Cname, R, E> {
            AsReqBuilder {
                kdc_options: self.kdc_options,
                cname: Cname(cname),
                realm: self.realm,
                etype: self.etype,
                padata: self.padata,
                addresses: self.addresses,
            }
        }
    }

    impl<O, C, E> AsReqBuilder<O, C, NoRealm, E> {
        pub fn realm(self, realm: impl Into<KerberosString>) -> AsReqBuilder<O, C, Realm, E> {
            AsReqBuilder {
                kdc_options: self.kdc_options,
                cname: self.cname,
                realm: Realm(realm.into()),
                etype: self.etype,
                padata: self.padata,
                addresses: self.addresses,
            }
        }
    }

    impl<O, C, R> AsReqBuilder<O, C, R, NoEtype> {
        pub fn etype(self, etype: Vec<i32>) -> AsReqBuilder<O, C, R, Etype> {
            AsReqBuilder {
                kdc_options: self.kdc_options,
                cname: self.cname,
                realm: self.realm,
                etype: Etype(etype),
                padata: self.padata,
                addresses: self.addresses,
            }
        }
    }

    impl<O, C, R, E> AsReqBuilder<O, C, R, E> {
        pub fn with_padata(self, value: PaData) -> Self {
            let Self {
                kdc_options,
                cname,
                realm,
                etype,
                addresses,
                ..
            } = self;
            let padata = match self.padata {
                None => Some(vec![value]),
                Some(mut values) => {
                    values.push(value);
                    Some(values)
                }
            };
            Self {
                kdc_options,
                cname,
                realm,
                etype,
                padata,
                addresses,
            }
        }
    }
    impl<O, C, R, E> AsReqBuilder<O, C, R, E> {
        pub fn with_address(self, value: HostAddress) -> Self {
            let Self {
                kdc_options,
                cname,
                realm,
                etype,
                padata,
                ..
            } = self;
            let addresses = match self.addresses {
                None => Some(vec![value]),
                Some(mut values) => {
                    values.push(value);
                    Some(values)
                }
            };
            Self {
                kdc_options,
                cname,
                realm,
                etype,
                padata,
                addresses,
            }
        }
    }

    impl AsReqBuilder<Options, Cname, Realm, Etype> {
        pub fn build(self) -> AsReq {
            let service_realm = self.realm.0.clone();
            AsReq(KdcReq {
                pvno: Integer::from(5),
                msg_type: Integer::from(10),
                padata: self.padata,
                req_body: KdcReqBody {
                    kdc_options: self.kdc_options.0,
                    // TODO: Make cname optional?
                    cname: Some(self.cname.0),
                    realm: self.realm.0,
                    // TODO: Make defaut sname, allow override
                    sname: Some(PrincipalName {
                        r#type: NT_SRV_INST,
                        string: vec![KerberosString::new("krbtgt".to_owned()), service_realm],
                    }),
                    from: None,
                    till: KerberosTime(Utc.timestamp_nanos(2136422885_000_000_000).into()),
                    rtime: Some(KerberosTime(
                        Utc.timestamp_nanos(2136422885_000_000_000).into(),
                    )),
                    nonce: OsRng.next_u32() & 0x7fffffff, // Windows doesn't like the high bit set
                    etype: self.etype.0,
                    addresses: self.addresses,
                    enc_authorization_data: None,
                    additional_tickets: None,
                },
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use bytes::Bytes;
        use rasn::der;
        use rasn_kerberos::{EncryptedData, KerberosFlags};

        use crate::constants::{
            ETYPE_AES128_CTS_HMAC_SHA1_96, ETYPE_RC4_MD4, NT_PRINCIPAL, PA_ENC_TIMESTAMP,
            PA_PAC_REQUEST,
        };

        use super::super::*;

        #[test]
        fn build_works() {
            let cname = PrincipalName {
                r#type: NT_PRINCIPAL,
                string: vec![KerberosString::new("vagrant".to_owned())],
            };
            let realm = KerberosString::new("WINDOMAIN.LOCAL".to_owned());
            let enc_ts = Bytes::from_static(b"aaaabbbbccccdddd");
            let as_req = AsReqBuilder::new()
                .with_padata(PaData {
                    r#type: PA_ENC_TIMESTAMP,
                    value: der::encode(&EncryptedData {
                        etype: ETYPE_RC4_MD4,
                        kvno: None,
                        cipher: enc_ts.clone(),
                    })
                    .unwrap()
                    .into(),
                })
                .with_padata(PaData {
                    r#type: PA_PAC_REQUEST,
                    value: b"\x30\x05\xa0\x03\x01\x01\xff".as_ref().into(),
                })
                .kdc_options(KdcOptions(KerberosFlags::from_slice(b"\x40\x81\x00\x10")))
                .cname(cname.clone())
                .realm(realm.clone())
                .etype(vec![ETYPE_AES128_CTS_HMAC_SHA1_96])
                .with_address(HostAddress {
                    addr_type: HostAddress::NET_BIOS,
                    address: b"WORKSTATION".as_ref().into(),
                })
                .build();
            todo!()
        }
    }
}
