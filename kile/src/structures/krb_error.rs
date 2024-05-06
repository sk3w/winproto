use bytes::Bytes;
use chrono::Utc;
use rasn::types::SequenceOf;
use rasn_kerberos::{
    EtypeInfo2, EtypeInfo2Entry, KerberosString, KerberosTime, KrbError, PaData, PrincipalName,
};

use crate::constants::{KDC_ERR_PREAUTH_REQUIRED, PA_ENC_TIMESTAMP, PA_ETYPE_INFO2};

pub use self::builder::KrbErrorBuilder;
use self::builder::{NoErrorCode, NoRealm, NoSname};

pub trait KrbErrorExt {
    fn builder() -> KrbErrorBuilder<NoErrorCode, NoRealm, NoSname>;
    fn new_preauth_required(realm: String, etype: i32) -> Self;
}

impl KrbErrorExt for KrbError {
    fn builder() -> KrbErrorBuilder<NoErrorCode, NoRealm, NoSname> {
        KrbErrorBuilder::new()
    }

    fn new_preauth_required(realm: String, etype: i32) -> Self {
        let etype_info: EtypeInfo2 = vec![EtypeInfo2Entry {
            etype,
            salt: None,
            s2kparams: None,
        }];
        let e_data: SequenceOf<PaData> = vec![
            PaData {
                r#type: PA_ETYPE_INFO2,
                value: rasn::der::encode(&etype_info).unwrap().into(),
            },
            PaData {
                r#type: PA_ENC_TIMESTAMP,
                value: Bytes::new(),
            },
            PaData {
                r#type: 16.into(),
                value: Bytes::new(),
            },
            PaData {
                r#type: 15.into(),
                value: Bytes::new(),
            },
        ];
        let e_data = Some(rasn::der::encode(&e_data).unwrap().into());
        Self {
            pvno: 5.into(),
            msg_type: 30.into(),
            ctime: None,
            cusec: None,
            stime: KerberosTime(Utc::now().into()),
            susec: 500001.into(),
            error_code: KDC_ERR_PREAUTH_REQUIRED,
            crealm: None,
            cname: None,
            realm: KerberosString::new(realm.clone()),
            sname: PrincipalName {
                r#type: 2,
                string: vec!["krbtgt".to_string().into(), realm.into()],
            },
            e_text: None,
            e_data,
        }
    }
}

mod builder {
    use bytes::Bytes;
    use rasn::types::Integer;
    use rasn_kerberos::{KerberosString, KerberosTime, KrbError, Microseconds, PrincipalName};

    pub struct KrbErrorBuilder<E, R, S> {
        stime: Option<KerberosTime>,
        susec: Option<Microseconds>,
        error_code: E,
        realm: R,
        sname: S,
        e_text: Option<KerberosString>,
        e_data: Option<Bytes>,
    }

    pub struct NoErrorCode;
    pub struct ErrorCode(i32);

    pub struct NoRealm;
    pub struct Realm(KerberosString);

    pub struct NoSname;
    pub struct Sname(PrincipalName);

    impl KrbErrorBuilder<NoErrorCode, NoRealm, NoSname> {
        pub const fn new() -> Self {
            Self {
                stime: None,
                susec: None,
                error_code: NoErrorCode,
                realm: NoRealm,
                sname: NoSname,
                e_text: None,
                e_data: None,
            }
        }
    }

    impl<R, S> KrbErrorBuilder<NoErrorCode, R, S> {
        pub fn error_code(self, error_code: i32) -> KrbErrorBuilder<ErrorCode, R, S> {
            KrbErrorBuilder {
                stime: self.stime,
                susec: self.susec,
                error_code: ErrorCode(error_code),
                realm: self.realm,
                sname: self.sname,
                e_text: self.e_text,
                e_data: self.e_data,
            }
        }
    }

    impl<E, S> KrbErrorBuilder<E, NoRealm, S> {
        pub fn realm(self, realm: impl Into<KerberosString>) -> KrbErrorBuilder<E, Realm, S> {
            KrbErrorBuilder {
                stime: self.stime,
                susec: self.susec,
                error_code: self.error_code,
                realm: Realm(realm.into()),
                sname: self.sname,
                e_text: self.e_text,
                e_data: self.e_data,
            }
        }
    }

    impl<E, R> KrbErrorBuilder<E, R, NoSname> {
        pub fn sname(self, sname: PrincipalName) -> KrbErrorBuilder<E, R, Sname> {
            KrbErrorBuilder {
                stime: self.stime,
                susec: self.susec,
                error_code: self.error_code,
                realm: self.realm,
                sname: Sname(sname),
                e_text: self.e_text,
                e_data: self.e_data,
            }
        }
    }

    // Manipulate default / optional fields
    impl<E, R, S> KrbErrorBuilder<E, R, S> {
        pub fn with_e_text(self, e_text: impl Into<KerberosString>) -> Self {
            Self {
                stime: self.stime,
                susec: self.susec,
                error_code: self.error_code,
                realm: self.realm,
                sname: self.sname,
                e_text: Some(e_text.into()),
                e_data: self.e_data,
            }
        }
    }

    impl KrbErrorBuilder<ErrorCode, Realm, Sname> {
        pub fn build(self) -> KrbError {
            let now = chrono::offset::Local::now();
            KrbError {
                pvno: Integer::from(5),
                msg_type: Integer::from(30),
                ctime: None,
                cusec: None,
                stime: self
                    .stime
                    .unwrap_or_else(|| KerberosTime(now.fixed_offset())),
                susec: self
                    .susec
                    .unwrap_or_else(|| now.timestamp_subsec_micros().into()),
                error_code: self.error_code.0,
                crealm: None,
                cname: None,
                realm: self.realm.0,
                sname: self.sname.0,
                e_text: self.e_text,
                e_data: self.e_data,
            }
        }
    }
}
