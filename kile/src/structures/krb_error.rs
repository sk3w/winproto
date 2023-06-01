use bytes::Bytes;
use chrono::Utc;
use rasn::types::SequenceOf;
use rasn_kerberos::{
    EtypeInfo2, EtypeInfo2Entry, KerberosString, KerberosTime, KrbError, PaData, PrincipalName,
};

use crate::constants::{KDC_ERR_PREAUTH_REQUIRED, PA_ENC_TIMESTAMP, PA_ETYPE_INFO2};

pub trait KrbErrorExt {
    fn new_preauth_required(realm: String, etype: i32) -> Self;
}

impl KrbErrorExt for KrbError {
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
