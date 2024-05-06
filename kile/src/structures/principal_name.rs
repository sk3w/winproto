use itertools::Itertools;
use rasn_kerberos::{KerberosString, PrincipalName};

use crate::constants::{NT_ENTERPRISE, NT_PRINCIPAL};

pub trait PrincipalNameExt {
    fn new_principal(string: String) -> Self;
    fn new_enterprise(string: String) -> Self;
    fn to_string(&self) -> String;
}

impl PrincipalNameExt for PrincipalName {
    /// Create new NT-PRINCIPAL Principal Name from string
    fn new_principal(string: String) -> Self {
        Self {
            r#type: NT_PRINCIPAL,
            string: vec![KerberosString::new(string)],
        }
    }

    /// Create new NT-ENTERPRISE Principal Name from string
    fn new_enterprise(string: String) -> Self {
        Self {
            r#type: NT_ENTERPRISE,
            string: vec![KerberosString::new(string)],
        }
    }

    /// Convert Principal Name to "primary/instance" string format
    fn to_string(&self) -> String {
        self.string
            .iter()
            .map(|s| s.as_str())
            .intersperse("/")
            .collect()
    }
}
