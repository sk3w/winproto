use itertools::Itertools;
use rasn::der;
use rasn_kerberos::{EncKrbCredPart, KrbCred};

pub trait KrbCredExt {
    fn show(&self) -> String;
}

impl KrbCredExt for KrbCred {
    fn show(&self) -> String {
        let ticket = self.tickets.first().unwrap();
        let body: EncKrbCredPart = der::decode(self.enc_part.cipher.as_ref()).unwrap();
        format!(
            "[TGT]\nRealm: {}\nPrincipalName: {:?}\nBody: {:#?}",
            ticket.realm.as_str(),
            &ticket
                .sname
                .string
                .iter()
                .map(|i| i.as_str())
                .intersperse("/")
                .collect::<String>(),
            &body,
        )
    }
}
