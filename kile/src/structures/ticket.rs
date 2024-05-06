use itertools::Itertools;
use rasn_kerberos::Ticket;

pub trait TicketExt {
    fn get_spn(&self) -> String;
}

impl TicketExt for Ticket {
    fn get_spn(&self) -> String {
        self.sname
            .string
            .iter()
            .map(|i| i.as_str())
            .intersperse("/")
            .collect::<String>()
    }
}
