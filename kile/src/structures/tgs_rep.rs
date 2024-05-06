use rasn_kerberos::TgsRep;

use super::TicketExt;

pub trait TgsRepExt {
    fn get_spn(&self) -> String;
}

impl TgsRepExt for TgsRep {
    /// Get Service Principal Name from TGS-REP ticket field
    fn get_spn(&self) -> String {
        self.0.ticket.get_spn()
    }
}