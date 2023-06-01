use rasn_kerberos::{AsRep, AsReq, KrbError, TgsRep, TgsReq};

#[derive(Debug, derive_more::From)]
pub enum KdcFrame {
    AsReq(AsReq),
    AsRep(AsRep),
    TgsReq(TgsReq),
    TgsRep(TgsRep),
    KrbError(KrbError),
}
