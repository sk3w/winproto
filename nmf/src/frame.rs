extern crate alloc;

use alloc::vec::Vec;
use bytes::Bytes;
use derive_more::{From, TryInto};

use crate::records::*;

#[derive(Debug, From, PartialEq, TryInto)]
pub enum NmfFrame {
    Preamble(PreambleMessage),
    PreambleEnd(PreambleEndRecord),
    PreambleAck(PreambleAckRecord),
    UpgradeRequest(UpgradeRequestRecord),
    UpgradeResponse(UpgradeResponseRecord),
    End(EndRecord),
    SizedEnvelope(SizedEnvelopeRecord),
    UnsizedEnvelope(UnsizedEnvelopeRecord),
    Fault(FaultRecord),
    Unknown(Bytes),
}
