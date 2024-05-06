use kile::{
    structures::{AsReqExt, KrbErrorExt},
    KdcFrame,
};
use rasn_kerberos::{KrbError, PrincipalName};
use tracing::info;

use super::{Handler, HandlerAction};

/// Handler that responds to AS-REQ messages with a KRB-ERROR
#[derive(Clone, Copy)]
pub struct ForgeErrorHandler {
    error_code: i32,
}

impl ForgeErrorHandler {
    pub fn new(error_code: i32) -> Self {
        Self { error_code }
    }
}

impl Handler for ForgeErrorHandler {
    fn name(&self) -> &'static str {
        "FORGE-ERROR"
    }

    fn handle_downstream(&mut self, frame: KdcFrame) -> HandlerAction {
        match &frame {
            KdcFrame::AsReq(as_req) => match as_req.get_pa_etype() {
                Some(_) => {
                    info!("Received AS-REQ with preauth, forging KRB-ERROR...");
                    let realm = as_req.get_realm().to_owned();
                    // let now = Local::now();
                    // let reply = KrbError {
                    //     pvno: 5.into(),
                    //     msg_type: 30.into(),
                    //     ctime: None,
                    //     cusec: None,
                    //     stime: KerberosTime(now.fixed_offset()),
                    //     susec: now.timestamp_subsec_micros().into(),
                    //     error_code: self.error_code,
                    //     crealm: None,
                    //     cname: None,
                    //     realm: KerberosString::new(realm.clone()),
                    //     sname: PrincipalName {
                    //         r#type: 2,
                    //         string: vec!["krbtgt".to_string().into(), realm.into()],
                    //     },
                    //     e_text: None,
                    //     e_data: None,
                    // };
                    let reply = KrbError::builder()
                        .error_code(self.error_code)
                        .realm(realm.clone())
                        .sname(PrincipalName {
                            r#type: 2,
                            string: vec!["krbtgt".to_owned().into(), realm.into()],
                        })
                        .build();
                    HandlerAction::DropAndReplyWith(KdcFrame::KrbError(reply))
                }
                None => {
                    info!("Received AS-REQ without preauth, forwarding to upstream KDC...");
                    HandlerAction::Forward(frame)
                }
            },
            _ => HandlerAction::Forward(frame),
        }
    }

    fn handle_upstream(&mut self, frame: KdcFrame) -> HandlerAction {
        HandlerAction::Forward(frame)
    }
}
