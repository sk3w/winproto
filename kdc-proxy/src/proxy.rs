use std::{io, net::SocketAddr, sync::Arc};

use futures::{
    future::abortable,
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use tokio_util::codec::Framed;
use tracing::{info, warn};

use crate::{
    handler::{Handler, HandlerAction},
    KdcCodec, KdcFrame,
};

pub struct KdcProxy {
    client_framed: Framed<TcpStream, KdcCodec>,
    server_framed: Framed<TcpStream, KdcCodec>,
}

impl KdcProxy {
    pub async fn listen(
        listen_addr: SocketAddr,
        remote_addr: SocketAddr,
        handler: impl Handler + Clone + Send + 'static,
    ) -> io::Result<()> {
        let listener = TcpListener::bind(listen_addr).await?;
        info!("Listening on {listen_addr}");
        loop {
            let (client_stream, client_addr) = listener.accept().await?;
            info!("Received connection from {client_addr}");
            let client_framed = Framed::new(client_stream, KdcCodec);
            let server_stream = TcpStream::connect(remote_addr).await?;
            let server_framed = Framed::new(server_stream, KdcCodec);
            let proxy = KdcProxy {
                client_framed,
                server_framed,
            };
            tokio::spawn(proxy.run(handler.clone()));
        }
    }

    async fn run(self, handler: impl Handler + Send + 'static) -> io::Result<()> {
        let (client_sink, mut client_stream): (
            SplitSink<Framed<TcpStream, KdcCodec>, KdcFrame>,
            SplitStream<Framed<TcpStream, KdcCodec>>,
        ) = self.client_framed.split();
        let (mut server_sink, mut server_stream): (
            SplitSink<Framed<TcpStream, KdcCodec>, KdcFrame>,
            SplitStream<Framed<TcpStream, KdcCodec>>,
        ) = self.server_framed.split();
        let client_sink = Arc::new(Mutex::new(client_sink));
        let client_reply_sink = client_sink.clone();
        let handler = Arc::new(Mutex::new(handler));
        let handler2 = handler.clone();

        // Handle messages from client
        let (client_future, client_abort_handle) = abortable(async move {
            while let Some(item) = client_stream.next().await {
                // match item {
                //     Ok(KdcFrame::AsReq(as_req)) => {
                //         info!("Received AS_REQ, forwarding to KDC...");
                //         server_sink.send(as_req.into()).await.unwrap();
                //     }
                //     Ok(KdcFrame::TgsReq(tgs_req)) => {
                //         info!("Received TGS_REQ, forwarding to KDC...");
                //         server_sink.send(tgs_req.into()).await.unwrap();
                //     }
                //     Ok(frame) => {
                //         warn!("Received unexpected message from client: {frame:?}");
                //     }
                //     Err(error) => warn!("Failed to parse message from client: {}", &error),
                // }
                if let Ok(frame) = item {
                    match handler.lock().await.handle_downstream(frame) {
                        HandlerAction::Forward(frame) => {
                            info!("Forwarding message to KDC...");
                            server_sink.send(frame).await.unwrap();
                        }
                        HandlerAction::DropAndReplyWith(frame) => {
                            info!("Dropping message to KDC and sending reply to client...");
                            client_reply_sink.lock().await.send(frame).await.unwrap();
                        }
                        HandlerAction::DropSilently => {
                            info!("Dropping message to KDC silently!");
                            // don't do anything
                        }
                    }
                } else {
                    warn!("Failed to parse message from client!");
                }
            }
        });

        // Handle messages from KDC
        let (server_future, server_abort_handle) = abortable(async move {
            while let Some(item) = server_stream.next().await {
                // match item {
                //     Ok(KdcFrame::AsRep(as_rep)) => {
                //         info!("Received AS_REP, forwarding to client...");
                //         client_sink.lock().await.send(as_rep.into()).await.unwrap();
                //     }
                //     Ok(KdcFrame::TgsRep(tgs_rep)) => {
                //         info!("Received TGS_REP, forwarding to client...");
                //         client_sink.lock().await.send(tgs_rep.into()).await.unwrap();
                //     }
                //     Ok(KdcFrame::KrbError(krb_error)) => {
                //         info!("Received KRB_ERROR, forwarding to client...");
                //         client_sink
                //             .lock()
                //             .await
                //             .send(krb_error.into())
                //             .await
                //             .unwrap();
                //     }
                //     Ok(frame) => {
                //         warn!("Received unexpected message from KDC: {frame:?}");
                //     }
                //     Err(error) => warn!("Failed to parse message from KDC: {}", &error),
                // }
                match item {
                    Ok(frame) => match handler2.lock().await.handle_upstream(frame) {
                        HandlerAction::Forward(frame) => {
                            client_sink.lock().await.send(frame).await.unwrap();
                        }
                        HandlerAction::DropAndReplyWith(_) => {
                            info!("Dropping message to KDC and sending reply to client...");
                            todo!()
                        }
                        HandlerAction::DropSilently => {
                            info!("Dropping message from KDC silently!");
                            // don't do anything
                        }
                    },
                    Err(error) => warn!("Failed to parse message from KDC: {}", &error),
                }
            }
        });

        tokio::select! {
            _ = tokio::spawn(client_future) => {
                info!("Client disconnected");
                server_abort_handle.abort();
            }
            _ = tokio::spawn(server_future) => {
                info!("Server disconnected");
                client_abort_handle.abort();
            }
        }
        Ok(())
    }
}
