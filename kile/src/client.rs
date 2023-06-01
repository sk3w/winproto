use std::{io, net::SocketAddr};

use futures::{SinkExt, StreamExt};
use rasn_kerberos::AsReq;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::{KdcCodec, KdcFrame};

pub struct KdcClient {
    framed: Framed<TcpStream, KdcCodec>,
}

impl KdcClient {
    pub async fn connect(addr: SocketAddr) -> io::Result<Self> {
        let tcp_stream = TcpStream::connect(addr).await?;
        let framed = Framed::new(tcp_stream, KdcCodec);
        Ok(Self { framed })
    }

    pub async fn send_as_req(&mut self, as_req: AsReq) -> io::Result<KdcFrame> {
        self.framed.send(KdcFrame::AsReq(as_req)).await?;
        let response = self.framed.next().await.unwrap()?;
        Ok(response)
    }
}
