extern crate std;

use futures::{SinkExt, StreamExt};
use std::{io, string::String, time::Duration};
use tokio::{
    net::{TcpStream, ToSocketAddrs},
    time::timeout,
};
use tokio_util::codec::Framed;

use crate::{
    codec::NmfCodec,
    frame::NmfFrame,
    records::{PreambleMessage, PreambleEndRecord, UpgradeRequestRecord},
};

/// # TCP client for .NET Message Framing Protocol
pub struct NetTcpClient {
    pub framed: Framed<TcpStream, NmfCodec>,
}

impl NetTcpClient {
    pub async fn connect(addr: impl ToSocketAddrs) -> io::Result<Self> {
        let tcp = timeout(Duration::from_secs(5), TcpStream::connect(addr)).await??;
        let framed = Framed::new(tcp, NmfCodec);
        Ok(Self { framed })
    }

    pub async fn send_preamble(&mut self, uri: String) -> io::Result<NmfFrame> {
        let msg = PreambleMessage::new(uri);
        self.framed.send(msg).await?;
        self.framed.send(PreambleEndRecord::default()).await?;
        match self.framed.next().await {
            Some(Ok(frame)) => Ok(frame),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Expected a NmfFrame",
            )),
        }
    }

    pub async fn send_negotiate(&mut self, uri: String) -> io::Result<NmfFrame> {
        let msg = PreambleMessage::new(uri);
        self.framed.send(msg).await?;
        self.framed.send(UpgradeRequestRecord::negotiate()).await?;
        match self.framed.next().await {
            Some(Ok(frame)) => Ok(frame),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Expected a NmfFrame",
            )),
        }
    }
}

/// # Named pipe client for .NET Message Framing Protocol
///
/// Currently unimplemented
pub struct NetPipeClient;
