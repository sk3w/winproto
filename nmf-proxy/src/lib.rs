use std::{io, net::SocketAddr};

use futures::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use nmf::{codec::NmfCodec, frame::NmfFrame};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;

pub struct NmfProxy {
    downstream: Framed<TcpStream, NmfCodec>,
    upstream: Framed<TcpStream, NmfCodec>,
}

impl NmfProxy {
    pub async fn listen(listen_addr: &SocketAddr, remote_addr: &SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(&listen_addr).await?;
        println!("[*] Listening on {}", &listen_addr);
        let (client_stream, client_addr) = listener.accept().await?;
        println!("[*] Received connection from {}", &client_addr);
        let downstream = Framed::new(client_stream, NmfCodec);
        let server_stream = TcpStream::connect(remote_addr).await?;
        let upstream = Framed::new(server_stream, NmfCodec);
        Ok(Self {
            downstream,
            upstream,
        })
    }

    pub async fn run(self) -> io::Result<()> {
        // Split read & write
        let (mut down_write, mut down_read): (
            SplitSink<Framed<TcpStream, NmfCodec>, NmfFrame>,
            SplitStream<Framed<TcpStream, NmfCodec>>,
        ) = self.downstream.split();
        let (mut up_write, mut up_read): (
            SplitSink<Framed<TcpStream, NmfCodec>, NmfFrame>,
            SplitStream<Framed<TcpStream, NmfCodec>>,
        ) = self.upstream.split();

        // Handle messages from client
        let down_handler = tokio::spawn(async move {
            while let Some(res) = down_read.next().await {
                match res {
                    Ok(msg) => {
                        println!("[*] Client Request: {:#?}", &msg);
                        up_write.send(msg).await.unwrap();
                    }
                    Err(_) => (), // TODO: Handle codec errors
                }
            }
        });

        // Handle messages from server
        let up_handler = tokio::spawn(async move {
            while let Some(res) = up_read.next().await {
                match res {
                    Ok(msg) => {
                        println!("[*] Server Response {:#?}", &msg);
                        down_write.send(msg).await.unwrap();
                    }
                    Err(_) => (), // TODO: Handle codec errors
                }
            }
        });
        let (_down_res, _up_res) = (down_handler.await.unwrap(), up_handler.await.unwrap());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
