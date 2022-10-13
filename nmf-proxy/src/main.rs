use std::{net::SocketAddr, error::Error, io};

use clap::Parser;
use nmf_proxy::NmfProxy;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Address and port number to listen on
    #[arg(short, long, default_value = "127.0.0.1:8081")]
    listen_addr: SocketAddr,
    /// Address and port number of upstream service
    #[arg(short, long)]
    remote_addr: SocketAddr,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    let proxy = NmfProxy::listen(&args.listen_addr, &args.remote_addr).await?;
    proxy.run().await?;
    Ok(())
}