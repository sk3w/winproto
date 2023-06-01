use std::{
    io,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use chrono::Utc;
use clap::Parser;
use kile::{
    structures::{AsRepExt, AsReqExt},
    KdcClient, KdcFrame,
};

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
/// get-tgt - Request a Kerberos TGT
struct Args {
    /// IP address of KDC
    target: IpAddr,

    /// Realm
    #[arg(short, long)]
    realm: String,

    /// Hostname
    #[arg(short, long, default_value = "WIN10")]
    hostname: String,

    /// Username
    #[arg(short, long)]
    username: String,

    /// Password
    #[arg(short, long)]
    password: String,

    /// Output (kirbi) filepath
    #[arg(short, long, value_name = "PATH")]
    output: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    let mut client = KdcClient::connect(SocketAddr::new(args.target, 88)).await?;
    let as_req = AsReqExt::new_rc4(args.realm, args.hostname, args.username, &args.password);
    let rep = client.send_as_req(as_req).await?;
    match rep {
        KdcFrame::AsRep(as_rep) => {
            let session_key = as_rep.get_session_key(&args.password).unwrap();
            println!(
                "Received a TGT for {}@{}",
                as_rep.get_cname(),
                as_rep.get_crealm(),
            );
            let path = args.output.unwrap_or_else(|| {
                PathBuf::from(format!(
                    "{}@{}_{}.kirbi",
                    as_rep.get_cname(),
                    as_rep.get_crealm(),
                    Utc::now().format("%Y%m%dT%H%M%S")
                ))
            });
            kile::fs::write_tgt_to_kirbi(as_rep, session_key, &path).unwrap();
            println!("Saved TGT to: {}", &path.display());
        }
        KdcFrame::KrbError(krb_error) => {
            dbg!(krb_error);
        }
        _ => unreachable!(),
    }
    Ok(())
}
