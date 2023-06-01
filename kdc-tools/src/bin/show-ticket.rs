use std::{io, path::PathBuf};

use clap::Parser;
use kile::structures::KrbCredExt;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
/// show-ticket - Display information from saved (kirbi) TGTs
struct Args {
    /// TGT (kirbi) filepath
    path: PathBuf,
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    let ticket = kile::fs::read_kirbi(&args.path)?;
    println!("{}", &ticket.show());
    //println!("{:?}", &ticket);
    Ok(())
}
