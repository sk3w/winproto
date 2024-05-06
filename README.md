# winproto
Some tools for researching windows protocols

## Building
You will need Rust installed to compile this code (`https://rustup.rs` is recommended.) From the root workspace, run `cargo build --release`, and the binaries will be under `./target/release`.

## Tools
- [kdc-proxy](kdc-proxy/README.md) - A MITM proxy tool for Kerberos KDC traffic
- [nmf-proxy](nmf-proxy/README.md) - A MITM proxy tool for [MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/0aab922d-8023-48bb-8ba2-c4d3404cc69d) traffic