# winproto
Some tools for researching windows protocols

## Building
You will need Rust installed to compile this code (`https://rustup.rs` is recommended.) From the root workspace, run `cargo build --release`, and the binaries will be under `./target/release`.

## nmf-proxy
Example usage:
```
nmf-proxy -l 127.0.0.1:9389 -r <TARGET_IP_ADDRESS>:9389
[*] Listening on 127.0.0.1:9389
[*] Received connection from 127.0.0.1:58225
[*] Client Request: Preamble(
    PreambleMessage {
        version: VersionRecord,
        mode: Duplex,
        via: ViaRecord(
            "net.tcp://localhost:9389/ActiveDirectoryWebServices/mex",
        ),
        encoding: Soap12Nbfse,
    },
)
[*] Client Request: PreambleEnd(
    PreambleEndRecord,
)
[*] Server Response: PreambleAck(
    PreambleAckRecord,
)
```