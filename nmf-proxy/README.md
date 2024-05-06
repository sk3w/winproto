# nmf-proxy
A MITM proxy tool for [MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/0aab922d-8023-48bb-8ba2-c4d3404cc69d) traffic

## Usage
Example usage:
```
$ nmf-proxy -l 127.0.0.1:9389 -r <TARGET_IP_ADDRESS>:9389
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