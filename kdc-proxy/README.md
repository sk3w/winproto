# kdc-proxy
A MITM proxy tool for Kerberos KDC traffic

## Setup
This tool runs a transparent KDC proxy service to receive KRB5 client messages and forward them to an upstream KDC.
You will need a separate method to get clients to connect to your service.

In a lab environment, one simple way is to add the MITM host as a KDC for the target realm on a target client, using the
[`ksetup /addkdc`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ksetup-addkdc)
command, or manually editing the following registry key:

```
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\LSA\Kerberos\Domains
```

In an authorized adversarial simulation, there are many potential options for achieving the necessary MITM positioning, such as DNS misconfiguration, DHCPv6 poisoning, and ARP spoofing.

## Usage
Example usage for passing traffic unmodified:
```
$ kdc-proxy 0.0.0.0:88 192.168.56.102:88
2023-06-02T19:55:24.691304Z  INFO kdc_proxy::proxy: Listening on 0.0.0.0:88
2023-06-02T19:56:05.201483Z  INFO kdc_proxy::proxy: Received connection from 192.168.56.104:53381
2023-06-02T19:56:05.203586Z  INFO kdc_proxy::proxy: Received AS-REQ, forwarding to KDC...
2023-06-02T19:56:05.205339Z  INFO kdc_proxy::proxy: Received KRB_ERROR, forwarding to client...
2023-06-02T19:56:05.239626Z  INFO kdc_proxy::proxy: Client disconnected
2023-06-02T19:56:05.248617Z  INFO kdc_proxy::proxy: Received connection from 192.168.56.104:53382
2023-06-02T19:56:05.249700Z  INFO kdc_proxy::proxy: Received AS-REQ, forwarding to KDC...
2023-06-02T19:56:05.251806Z  INFO kdc_proxy::proxy: Received AS-REP, forwarding to client...
2023-06-02T19:56:05.252480Z  INFO kdc_proxy::proxy: Client disconnected
2023-06-02T19:56:05.253579Z  INFO kdc_proxy::proxy: Received connection from 192.168.56.104:53383
2023-06-02T19:56:05.254493Z  INFO kdc_proxy::proxy: Received TGS-REQ, forwarding to KDC...
2023-06-02T19:56:05.258520Z  INFO kdc_proxy::proxy: Received TGS_REP, forwarding to client...
2023-06-02T19:56:05.259056Z  INFO kdc_proxy::proxy: Client disconnected
...
```

Full list of arguments and options:
```
$ kdc-proxy --help
Usage: kdc-proxy [OPTIONS] <LISTEN_ADDR> <REMOTE_ADDR>

Arguments:
  <LISTEN_ADDR>
          Socket address (IP:PORT) for local listener (ex. 0.0.0.0:88)

  <REMOTE_ADDR>
          Socket address (IP:PORT) of remote KDC

Options:
  -m, --mode <MODE>
          [default: log-only]

          Possible values:
          - log-only
          - roast-passive:  Dump hashes for AS-REQ preauth
          - roast-active:   Attempt downgrade of AS-REQ preauth to RC4 and dump hashes
          - downgrade-pa:   Attempt downgrade of AS-REQ preauth to provided <ETYPE> value
          - forge-error:    Reply to AS-REQ with a KRB-ERROR using provided <ERROR_CODE> value
          - ritm:           Attempt Roast-in-the-Middle attack using provided <SPN> value
          - cve-2022-33647: Attempt CVE-2022-33647 downgrade of TGT session key
          - cve-2023-28244: Attempt CVE-2023-28244 downgrade of AS-REQ preauth

      --etype <ETYPE>
          

      --error-code <ERROR_CODE>
          

      --spn <SPN>
          Service Principal Name (slash-delimited, ex. "krbtgt/WINDOMAIN.LOCAL")

  -o, --output-dir <OUTPUT_DIR>
          Output directory path

  -h, --help
          Print help (see a summary with '-h')
```
