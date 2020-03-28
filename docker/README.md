# PyTLSSniff

PyTLSSniff - Python TLS handshake sniffer to extract domain names

## Getting Started

### Run the container from the last release

```sh
docker run --network=host -it dnsprivacysecurity/pytlssniff
```

## Usage

### Command line parameters

```
$ docker run -it dnsprivacysecurity/pytlssniff --help
usage: pytlssniff [-h] [-d] [-s] [-a] [-c] [-i INTERFACE] [-r INPUT_FILE]
                  [-p PACKET_COUNT] [-b BPF_FILTER] [-Y DISPLAY_FILTER]

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           enable debug mode
  -s, --sni             sniff SNI values from TLS handshakes
  -a, --san             sniff domains from certificate SAN section
  -c, --cn              sniff Common Name from certificate CN section
  -i INTERFACE, --interface INTERFACE
                        name or idx of interface (default: any)
  -r INPUT_FILE, --input-file INPUT_FILE
                        set the filename to read from (- to read from stdin)
  -p PACKET_COUNT, --packet-count PACKET_COUNT
                        stop after n packets (def: infinite)
  -b BPF_FILTER, --bpf-filter BPF_FILTER
                        packet filter in Berkeley Packet Filter (BPF) syntax
                        (for live trace only)
  -Y DISPLAY_FILTER, --display-filter DISPLAY_FILTER
                        packet displaY filter in Wireshark display filter
```

### Live trace example with Berkeley Packet Filter (BPF)

```sh
docker run --network=host -it dnsprivacysecurity/pytlssniff -s -p 5 -b "ip host 10.8.3.35"
client_hello(1) IPv4    10.8.3.35:60588 88.99.24.79:443         biot.com
client_hello(1) IPv4    10.8.3.35:53412 91.198.174.194:443      wikipedia.com
client_hello(1) IPv4    10.8.3.35:58990 91.198.174.192:443      www.wikipedia.org
client_hello(1) IPv4    10.8.3.35:55302 140.82.118.3:443        github.com
client_hello(1) IPv4    10.8.3.35:48082 185.199.110.154:443     github.githubassets.com
```
