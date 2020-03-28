# PyTLSSniff

PyTLSSniff - Python TLS handshake sniffer to extract domain names

<!-- GETTING STARTED -->
## Getting Started

### Prerequisites for installation

This project uses the Python wrapper for tshark ([pyshark](https://github.com/KimiNewt/pyshark)). It is therefore necessary to install tshark before using PyTLSSniff.

#### Debian / Ubuntu / Mint

```sh
sudo apt install tshark
```

### Install PyTLSSniff

```sh
pip3 install PyTLSSniff
```

PyTLSSniff on PyPi: [PyTLSSniff](https://pypi.org/project/PyTLSSniff)
<!-- USAGE EXAMPLES -->
## Usage

### Command line parameters

```
pytlssniff [-h] [-d] [-s] [-a] [-c] [-i INTERFACE] [-r INPUT_FILE]
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

### Live trace example

```sh
$ pytlssniff -s -i eth0 -p 5 -Y "ip.addr == 10.8.3.35"
client_hello(1) IPv4    10.8.3.35:56670 91.198.174.192:443      www.wikipedia.org
client_hello(1) IPv4    10.8.3.35:52000 91.198.174.208:443      upload.wikimedia.org
client_hello(1) IPv4    10.8.3.35:56674 91.198.174.192:443      de.wikipedia.org
client_hello(1) IPv4    10.8.3.35:52984 140.82.118.3:443        github.com
client_hello(1) IPv4    10.8.3.35:51770 151.101.12.133:443      avatars0.githubusercontent.com
```
