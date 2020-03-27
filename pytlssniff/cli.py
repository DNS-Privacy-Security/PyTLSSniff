import argparse
from .sniffer import TLSHandshakeSniffer


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("-d", '--debug', dest='debug', action='store_true',
                        help="enable debug mode")
    parser.add_argument("-s", '--sni', dest='sni', action='store_true',
                        help="sniff SNI values from TLS handshakes")
    parser.add_argument("-a", '--san', dest='san', action='store_true',
                        help="sniff domains from certificate SAN section")
    parser.add_argument("-c", '--cn', dest='cn', action='store_true',
                        help="sniff Common Name from certificate CN section")
    parser.add_argument("-i", '--interface', dest='interface', default="any",
                        help="name or idx of interface (default: any)", required=False)
    parser.add_argument("-r", '--input-file', dest='input_file', default=None,
                        help="set the filename to read from (- to read from stdin)", required=False)
    parser.add_argument("-p", '--packet-count', dest='packet_count', type=int, default=None,
                        help="stop after n packets (def: infinite)", required=False)
    parser.add_argument("-b", "--bpf-filter", dest="bpf_filter", default="",
                        help="packet filter in Berkeley Packet Filter (BPF) syntax (for live trace only)", required=False)
    parser.add_argument("-Y", "--display-filter", dest="display_filter", default="",
                        help="packet displaY filter in Wireshark display filter", required=False)

    return parser.parse_args()


def cli():
    args = parse_args()
    handshake_sniffer = TLSHandshakeSniffer(args.interface, args.input_file, args.bpf_filter, args.display_filter)

    if not (args.sni or args.cn or args.san):
        args.sni = True
        args.cn = True
        args.san = True

    for message in handshake_sniffer.listen(args.sni, args.cn, args.san, args.packet_count, args.debug):
        dns_name = ''

        if message.sni is not None:
            dns_name = message.sni
        if message.cn is not None:
            if dns_name != '' and dns_name != message.cn:
                dns_name += f",{message.cn}"
            else:
                dns_name = message.cn
        if message.san is not None:
            if message.sni in message.san:
                message.san.remove(message.sni)
            if message.cn in message.san:
                message.san.remove(message.cn)

            if len(message.san) > 0:
                if dns_name != '':
                    dns_name += ','
                dns_name += ','.join(message.san)

        if message.ip_version == 4:
            ip_version = 'IPv4'
            src_ip = message.src_ip
            dst_ip = message.dst_ip
        else:
            ip_version = 'IPv6'
            src_ip = f'[{message.src_ip}]'
            dst_ip = f'[{message.dst_ip}]'

        print(
            f"{message.handshake_type.name}({message.handshake_type.value})\t{ip_version}\t"
            f"{src_ip}:{message.src_port}\t{dst_ip}:{message.dst_port}\t{dns_name}", flush=True
        )


if __name__ == "__main__":
    cli()
