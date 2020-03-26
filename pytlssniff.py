#!/usr/bin/env python3

import argparse
import binascii
import base64
import OpenSSL.crypto
from typing import NamedTuple, Iterator, Optional, List
from enum import Enum
from pyshark import FileCapture, LiveCapture
from pyshark.packet.packet import Packet


class TLSHandshakeType(Enum):
    hello_request = 0
    client_hello = 1
    server_hello = 2
    hello_verify_request = 3
    new_session_ticket = 4
    end_of_early_data = 5
    hello_retry_request = 6
    encrypted_extensions = 8
    certificate = 11
    server_key_exchange = 12
    certificate_request = 13
    server_hello_done = 14
    certificate_verify = 15
    client_key_exchange = 16
    finished = 20
    certificate_url = 21
    certificate_status = 22
    supplemental_data = 23
    key_update = 24
    compressed_certificate = 25
    message_hash = 254


class TLSHandshakeMessage(NamedTuple):
    handshake_type: TLSHandshakeType
    ip_version: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    sni: Optional[str]
    cn: Optional[str]
    san: Optional[List[str]]


class TLSHandshakeSniffer():
    def __init__(self, interface='any', input_file=None, custom_bpf_filter='', custom_display_filter=''):
        self.interface = interface
        self.input_file = input_file
        self.custom_bpf_filter = custom_bpf_filter
        self.custom_display_filter = custom_display_filter

    @classmethod
    def _extract_certificate_san(cls, x509cert: OpenSSL.crypto.X509) -> Optional[List[str]]:
        san = []
        for i in range(0, x509cert.get_extension_count()):
            ext = x509cert.get_extension(i)
            if 'subjectAltName' in ext.get_short_name().decode('utf-8'):
                for san_item in str(ext).lower().split(', '):
                    if san_item.startswith('dns:'):
                        san.append(san_item[4:].strip())

        if len(san) > 0:
            return san
        else:
            return None

    @classmethod
    def _parse_certificate(cls, certificate: str) -> Optional[OpenSSL.crypto.X509]:
        try:
            cert = binascii.unhexlify(certificate.replace(':', ''))
            b64cert = base64.standard_b64encode(cert)
            b64certUtf8 = (
                "-----BEGIN CERTIFICATE-----\n"
                f"{b64cert.decode('utf-8')}\n"
                "-----END CERTIFICATE-----"
            )

            return OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM,
                b64certUtf8
            )
        except Exception:
            return None

    @classmethod
    def _parse_packet(self, packet: Packet, sniff_sni=True, sniff_cn=True, sniff_san=True) -> Optional[TLSHandshakeMessage]:
        san = None
        cn = None
        sni = None

        try:
            handshake_type = TLSHandshakeType(int(packet.ssl.handshake_type))

            if sniff_sni and 'handshake_extensions_server_name' in packet.ssl.field_names and packet.ssl.handshake_extensions_server_name != '':
                sni = packet.ssl.handshake_extensions_server_name.lower()

            if sniff_cn and 'x509ce_dnsname' in packet.ssl.field_names:
                cn = packet.ssl.x509ce_dnsname.lower()

            # Hopefully the SAN section will also be accessible with pyshark in future
            if sniff_san and 'handshake_certificate' in packet.ssl.field_names:
                cert = self._parse_certificate(packet.ssl.handshake_certificate)
                if cert is not None:
                    san = self._extract_certificate_san(cert)

            if 'ip' in packet:
                ip_version = 4
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
            elif 'ipv6' in packet:
                ip_version = 6
                src_ip = packet.ipv6.src
                dst_ip = packet.ipv6.dst
            else:
                return None

            if sni is not None or cn is not None or san is not None:
                return TLSHandshakeMessage(
                    handshake_type=handshake_type,
                    ip_version=ip_version,
                    src_ip=src_ip,
                    src_port=int(packet.tcp.srcport),
                    dst_ip=dst_ip,
                    dst_port=int(packet.tcp.dstport),
                    sni=sni,
                    cn=cn,
                    san=san
                )

            return None
        except Exception:
            return None

    def listen(self, sniff_sni=True, sniff_cn=True, sniff_san=True, packet_count: int = None, debug: bool = False) -> Iterator[TLSHandshakeMessage]:
        # Currently only IPv4 is supported for BPF tcp data access. Manpage says: "this will be fixed in the future" for IPv6.
        # Until then, only the 'tcp' filter is applied
        # bpf_filter = 'tcp[((tcp[12:1] & 0xf0) >> 2):1] = 22'
        bpf_filter = 'tcp'
        display_filter = f'(ssl.record.content_type == 22 && ssl.handshake.type)'

        if self.custom_bpf_filter != '':
            bpf_filter += f' && {self.custom_bpf_filter.strip()}'
        if self.custom_display_filter != '':
            display_filter += f' && {self.custom_display_filter.strip()}'

        if packet_count is not None and packet_count <= 0:
            packet_count = None

        if self.input_file is not None:
            packet_iterator = iter(FileCapture(input_file=self.input_file, display_filter=display_filter, debug=debug))
        else:
            capture = LiveCapture(interface=self.interface, bpf_filter=bpf_filter, display_filter=display_filter, debug=debug)
            packet_iterator = capture.sniff_continuously()

        for packet in packet_iterator:
            handshake_message = self._parse_packet(packet, sniff_sni=sniff_sni, sniff_cn=sniff_cn, sniff_san=sniff_san)

            if handshake_message is not None:
                yield handshake_message

                if packet_count is not None:
                    packet_count -= 1
                    if packet_count <= 0:
                        break

        raise StopIteration


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


def main():
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

        ip_version = 'IPv4' if message.ip_version == 4 else 'IPv6'

        print(
            f"{message.handshake_type.name}({message.handshake_type.value})\t{ip_version}\t"
            f"{message.src_ip}:{message.src_port}\t{message.dst_ip}:{message.dst_port}\t" + f"{dns_name}", flush=True
        )


if __name__ == "__main__":
    main()
