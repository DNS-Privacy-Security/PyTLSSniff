import binascii
import base64
import OpenSSL.crypto
import signal
from typing import NamedTuple, Iterator, Optional, List
from enum import Enum
from OpenSSL.crypto import X509, FILETYPE_PEM
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
    def __init__(self, interface='any', input_file=None, bpf_filter='', display_filter=''):
        self.interface = interface
        self.input_file = input_file
        self.bpf_filter = bpf_filter
        self.display_filter = display_filter

    @classmethod
    def _extract_certificate_san(cls, x509cert: X509) -> Optional[List[str]]:
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
    def _parse_certificate(cls, certificate: str) -> Optional[X509]:
        try:
            cert = binascii.unhexlify(certificate.replace(':', ''))
            b64cert = base64.standard_b64encode(cert)
            b64certUtf8 = (
                "-----BEGIN CERTIFICATE-----\n"
                f"{b64cert.decode('utf-8')}\n"
                "-----END CERTIFICATE-----"
            )

            return OpenSSL.crypto.load_certificate(
                FILETYPE_PEM,
                b64certUtf8
            )
        except Exception:
            return None

    @classmethod
    def _get_handshake_message(cls, packet: Packet, sniff_sni=True, sniff_cn=True, sniff_san=True) -> Optional[TLSHandshakeMessage]:
        san, cn, sni = None, None, None

        try:
            handshake_type = TLSHandshakeType(int(packet.ssl.handshake_type))

            if sniff_sni and 'handshake_extensions_server_name' in packet.ssl.field_names and packet.ssl.handshake_extensions_server_name != '':
                sni = packet.ssl.handshake_extensions_server_name.lower()

            if sniff_cn and 'x509ce_dnsname' in packet.ssl.field_names:
                cn = packet.ssl.x509ce_dnsname.lower()

            # Hopefully the SAN section will also be accessible with pyshark in future
            if sniff_san and 'handshake_certificate' in packet.ssl.field_names:
                cert = cls._parse_certificate(packet.ssl.handshake_certificate)
                if cert is not None:
                    san = cls._extract_certificate_san(cert)

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

    def listen(self, sniff_sni=False, sniff_cn=False, sniff_san=False, packet_count: int = None, debug: bool = False) -> Iterator[TLSHandshakeMessage]:
        # Workaround for pyshark, because SIGINT handling does not work properly
        original_sigint_handler = signal.getsignal(signal.SIGINT)
        if original_sigint_handler == signal.default_int_handler:
            signal.signal(signal.SIGINT, lambda *args: None)

        # Currently only IPv4 is supported for BPF tcp data access. Manpage says: "this will be fixed in the future" for IPv6.
        # Until then, only the 'tcp' filter is applied
        # bpf_filter = 'tcp[((tcp[12:1] & 0xf0) >> 2):1] = 22'
        bpf_filter = 'tcp'
        display_filter = f'(ssl.record.content_type == 22 && ssl.handshake.type)'

        if self.bpf_filter != '':
            bpf_filter += f' && {self.bpf_filter.strip()}'
        if self.display_filter != '':
            display_filter += f' && {self.display_filter.strip()}'

        if packet_count is not None and packet_count <= 0:
            packet_count = None

        if self.input_file is not None:
            packet_iterator = iter(FileCapture(input_file=self.input_file, display_filter=display_filter, debug=debug))
        else:
            capture = LiveCapture(interface=self.interface, bpf_filter=bpf_filter, display_filter=display_filter, debug=debug)
            packet_iterator = capture.sniff_continuously()

        if not (sniff_sni or sniff_cn or sniff_san):
            sniff_sni = True
            sniff_cn = True
            sniff_san = True
        
        for packet in packet_iterator:
            handshake_message = self._get_handshake_message(packet, sniff_sni=sniff_sni, sniff_cn=sniff_cn, sniff_san=sniff_san)

            if handshake_message is not None:
                yield handshake_message

                if packet_count is not None:
                    packet_count -= 1
                    if packet_count <= 0:
                        break

        signal.signal(signal.SIGINT, original_sigint_handler)

        raise StopIteration
