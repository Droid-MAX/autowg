from abc import ABC, abstractmethod
from hashlib import blake2b
from ipaddress import IPv6Address, IPv6Network
import re
import time
from typing import Any, Dict, Optional

from wgnlpy import PublicKey, WireGuard

class NameConverter(ABC):
    @abstractmethod
    def convert(self, prefix: IPv6Network, name: str) -> IPv6Address:
        pass

class DirectBCDConverter(NameConverter):
    def convert(self, prefix: IPv6Network, name: str) -> IPv6Address:
        value = int(name)
        if not (0 <= value <= 9999):
            raise ValueError('value %d out of range' % value)

        address = bytearray(16)
        address[:] = prefix.network_address.packed

        num = int(name, 16)
        address[14] = num >> 8
        address[15] = num & 0xff

        return IPv6Address(bytes(address))

class MetansConverter(NameConverter):
    label_pattern = re.compile(r'([a-z0-9][a-z0-9-]*[a-z0-9]|[a-z0-9])')

    def __init__(self, template: Optional[str] = None):
        self.template = template or '%s'

    def convert(self, prefix: IPv6Network, name: str) -> IPv6Address:
        name = name.lower()
        labels = (self.template % name).split('.')

        h = blake2b(digest_size=16)

        for label in labels:
            if len(label) > 63 or not self.label_pattern.fullmatch(label):
                raise ValueError('invalid label "%s"' % label)

        h.update(b'\x00'.join([x.encode('ascii') for x in reversed(labels)]))

        digest = h.digest()

        net = prefix.network_address.packed
        netmask = prefix.netmask.packed

        address = bytearray(16)
        for i in range(0, 16):
            address[i] = (net[i] & netmask[i]) | (digest[i] & ~netmask[i])

        return IPv6Address(bytes(address))

class Tunnel:
    def __init__(self, interface: str, prefix: str, converter: NameConverter):
        self.interface = interface
        self.prefix = IPv6Network(prefix)
        self.converter = converter

        self.peers = {}
        self.key_to_name = {}

        self.wg = WireGuard()

        ifinfo = self.wg.get_interface(self.interface)
        self.listen_port = ifinfo.listen_port
        self.pubkey = ifinfo.public_key

        if self.pubkey is None:
            raise ValueError("interface %s is not fully initialized: no key is set" % interface)

    def flush(self):
        ifinfo = self.wg.get_interface(self.interface)

        to_remove = []
        for peer in ifinfo.peers.values():
            for net in peer.allowedips:
                if net.subnet_of(self.prefix):
                    to_remove.append(peer.public_key)

        self.wg.remove_peers(self.interface, *to_remove)

    def get_config(self) -> Dict[str, Any]:
        return {
            'port': self.listen_port,
            'pubkey': str(self.pubkey)
        }

    def set_peer(self, name: str, pubkey: str) -> str:
        addr = self.converter.convert(self.prefix, name)
        pk = PublicKey(pubkey)

        if name in self.peers:
            old_key = self.peers[name]['pk']

            if old_key == pk:
                return str(addr)

            self.wg.remove_peers(self.interface, old_key)
            del self.key_to_name[old_key]

        self.wg.set_peer(self.interface, pk,
                         replace_allowedips=True, allowedips=[addr])

        self.peers[name] = {
            'pk': pk,
            'created': int(time.time())
        }

        self.key_to_name[pk] = name

        return str(addr)

    @staticmethod
    def _peerstats(peer) -> Dict[str, Any]:
        last_handshake = 0
        if peer.last_handshake_time:
            last_handshake = int(peer.last_handshake_time)

        ip = ""
        if peer.allowedips and type(peer.allowedips[0]) == IPv6Network:
            net = peer.allowedips[0]
            ip = str(net.network_address)

        return {
            "pubkey": str(peer.public_key),
            "last_handshake": last_handshake,
            "ip": ip,
            "rx_bytes": peer.rx_bytes,
            "tx_bytes": peer.tx_bytes
        }

    def peerstats(self, name: str) -> Optional[Dict[str, Any]]:
        if name not in self.peers:
            return None

        peer_info = self.peers[name]

        ifinfo = self.wg.get_interface(self.interface)
        for peer in ifinfo.peers.values():
            if peer.public_key == peer_info['pk']:
                stats = self._peerstats(peer)
                stats['created'] = peer_info['created']

                return stats

    def peerstats_all(self) -> Dict[str, Dict[str, Any]]:
        result = {}

        ifinfo = self.wg.get_interface(self.interface)
        for peer in ifinfo.peers.values():
            if peer.public_key in self.key_to_name:
                name = self.key_to_name[peer.public_key]

                stats = self._peerstats(peer)
                stats['created'] = self.peers[name]['created']

                result[name] = stats

        return result
