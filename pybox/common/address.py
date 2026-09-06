from dataclasses import dataclass
from enum import Enum
import ipaddress
from urllib.parse import urlsplit


class AddressType(Enum):
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    DOMAIN = "DOMAIN"


@dataclass
class IPV4_Address:
    address: ipaddress.IPv4Address
    port: int

    @property
    def type(self):
        return AddressType.IPV4

    def authority(self) -> str:
        return f"{self.address}:{self.port}"


@dataclass
class IPV6_Address:
    address: ipaddress.IPv6Address
    port: int

    @property
    def type(self):
        return AddressType.IPV6

    def authority(self) -> str:
        return f"[{self.address}]:{self.port}"


@dataclass
class DOMAIN_Address:
    address: str
    port: int

    @property
    def type(self):
        return AddressType.DOMAIN

    def authority(self) -> str:
        return f"{self.address}:{self.port}"


Address = IPV4_Address | IPV6_Address | DOMAIN_Address


def host_port_to_addr(host: str, port: int) -> Address:
    try:
        ip = ipaddress.ip_address(host)
        if isinstance(ip, ipaddress.IPv4Address):
            return IPV4_Address(ip, port)
        else:
            return IPV6_Address(ip, port)
    except ValueError:
        return DOMAIN_Address(host, port)


def authority_to_addr(authority: str) -> Address:
    parsed = urlsplit(f"//{authority}")
    if parsed.hostname is None or parsed.port is None:
        raise RuntimeError("invalid authority")
    return host_port_to_addr(parsed.hostname, parsed.port)
