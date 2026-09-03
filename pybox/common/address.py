from dataclasses import dataclass
from enum import Enum
import ipaddress


class AddressType(Enum):
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    DOMAIN = "DOMAIN"


@dataclass
class Destination:
    type: AddressType
    address: str
    port: int

    def authority(self) -> str:
        try:
            ip = ipaddress.ip_address(self.address)
        except ValueError:
            return f"{self.address}:{self.port}"
        if ip.version == 6:
            return f"[{self.address}]:{self.port}"
        else:
            return f"{self.address}:{self.port}"

    @classmethod
    def from_host_port(cls, host: str, port: int) -> "Destination":
        type = AddressType.IPV4
        try:
            ip = ipaddress.ip_address(host)
            if ip.version == 6:
                type = AddressType.IPV6
        except ValueError:
            type = AddressType.DOMAIN
        return Destination(type, host, port)
