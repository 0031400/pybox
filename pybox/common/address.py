from dataclasses import dataclass
from enum import Enum


class AddressType(Enum):
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    DOMAIN = "DOMAIN"


@dataclass
class Destination:
    type: AddressType
    address: str
    port: int
