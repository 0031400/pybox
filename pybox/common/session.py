from dataclasses import dataclass

from ..connections.connection import Connection
from .address import Address


@dataclass(slots=True)
class Session:
    connection: Connection
    destination: Address
    initial_data: bytes
