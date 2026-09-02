from dataclasses import dataclass

from ..connections.connection import Connection
from .address import Destination

@dataclass(slots=True)
class Session:
    connection:Connection
    destination:Destination