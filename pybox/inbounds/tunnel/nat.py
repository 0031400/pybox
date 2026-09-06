from dataclasses import dataclass
import ipaddress


@dataclass(frozen=True)
class FlowKey:
    src_ip: ipaddress.IPv4Address
    dst_ip: ipaddress.IPv4Address
    src_port: int
    dst_port: int


class Nat:
    def __init__(self) -> None:
        self._forward: dict[FlowKey, int] = {}
        self._reverse: dict[int, FlowKey] = {}
        self._port = 10000

    def lookup_or_create(self, key: FlowKey):
        nat_port = self._forward.get(key)
        if not nat_port:
            nat_port = self.gen_port()
            self._forward[key] = nat_port
            self._reverse[nat_port] = key
        return nat_port

    def lookup_back(self, nat_port: int) -> FlowKey | None:
        return self._reverse.get(nat_port)

    def gen_port(self):
        self._port += 1
        if self._port == 60000:
            self._port = 10000
        return self._port
