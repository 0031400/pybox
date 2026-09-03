from dataclasses import dataclass

from .address import AddressType, Destination

@dataclass
class RouteRule:
    domain_suffix: list[str]
    ip_cidr: list[str]
    outbound: str

    def match(self, destination: Destination) -> bool:
        if destination.type == AddressType.DOMAIN:
            for suffix in self.domain_suffix:
                if destination.address.endswith(suffix):
                    return True
        return False


@dataclass
class Router:
    def __init__(self, rules: list[RouteRule], final: str) -> None:
        self.rules = rules
        self.final = final

    def route(self, destination: Destination) -> str:
        for rule in self.rules:
            if rule.match(destination):
                return rule.outbound
        return self.final
