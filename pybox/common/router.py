from dataclasses import dataclass
import ipaddress
import re

from .address import AddressType, Destination


@dataclass
class RouteRule:
    domain: list[str]
    domain_suffix: list[str]
    domain_keyword: list[str]
    domain_regex: list[re.Pattern[str]]
    ip_cidr: list[str]
    outbound: str

    def match_domain(self, domain: str) -> bool:
        domain = domain.lower().rstrip(".")
        for suffix in self.domain_suffix:
            suffix = suffix.lower().rstrip(".")
            if suffix.startswith("."):
                if domain.endswith(suffix):
                    return True
            else:
                if domain == suffix or domain.endswith("." + suffix):
                    return True
        for value in self.domain:
            value = value.lower().rstrip(".")
            if value == domain:
                return True
        for keyword in self.domain_keyword:
            if keyword.lower() in domain:
                return True
        for pattern in self.domain_regex:
            if pattern.search(domain):
                return True
        return False

    def match_ip(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        for cidr in self.ip_cidr:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if ip in network:
                return True
        return False

    def match(self, destination: Destination) -> bool:
        if destination.type == AddressType.DOMAIN:
            return self.match_domain(destination.address)
        else:
            try:
                ip = ipaddress.ip_address(destination.address)
            except ValueError:
                return False
            return self.match_ip(ip)


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
