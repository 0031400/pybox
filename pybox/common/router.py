from dataclasses import dataclass
import ipaddress
import re

from .address import Address, DOMAIN_Address


@dataclass
class Rule:
    domain: list[str]
    domain_suffix: list[str]
    domain_keyword: list[str]
    domain_regex: list[re.Pattern[str]]
    ip_cidr: list[str]

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

    def match(self, destination: Address) -> bool:
        if isinstance(destination, DOMAIN_Address):
            return self.match_domain(destination.address)
        else:
            return self.match_ip(destination.address)


@dataclass
class RouteRule:
    rule: Rule | None
    rule_sets: list[str]
    outbound: str


@dataclass
class Router:
    def __init__(
        self, rules: list[RouteRule], rule_sets: dict[str, list[Rule]], final: str
    ) -> None:
        self.rules = rules
        self.rule_sets = rule_sets
        self.final = final

    def route(self, destination: Address) -> str:
        for rule in self.rules:
            if self.match(rule, destination):
                return rule.outbound
        return self.final

    def match(self, route_rule: RouteRule, destination: Address) -> bool:
        if route_rule.rule is not None:
            if route_rule.rule.match(destination):
                return True
        for rule_set_tag in route_rule.rule_sets:
            rules = self.rule_sets[rule_set_tag]
            for rule in rules:
                if rule.match(destination):
                    return True
        return False
