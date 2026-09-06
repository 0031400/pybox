from dataclasses import dataclass

from ..common.address import DOMAIN_Address
from ..common.router import Rule


@dataclass
class DnsRouteRule:
    rule: Rule | None
    rule_sets: list[str]
    server: str


@dataclass
class DnsRouter:
    def __init__(
        self, rules: list[DnsRouteRule], rule_sets: dict[str, list[Rule]], final: str
    ) -> None:
        self.rules = rules
        self.rule_sets = rule_sets
        self.final = final

    def route(self, domain: str) -> str:
        for rule in self.rules:
            if self.match(rule, domain):
                return rule.server
        return self.final

    def match(self, route_rule: DnsRouteRule, domain: str) -> bool:
        if route_rule.rule is not None:
            if route_rule.rule.match(DOMAIN_Address(domain,0)):
                return True
        for rule_set_tag in route_rule.rule_sets:
            rules = self.rule_sets[rule_set_tag]
            for rule in rules:
                if rule.match(DOMAIN_Address(domain,0)):
                    return True
        return False
