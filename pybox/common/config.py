from dataclasses import dataclass, field
import json


@dataclass
class TransportConfig:
    type: str
    path: str | None
    headers: dict[str, str] | None


@dataclass
class TlsConfig:
    enabled: bool
    server_name: str | None
    insecure: bool
    certificate_path: str | None
    key_path: str | None


@dataclass
class InboundConfig:
    type: str
    listen: str | None
    listen_port: int | None
    uuid: list[str] | None
    transport: TransportConfig | None
    tls: TlsConfig | None
    tun_ipv4: str | None
    tun_next_ipv4: str | None
    tun_ipv6: str | None
    tun_next_ipv6: str | None
    auto_route: bool | None


@dataclass
class OutboundConfig:
    type: str
    tag: str
    server: str | None
    server_port: int | None
    uuid: str | None
    transport: TransportConfig | None
    tls: TlsConfig | None


@dataclass
class SystemProxyConfig:
    enabled: bool
    server: str


def normalize_list(data: str | list[str] | None) -> list[str]:
    if data is None:
        return []
    if isinstance(data, str):
        return [data]
    return data


@dataclass
class RuleConfig:
    domain_suffix: list[str]
    domain: list[str]
    domain_keyword: list[str]
    domain_regex: list[str]
    ip_cidr: list[str]


@dataclass
class RouteRuleConfig:
    rule: RuleConfig | None
    rule_set: list[str]
    outbound: str


@dataclass
class RuleSetConfig:
    tag: str
    type: str
    format: str
    path: str


@dataclass
class RouteConfig:
    rules: list[RouteRuleConfig]
    rule_sets: list[RuleSetConfig]
    final: str = ""


@dataclass
class DnsRuleConfig:
    rule: RuleConfig | None
    rule_set: list[str]
    server: str


@dataclass
class DnsServerConfig:
    type: str
    tag: str
    server: str | None
    server_port: int | None
    tls: TlsConfig | None
    path: str | None
    headers: dict[str, str] | None
    host: str | None


@dataclass
class DnsConfig:
    enabled: bool
    listen: str | None
    listen_port: int | None
    servers: list[DnsServerConfig]
    rules: list[DnsRuleConfig]
    default_nameserver: str | None
    final: str | None


@dataclass
class Config:
    inbounds: list[InboundConfig]
    outbounds: list[OutboundConfig]
    route: RouteConfig
    dns: DnsConfig | None
    system_proxy: SystemProxyConfig | None


def load_config(path: str) -> Config:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return parse_config(data)


def parse_system_proxy(data: dict) -> SystemProxyConfig:
    return SystemProxyConfig(data["enabled"], data["server"])


def parse_config(data: dict) -> Config:
    system_proxy_data = data.get("system_proxy", None)
    system_proxy: SystemProxyConfig | None = None
    if system_proxy_data:
        system_proxy = parse_system_proxy(system_proxy_data)
    dns_data = data.get("dns", None)
    dns: DnsConfig | None = None
    if dns_data:
        dns = parse_dns(dns_data)
    return Config(
        [parse_inbound(item) for item in data["inbounds"]],
        [parse_outbound(item) for item in data["outbounds"]],
        parse_route(data["route"]),
        dns,
        system_proxy,
    )


def parse_inbound(data: dict) -> InboundConfig:
    transport_data = data.get("transport")
    transport: TransportConfig | None = None
    if transport_data is not None:
        transport = parse_transport(transport_data)
    tls_data = data.get("tls")
    tls: TlsConfig | None = None
    if tls_data is not None:
        tls = parse_tls(tls_data)
    return InboundConfig(
        data["type"],
        data.get("listen"),
        data.get("listen_port"),
        data.get("uuid"),
        transport,
        tls,
        data.get("tun_ipv4"),
        data.get("tun_next_ipv4"),
        data.get("tun_ipv6"),
        data.get("tun_next_ipv6"),
        data.get("auto_route"),
    )


def parse_transport(data: dict) -> TransportConfig:
    return TransportConfig(data["type"], data.get("path"), data.get("headers"))


def parse_tls(data: dict) -> TlsConfig:
    return TlsConfig(
        data.get("enabled", False),
        data.get("server_name"),
        data.get("insecure", False),
        data.get("certificate_path"),
        data.get("key_path"),
    )


def parse_outbound(data: dict) -> OutboundConfig:
    transport_data = data.get("transport")
    transport: TransportConfig | None = None
    if transport_data is not None:
        transport = parse_transport(transport_data)
    tls_data = data.get("tls")
    tls: TlsConfig | None = None
    if tls_data is not None:
        tls = parse_tls(tls_data)
    return OutboundConfig(
        data["type"],
        data["tag"],
        data.get("server"),
        data.get("server_port"),
        data.get("uuid"),
        transport,
        tls,
    )


def parse_rule(data: dict) -> RuleConfig:
    return RuleConfig(
        normalize_list(data.get("domain_suffix")),
        normalize_list(data.get("domain")),
        normalize_list(data.get("domain_keyword")),
        normalize_list(data.get("domain_regex")),
        normalize_list(data.get("ip_cidr")),
    )


def parse_route_rule(data: dict) -> RouteRuleConfig:
    return RouteRuleConfig(
        parse_rule(data),
        normalize_list(data.get("rule_set")),
        data["outbound"],
    )


def parse_rule_set(data: dict) -> RuleSetConfig:
    return RuleSetConfig(data["tag"], data["type"], data["format"], data["path"])


def parse_route(data: dict) -> RouteConfig:
    return RouteConfig(
        [parse_route_rule(item) for item in data.get("rules", [])],
        [parse_rule_set(item) for item in data.get("rule_set", [])],
        data["final"],
    )


def parse_dns_server(data: dict) -> DnsServerConfig:
    tls_data = data.get("tls")
    tls: TlsConfig | None = None
    if tls_data is not None:
        tls = parse_tls(tls_data)
    return DnsServerConfig(
        data["type"],
        data["tag"],
        data.get("server"),
        data.get("server_port"),
        tls,
        data.get("path"),
        data.get("headers"),
        data.get("host"),
    )


def parse_dns_rule(data: dict) -> DnsRuleConfig:
    return DnsRuleConfig(
        parse_rule(data),
        normalize_list(data.get("rule_set")),
        data["server"],
    )


def parse_dns(data: dict) -> DnsConfig:
    return DnsConfig(
        data.get("enabled", False),
        data.get("listen"),
        data.get("listen_port"),
        [parse_dns_server(item) for item in data.get("servers", [])],
        [parse_dns_rule(item) for item in data.get("rules", [])],
        data.get("default-nameserver"),
        data.get("final"),
    )
