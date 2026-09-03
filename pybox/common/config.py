from dataclasses import dataclass, field
import json


@dataclass
class InboundConfig:
    type: str
    listen: str | None
    listen_port: int | None


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


@dataclass
class OutboundConfig:
    type: str
    tag: str
    server: str | None
    server_port: int | None
    uuid: str | None
    transport: TransportConfig | None
    tls: TlsConfig | None


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
class Config:
    inbounds: list[InboundConfig]
    outbounds: list[OutboundConfig]
    route: RouteConfig


def load_config(path: str) -> Config:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return parse_config(data)


def parse_config(data: dict) -> Config:
    return Config(
        [parse_inbound(item) for item in data["inbounds"]],
        [parse_outbound(item) for item in data["outbounds"]],
        parse_route(data["route"]),
    )


def parse_inbound(data: dict) -> InboundConfig:
    return InboundConfig(data["type"], data.get("listen"), data.get("listen_port"))


def parse_transport(data: dict) -> TransportConfig:
    return TransportConfig(data["type"], data.get("path"), data.get("headers"))


def parse_tls(data: dict) -> TlsConfig:
    return TlsConfig(
        data.get("enabled", False), data.get("server_name"), data.get("insecure", False)
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
