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


@dataclass
class RouteRuleConfig:
    domain_suffix: list[str] = field(default_factory=list)
    domain: list[str] = field(default_factory=list)
    domain_keyword: list[str] = field(default_factory=list)
    domain_regex: list[str] = field(default_factory=list)
    ip_cidr: list[str] = field(default_factory=list)
    outbound: str = ""


@dataclass
class RouteConfig:
    rules: list[RouteRuleConfig] = field(default_factory=list)
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


def parse_route_rule(data: dict) -> RouteRuleConfig:
    return RouteRuleConfig(
        data.get("domain_suffix", []), data.get("ip_cidr", []), data["outbound"]
    )


def parse_route(data: dict) -> RouteConfig:
    return RouteConfig(
        [parse_route_rule(item) for item in data.get("rules", [])], data["final"]
    )
