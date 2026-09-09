import ipaddress
import json
import re

from pybox.common.log import log
from ..dns.dns import DnsCenter
from ..dns.router import DnsRouteRule, DnsRouter
from ..dns.servers.server import DnsServer
from ..dns.servers.tls import TlsDnsServer
from ..dns.servers.udp import UdpDnsServer
from ..inbounds.inbound import Inbound
from ..inbounds.listeners.listener import Listener
from ..inbounds.listeners.tls_listener import TlsListener
from ..inbounds.listeners.ws_listener import WsListener
from ..inbounds.listeners.wss_listener import WssListener
from ..inbounds.mixed import MixedInbound
from ..inbounds.tun import TunInbound
from ..inbounds.vless import VLessInbound
from ..outbounds.block import BlockOutbound
from ..outbounds.transports.tcp import TcpTransport
from ..outbounds.transports.tls import TlsTransport
from ..system_proxy.system_proxy import SystemProxy
from .config import (
    DnsConfig,
    DnsRuleConfig,
    DnsServerConfig,
    InboundConfig,
    RouteConfig,
    OutboundConfig,
    RuleConfig,
    RouteRuleConfig,
    RuleSetConfig,
    load_config,
    parse_rule,
)

from .address import Address, host_port_to_addr
from .core import Core
from ..inbounds.listeners.tcp_listener import TcpListener
from ..outbounds.direct import DirectOutbound
from ..outbounds.outbound import Outbound
from ..outbounds.transports.ws import WsTransport
from ..outbounds.transports.wss import WssTransport
from ..outbounds.vless import VlessOutbound
from .network import set_default_local_addr
from .router import RouteRule, Router, Rule


class App:
    def __init__(self, config_path: str) -> None:
        self.config = load_config(config_path)
        self.system_proxy: SystemProxy | None = None

    async def run(self):
        # rule sets
        rule_sets = {
            item.tag: load_rule_set(item) for item in self.config.route.rule_sets
        }
        # dns
        dns_router: DnsRouter | None = None
        center: DnsCenter | None = None
        if (
            self.config.dns
            and self.config.dns.enabled
            and self.config.dns.listen
            and self.config.dns.listen_port
        ):
            center = DnsCenter(
                self.config.dns.listen,
                self.config.dns.listen_port,
                {item.tag: create_dns_server(item) for item in self.config.dns.servers},
            )
            dns_router = create_dns_router(self.config.dns, rule_sets)

        # inbounds
        inbounds = [create_inbound(item) for item in self.config.inbounds]
        # tun
        tun_count = 0
        for inbound in inbounds:
            if isinstance(inbound, TunInbound):
                tun_count += 1
        if tun_count > 1:
            raise RuntimeError("only support one tun inbound")
        elif tun_count == 1:
            set_default_local_addr()

        # core
        core = Core(
            inbounds,
            {item.tag: create_outbound(item) for item in self.config.outbounds},
            create_router(self.config.route, rule_sets),
            center,
            dns_router,
        )
        await core.start()
        if self.config.system_proxy and self.config.system_proxy.enabled:
            self.system_proxy = SystemProxy(self.config.system_proxy.server)
            self.system_proxy.enable()
            log("system proxy", f"set: {self.system_proxy.server}")
        try:
            await core.run()
        finally:
            if self.system_proxy:
                self.system_proxy.disable()
                log("system proxy", f"unset")


def create_listener(config: InboundConfig) -> Listener:
    if config.listen_port is None or config.listen is None:
        raise RuntimeError("vless inbound error")
    if not config.transport or config.transport.type == "tcp":
        if not config.tls or not config.tls.enabled:
            return TcpListener(config.listen, config.listen_port)
        else:
            if not config.tls.certificate_path or not config.tls.key_path:
                raise RuntimeError("vless tls inbound error")
            return TlsListener(
                config.listen,
                config.listen_port,
                config.tls.certificate_path,
                config.tls.key_path,
            )
    elif config.transport.type == "ws":
        if not config.tls or not config.tls.enabled:
            return WsListener(
                config.listen, config.listen_port, config.transport.path or "/"
            )
        else:
            if not config.tls.certificate_path or not config.tls.key_path:
                raise RuntimeError("vless tls inbound error")
            return WssListener(
                config.listen,
                config.listen_port,
                config.transport.path or "/",
                config.tls.certificate_path,
                config.tls.key_path,
            )
    raise RuntimeError("listener unsupport")


def create_dns_server(config: DnsServerConfig) -> DnsServer:
    bootstrap_address_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    if config.bootstrap_address:
        bootstrap_address_ip = ipaddress.ip_address(config.bootstrap_address)
    if config.type == "udp":
        if not config.server or not config.server_port:
            raise RuntimeError("udp dns server error")
        return UdpDnsServer(
            config.server,
            config.server_port,
            bootstrap_address_ip,
        )
    elif config.type == "tls":
        if (
            not config.server
            or not config.server_port
            or not config.tls
            or not config.tls.enabled
        ):
            raise RuntimeError("tls dns server error")
        return TlsDnsServer(
            config.server,
            config.server_port,
            config.tls.server_name or config.server,
            config.tls.insecure,
            bootstrap_address_ip,
        )
    raise RuntimeError("unsupport dns server type")


def create_inbound(config: InboundConfig) -> Inbound:
    if config.type == "mixed":
        return MixedInbound(create_listener(config))
    elif config.type == "vless":
        if not config.uuid:
            raise RuntimeError("vless uuid error")
        return VLessInbound(create_listener(config), config.uuid)
    elif config.type == "tun":
        if not config.tun_ipv4 or not config.tun_next_ipv4:
            raise RuntimeError("tun need tun_ipv4 error")
        return TunInbound(
            ipaddress.IPv4Address(config.tun_ipv4),
            ipaddress.IPv4Address(config.tun_next_ipv4),
            ipaddress.IPv6Address(config.tun_ipv6),
            ipaddress.IPv6Address(config.tun_next_ipv6),
        )
    raise RuntimeError("unsupport inbound type")


def create_outbound(config: OutboundConfig) -> Outbound:
    if config.type == "block":
        return BlockOutbound()
    if config.type == "direct":
        return DirectOutbound()
    elif config.type == "vless":
        if config.server is None or config.server_port is None or config.uuid is None:
            raise RuntimeError("vless outbound error")
        if config.transport is None or config.transport.type == "tcp":
            if config.tls is None or config.tls.enabled == False:
                transport = TcpTransport()
            else:
                transport = TlsTransport(
                    config.tls.server_name or config.server,
                    config.tls.insecure,
                )
        elif config.transport.type == "ws":
            if config.tls is None or config.tls.enabled == False:
                transport = WsTransport(
                    config.transport.path or "/", config.transport.headers or {}
                )
            else:
                transport = WssTransport(
                    config.transport.path or "/",
                    config.transport.headers or {},
                    config.tls.server_name or config.server,
                    config.tls.insecure,
                )

        else:
            raise RuntimeError("unsupport transport type")
        return VlessOutbound(
            host_port_to_addr(config.server, config.server_port),
            config.uuid,
            transport,
        )
    else:
        raise RuntimeError("unsupport outbound type")


def load_rule_set(config: RuleSetConfig) -> list[Rule]:
    if config.type != "local" or config.format != "source":
        raise RuntimeError("unsupport rule set type")
    with open(config.path, "r", encoding="utf-8") as f:
        data = json.load(f)
    rules: list[Rule] = []
    for rule in data["rules"]:
        rules.append(create_rule(parse_rule(rule)))
    return rules


def create_rule(config: RuleConfig) -> Rule:
    return Rule(
        config.domain,
        config.domain_suffix,
        config.domain_keyword,
        [re.compile(item) for item in config.domain_regex],
        config.ip_cidr,
    )


def create_route_rule(config: RouteRuleConfig) -> RouteRule:
    rule: Rule | None = None
    if config.rule:
        rule = create_rule(config.rule)
    return RouteRule(
        rule,
        config.rule_set,
        config.outbound,
    )


def create_dns_route_rule(config: DnsRuleConfig) -> DnsRouteRule:
    rule: Rule | None = None
    if config.rule:
        rule = create_rule(config.rule)
    return DnsRouteRule(
        rule,
        config.rule_set,
        config.server,
    )


def create_dns_router(config: DnsConfig, rule_sets: dict[str, list[Rule]]) -> DnsRouter:
    if not config.final:
        raise RuntimeError("should have a dns final server")
    rules: list[DnsRouteRule] = []
    for item in config.rules:
        rule = create_dns_route_rule(item)
        for rule_set_tag in rule.rule_sets:
            if rule_set_tag not in rule_sets:
                raise RuntimeError("rule set not exist")
        rules.append(rule)
    return DnsRouter(
        rules,
        rule_sets,
        config.final,
    )


def create_router(config: RouteConfig, rule_sets: dict[str, list[Rule]]) -> Router:
    rules: list[RouteRule] = []
    for item in config.rules:
        rule = create_route_rule(item)
        for rule_set_tag in rule.rule_sets:
            if rule_set_tag not in rule_sets:
                raise RuntimeError("rule set not exist")
        rules.append(rule)
    return Router(
        rules,
        rule_sets,
        config.final,
    )
