import json
import re

from ..inbounds.inbound import Inbound
from ..inbounds.mixed import MixedInbound
from ..outbounds.block import BlockOutbound
from ..outbounds.transports.tcp import TcpTransport
from ..outbounds.transports.tls import TlsTransport
from .config import (
    InboundConfig,
    RouteConfig,
    OutboundConfig,
    RuleConfig,
    RouteRuleConfig,
    RuleSetConfig,
    load_config,
    parse_rule,
)

from .address import Destination
from .core import Core
from ..inbounds.listeners.tcp_listener import TcpListener
from ..outbounds.direct import DirectOutbound
from ..outbounds.outbound import Outbound
from ..outbounds.transports.ws import WsTransport
from ..outbounds.transports.wss import WssTransport
from ..outbounds.vless import VlessOutbound
from .router import RouteRule, Router, Rule


class App:
    def __init__(self, config_path: str) -> None:
        self.config = load_config(config_path)

    async def run(self):
        core = Core(
            [create_inbound(item) for item in self.config.inbounds],
            {item.tag: create_outbound(item) for item in self.config.outbounds},
            create_router(self.config.route),
        )
        await core.start()
        await core.run()


def create_inbound(config: InboundConfig) -> Inbound:
    if config.type == "mixed":
        if config.listen_port is None or config.listen is None:
            raise RuntimeError("socks5 inbound error")
        listener = TcpListener(config.listen, config.listen_port)
        return MixedInbound(listener)
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
            Destination.from_host_port(config.server, config.server_port),
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


def create_router(config: RouteConfig) -> Router:
    rule_sets = {item.tag: load_rule_set(item) for item in config.rule_sets}
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
