import re

from ..inbounds.inbound import Inbound
from ..outbounds.block import BlockOutbound
from ..outbounds.transports.tcp import TcpTransport
from ..outbounds.transports.tls import TlsTransport
from .config import InboundConfig, RouteConfig, RouteRuleConfig, load_config

from ..common.address import Destination
from ..common.config import load_config, OutboundConfig
from ..common.core import Core
from ..inbounds.listeners.tcp_listener import TcpListener
from ..inbounds.socks5 import Socks5Inbound
from ..outbounds.direct import DirectOutbound
from ..outbounds.outbound import Outbound
from ..outbounds.transports.ws import WsTransport
from ..outbounds.transports.wss import WssTransport
from ..outbounds.vless import VlessOutbound
from .router import RouteRule, Router


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
    if config.type == "socks5":
        if config.listen_port is None or config.listen is None:
            raise RuntimeError("socks5 inbound error")
        listener = TcpListener(config.listen, config.listen_port)
        return Socks5Inbound(listener, {})
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


def create_route(config: RouteRuleConfig) -> RouteRule:
    return RouteRule(
        config.domain,
        config.domain_suffix,
        config.domain_keyword,
        [re.compile(item) for item in config.domain_regex],
        config.ip_cidr,
        config.outbound,
    )


def create_router(config: RouteConfig) -> Router:
    return Router([create_route(item) for item in config.rules], config.final)
