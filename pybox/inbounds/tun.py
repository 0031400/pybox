import asyncio
import ipaddress
import threading
from typing import cast

from ..common.address import AddressType, Destination
from ..connections.connection import Connection
from ..connections.tcp import TcpConnection
from .inbound import Inbound
from .listeners.tcp_listener import TcpListener
from .tunnel.ip import (
    parse_tcp_ipv4,
    replace_ipv4_flow,
    update_ipv4_checksum,
    update_tcp_checksum,
)
from .tunnel.nat import FlowKey, Nat
from .tunnel.route import add_ipv4_address, set_route
from .tunnel.wintun import WinTun
from ..common.session import Session


class TunInbound(Inbound):
    def __init__(self, tun_ipv4: str, tun_next_ipv4: str) -> None:
        self.tun_ipv4 = tun_ipv4
        self.tun_next_ipv4 = tun_next_ipv4
        self.tun_name = "pybox"
        self.queue: asyncio.Queue[Session] = asyncio.Queue()
        self.ipv4_nat = Nat()

    async def start(self):
        self.tun = WinTun(self.tun_name)
        self.tun.start()
        self._packet_thread = threading.Thread(target=self.packet_loop, daemon=True)
        self._packet_thread.start()
        self._tun_thread = threading.Thread(target=self.tun.receive_worker, daemon=True)
        self._tun_thread.start()
        if not self.tun_ipv4 or not self.tun_next_ipv4:
            raise RuntimeError("need set tun ipv4")
        if not add_ipv4_address(self.tun_name, self.tun_ipv4):
            raise RuntimeError("fail set tun ipv4")
        self.listener: TcpListener = TcpListener(self.tun_ipv4, 0)
        for i in range(100):
            if i == 90:
                raise RuntimeError("fail listen tun ipv4")
            try:
                await self.listener.start()
                break
            except OSError as e:
                await asyncio.sleep(0.1)
        self.ipv4_listen_port, self.ipv6_listen_port = self.get_listen_port()
        if not set_route(self.tun_name, self.tun_next_ipv4):
            raise RuntimeError("fail set route")
        while True:
            connection = await self.listener.accept()
            asyncio.create_task(self._handshake(connection))

    async def close(self):
        self.tun.stop()

    async def sessions(self) -> Session:
        return await self.queue.get()

    def get_listen_port(self) -> tuple[int, int]:
        res: tuple[int, int] = (0, 0)
        if not self.listener.server:
            return res
        for sock in self.listener.server.sockets:
            name = sock.getsockname()
            try:
                ip = ipaddress.ip_address(name[0])
                if isinstance(name[1], int):
                    if ip.version == 6:
                        res = (res[0], name[1])
                    if ip.version == 4:
                        res = (name[1], res[1])
            except ValueError:
                continue
        return res

    def packet_loop(self):
        while True:
            packet = self.tun.get_packet()
            flow_key = parse_tcp_ipv4(packet)
            if flow_key:
                if (
                    self.tun_ipv4 == str(flow_key.src_ip)
                    and self.ipv4_listen_port == flow_key.src_port
                ):
                    nat_session = self.ipv4_nat.lookup_back(flow_key.dst_port)
                    if not nat_session:
                        continue
                    b = bytearray(packet)
                    replace_ipv4_flow(
                        b,
                        nat_session.dst_ip,
                        nat_session.src_ip,
                        nat_session.dst_port,
                        nat_session.src_port,
                    )
                    update_tcp_checksum(b)
                    update_ipv4_checksum(b)
                    self.tun.send(bytes(b))
                else:
                    nat_port = self.ipv4_nat.lookup_or_create(flow_key)
                    b = bytearray(packet)
                    replace_ipv4_flow(
                        b,
                        ipaddress.IPv4Address(self.tun_next_ipv4),
                        ipaddress.IPv4Address(self.tun_ipv4),
                        nat_port,
                        self.ipv4_listen_port,
                    )
                    update_tcp_checksum(b)
                    update_ipv4_checksum(b)
                    self.tun.send(bytes(b))

    async def _handshake(self, connection: TcpConnection):
        peer = connection.writer.get_extra_info("peername")
        nat_port = cast(int, peer[1])
        nat_session = self.ipv4_nat.lookup_back(nat_port)
        if not nat_session:
            raise RuntimeError("fail to find nat session")
        session = Session(
            connection,
            Destination(
                AddressType.IPV4, str(nat_session.dst_ip), nat_session.dst_port
            ),
            bytes(),
        )
        await self.queue.put(session)
