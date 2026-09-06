import asyncio
import ipaddress
import threading
from typing import cast

from ..common.address import AddressType, IPV4_Address
from ..connections.connection import Connection
from ..connections.tcp import TcpConnection
from .inbound import Inbound
from .listeners.tcp_listener import TcpListener
from .tunnel.ip import (
    parse_tcp_ipv4,
    replace_ipv4_flow,
    update_ipv4_checksum,
    update_ipv4_tcp_checksum,
    is_ipv4,
    is_ipv4_tcp,
)
from .tunnel.nat import Nat
from .tunnel.route import add_ipv4_address, set_route
from .tunnel.wintun import WinTun
from ..common.session import Session


class TunInbound(Inbound):
    def __init__(
        self, tun_ipv4: ipaddress.IPv4Address, tun_next_ipv4: ipaddress.IPv4Address
    ) -> None:
        self.tun_ipv4 = tun_ipv4
        self.tun_next_ipv4 = tun_next_ipv4
        self.tun_name = "pybox"
        self.tun = WinTun(self.tun_name)
        self.queue: asyncio.Queue[Session] = asyncio.Queue()
        self.ipv4_nat = Nat()
        self._packet_thread: threading.Thread | None = None
        self._tun_thread: threading.Thread | None = None
        self.listener = TcpListener(str(self.tun_ipv4), 0)

    async def start(self):
        self.tun.start()
        self._packet_thread = threading.Thread(target=self.packet_loop, daemon=True)
        self._packet_thread.start()
        self._tun_thread = threading.Thread(target=self.tun.receive_worker, daemon=True)
        self._tun_thread.start()
        if not add_ipv4_address(self.tun_name, self.tun_ipv4):
            raise RuntimeError("fail set tun ipv4")
        await self.start_tcp_listener()
        self.ipv4_listen_port, self.ipv6_listen_port = self.get_listen_port()
        if not set_route(self.tun_name, self.tun_next_ipv4):
            raise RuntimeError("fail set route")
        while True:
            connection = await self.listener.accept()
            asyncio.create_task(self._handshake(connection))

    async def start_tcp_listener(self):
        i = 0
        while True:
            if i > 100:
                raise RuntimeError("fail listen tun ipv4")
            try:
                await self.listener.start()
                return
            except OSError:
                await asyncio.sleep(0.1)
            finally:
                i += 1

    async def close(self):
        self.tun.stop()
        await self.listener.close()

    async def sessions(self) -> Session:
        return await self.queue.get()

    def get_listen_port(self) -> tuple[int, int]:
        ipv4_port = 0
        ipv6_port = 0
        assert self.listener.server
        for sock in self.listener.server.sockets:
            name = sock.getsockname()
            try:
                ip = ipaddress.ip_address(name[0])
                if isinstance(name[1], int):
                    if ip.version == 6:
                        ipv6_port = name[1]
                    if ip.version == 4:
                        ipv4_port = name[1]
            except ValueError:
                continue
        return (ipv4_port, ipv6_port)

    def packet_loop(self):
        while True:
            packet_bytes = self.tun.get_packet()
            packet = bytearray(packet_bytes)
            if is_ipv4(packet):
                if is_ipv4_tcp(packet):
                    self._deal_ipv4_tcp(packet)

    def _deal_ipv4_tcp(self, byte_array: bytearray):
        flow_key = parse_tcp_ipv4(byte_array)
        if not flow_key:
            return
        if (
            self.tun_ipv4 == flow_key.src_ip
            and self.ipv4_listen_port == flow_key.src_port
        ):
            nat_session = self.ipv4_nat.lookup_back(flow_key.dst_port)
            if not nat_session:
                return
            replace_ipv4_flow(
                byte_array,
                nat_session.dst_ip,
                nat_session.src_ip,
                nat_session.dst_port,
                nat_session.src_port,
            )
        else:
            nat_port = self.ipv4_nat.lookup_or_create(flow_key)
            replace_ipv4_flow(
                byte_array,
                self.tun_next_ipv4,
                self.tun_ipv4,
                nat_port,
                self.ipv4_listen_port,
            )
        update_ipv4_tcp_checksum(byte_array)
        update_ipv4_checksum(byte_array)
        self.tun.send(bytes(byte_array))

    async def _handshake(self, connection: TcpConnection):
        peer = connection.writer.get_extra_info("peername")
        nat_port = cast(int, peer[1])
        nat_session = self.ipv4_nat.lookup_back(nat_port)
        if not nat_session:
            raise RuntimeError("fail to find nat session")
        session = Session(
            connection,
            IPV4_Address(nat_session.dst_ip, nat_session.dst_port),
            bytes(),
        )
        await self.queue.put(session)
