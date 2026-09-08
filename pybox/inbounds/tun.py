import asyncio
import ipaddress
import threading
from typing import Any, cast

import dns
import dns.message

from ..common.address import AddressType, IPV4_Address
from ..common import globals
from ..connections.tcp import TcpConnection
from .inbound import Inbound
from .listeners.tcp_listener import TcpListener
from .tunnel.ip import (
    is_ipv4_udp,
    parse_ipv4_flow,
    replace_ipv4_flow,
    update_ipv4_checksum,
    update_ipv4_tcp_checksum,
    is_ipv4,
    is_ipv4_tcp,
    update_ipv4_udp_checksum,
)
from .tunnel.nat import Nat
from .tunnel.route import create_ipv4_address, set_route
from .tunnel.wintun import WinTun
from ..common.session import Session


def transport_to_host_port(transport: asyncio.DatagramTransport) -> tuple[str, int]:
    udp_addr = transport.get_extra_info("sockname")
    return (udp_addr[0], udp_addr[1])


class TunInbound(Inbound):
    def __init__(
        self, tun_ipv4: ipaddress.IPv4Address, tun_next_ipv4: ipaddress.IPv4Address
    ) -> None:
        self.tun_ipv4 = tun_ipv4
        self.tun_next_ipv4 = tun_next_ipv4
        self.tun_name = "pybox"
        self.tun = WinTun(self.tun_name)
        self.queue: asyncio.Queue[Session] = asyncio.Queue()
        self.ipv4_tcp_nat = Nat()
        self.ipv4_udp_nat = Nat()
        self.udp_client_map: dict[tuple[str, int], int] = {}
        self._packet_thread: threading.Thread | None = None
        self._tun_thread: threading.Thread | None = None
        self.listener = TcpListener(str(self.tun_ipv4), 0)
        self.ipv4_udp_listen_port = 0
        self.tasks: list[asyncio.Task] = []

    async def start(self):
        if not globals.LOCAL_IPV4:
            raise RuntimeError("tun should get local ipv4")
        self.tun.start()
        self._packet_thread = threading.Thread(target=self.packet_loop, daemon=True)
        self._packet_thread.start()
        self._tun_thread = threading.Thread(target=self.tun.receive_worker, daemon=True)
        self._tun_thread.start()
        luid = self.tun.get_luid()
        create_ipv4_address(luid, self.tun_ipv4, 32)
        # if not add_ipv4_address(self.tun_name, self.tun_ipv4):
        #     raise RuntimeError("fail set tun ipv4")
        # tcp listener
        await self.start_tcp_listener()
        self.ipv4_tcp_listen_port, self.ipv6_listen_port = self.get_tcp_listen_port()
        # udp listener
        loop = asyncio.get_running_loop()
        self.transport, protocol = await loop.create_datagram_endpoint(
            lambda: UdpListener(self), local_addr=(str(self.tun_ipv4), 0)
        )
        self.ipv4_udp_listen_port = self.get_udp_listen_port()
        if not set_route(self.tun_name, self.tun_next_ipv4):
            raise RuntimeError("fail set route")
        # if not set_dns(self.tun_name):
        #     raise RuntimeError("fail set dns")
        while True:
            connection = await self.listener.accept()
            task=asyncio.create_task(self._handshake(connection))
            self.tasks.append(task)

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
        return await self.listener.close()

    async def sessions(self) -> Session:
        return await self.queue.get()

    def get_udp_listen_port(self) -> int:
        udp_addr = self.transport.get_extra_info("sockname")
        return udp_addr[1]

    def get_tcp_listen_port(self) -> tuple[int, int]:
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
                elif is_ipv4_udp(packet):
                    self._deal_ipv4_udp(packet)

    def _deal_ipv4_udp(self, packet: bytearray):
        flow_key = parse_ipv4_flow(packet)
        if not flow_key or not self.ipv4_udp_listen_port:
            return
        if (
            self.tun_ipv4 == flow_key.src_ip
            and self.ipv4_udp_listen_port == flow_key.src_port
        ):
            nat_session = self.ipv4_udp_nat.lookup_back(flow_key.dst_port)
            if not nat_session:
                return
            replace_ipv4_flow(
                packet,
                nat_session.dst_ip,
                nat_session.src_ip,
                nat_session.dst_port,
                nat_session.src_port,
            )
        else:
            nat_port = self.ipv4_udp_nat.lookup_or_create(flow_key)
            replace_ipv4_flow(
                packet,
                self.tun_next_ipv4,
                self.tun_ipv4,
                nat_port,
                self.ipv4_udp_listen_port,
            )
        update_ipv4_udp_checksum(packet)
        update_ipv4_checksum(packet)
        self.tun.send(bytes(packet))

    def _deal_ipv4_tcp(self, packet: bytearray):
        flow_key = parse_ipv4_flow(packet)
        if not flow_key or not self.ipv4_tcp_listen_port:
            return
        if (
            self.tun_ipv4 == flow_key.src_ip
            and self.ipv4_tcp_listen_port == flow_key.src_port
        ):
            nat_session = self.ipv4_tcp_nat.lookup_back(flow_key.dst_port)
            if not nat_session:
                return
            replace_ipv4_flow(
                packet,
                nat_session.dst_ip,
                nat_session.src_ip,
                nat_session.dst_port,
                nat_session.src_port,
            )
        else:
            nat_port = self.ipv4_tcp_nat.lookup_or_create(flow_key)
            replace_ipv4_flow(
                packet,
                self.tun_next_ipv4,
                self.tun_ipv4,
                nat_port,
                self.ipv4_tcp_listen_port,
            )
        update_ipv4_tcp_checksum(packet)
        update_ipv4_checksum(packet)
        self.tun.send(bytes(packet))

    async def _handshake(self, connection: TcpConnection):
        peer = connection.writer.get_extra_info("peername")
        nat_port = cast(int, peer[1])
        nat_session = self.ipv4_tcp_nat.lookup_back(nat_port)
        if not nat_session:
            raise RuntimeError("fail to find nat session")
        initial_data = await connection.read(4096)
        session = Session(
            connection,
            IPV4_Address(nat_session.dst_ip, nat_session.dst_port),
            initial_data,
        )
        await self.queue.put(session)

    async def _handle_udp_client(self, data: bytes, addr: tuple[str, int]):
        nat_port = self.udp_client_map.get(addr)
        if not nat_port:
            raise RuntimeError("no nat port")
        self.transport.sendto(data, (str(self.tun_next_ipv4), nat_port))

    async def _handle_udp_listener(self, data: bytes, addr: tuple[str, int]):
        nat_port = addr[1]
        nat_session = self.ipv4_udp_nat.lookup_back(nat_port)
        if not nat_session:
            raise RuntimeError("fail to find nat session")
        # remote_transport = self.clients.get(nat_port)
        # if remote_transport:
        #     remote_transport.sendto(data, (nat_session.dst_ip, nat_session.dst_port))
        #     return
        loop = asyncio.get_running_loop()
        remote_transport, protocol = await loop.create_datagram_endpoint(
            lambda: UdpClient(self), local_addr=(globals.LOCAL_IPV4, 0)
        )
        remote_host, remote_port = transport_to_host_port(remote_transport)
        # self.clients[nat_port] = remote_transport
        # self.port_map[nat_port] = port
        self.udp_client_map[(str(nat_session.dst_ip), nat_session.dst_port)] = nat_port
        remote_transport.sendto(data, (str(nat_session.dst_ip), nat_session.dst_port))


class UdpListener(asyncio.DatagramProtocol):
    def __init__(self, tun: TunInbound) -> None:
        # self.clients: dict[int, asyncio.DatagramTransport] = {}
        # self.port_map: dict[int, int] = {}
        self.tun = tun
        self.tasks: list[asyncio.Task] = []
    # def connection_made(self, transport: asyncio.DatagramTransport) -> None:
    #     self.transport=transport
    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        task=asyncio.create_task(self.tun._handle_udp_listener(data, addr))
        self.tasks.append(task)

    # def handle_client(self,data:bytes, addr:tuple[str,int]):
    #     self.transport.sendto(data,)


class UdpClient(asyncio.DatagramProtocol):
    def __init__(self, tun: TunInbound) -> None:
        self.tun = tun
        self.tasks: list[asyncio.Task] = []
    # def connection_made(self, transport: asyncio.DatagramTransport) -> None:
    #     self.transport=transport
    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        task=asyncio.create_task(self.tun._handle_udp_client(data, addr))
        self.tasks.append(task)
        # self.listener.handle_client(data, addr)
