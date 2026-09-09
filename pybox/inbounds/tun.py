import asyncio
import ipaddress
import threading
from typing import Any, cast

from ..common.address import IPV4_Address
from ..common import globals
from ..common.udp import UdpClient
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
from .tunnel.route import create_ip_address, set_dns, set_route
from .tunnel.wintun import WinTun
from ..common.session import Session


def transport_to_host_port(transport: asyncio.DatagramTransport) -> tuple[str, int]:
    udp_addr = transport.get_extra_info("sockname")
    return (udp_addr[0], udp_addr[1])


class TunInbound(Inbound):
    def __init__(
        self,
        tun_ipv4: ipaddress.IPv4Address | None,
        tun_next_ipv4: ipaddress.IPv4Address | None,
        tun_ipv6: ipaddress.IPv6Address | None,
        tun_next_ipv6: ipaddress.IPv6Address | None,
    ) -> None:
        self.tun_ipv4 = tun_ipv4
        self.tun_next_ipv4 = tun_next_ipv4
        self.tun_ipv6 = tun_ipv6
        self.tun_next_ipv6 = tun_next_ipv6
        self.ipv4_enabled = True if self.tun_ipv4 and self.tun_next_ipv4 else False
        self.ipv6_enabled = True if self.tun_ipv6 and self.tun_next_ipv6 else False
        if not self.ipv4_enabled and not self.ipv6_enabled:
            raise RuntimeError("ipv4 or ipv6 must set one")
        self.tun_name = "pybox"
        self.tun = WinTun(self.tun_name)
        self.tcp_queue: asyncio.Queue[Session] = asyncio.Queue()
        # self.udp_client_map: dict[tuple[str, int], int] = {}
        self._packet_thread: threading.Thread | None = None
        self._tun_thread: threading.Thread | None = None
        self.ipv4_udp_dict: dict[int, UdpClient] = {}
        self.ipv6_udp_dict: dict[int, UdpClient] = {}
        self.tasks: list[asyncio.Task] = []
        if self.ipv4_enabled:
            self.ipv4_tcp_listener = TcpListener(str(self.tun_ipv4), 0)
            self.ipv4_tcp_nat = Nat()
            self.ipv4_udp_nat = Nat()
            self.ipv4_udp_listen_port = 0
        if self.ipv6_enabled:
            self.ipv6_tcp_listener = TcpListener(str(self.tun_ipv4), 0)
            self.ipv6_tcp_nat = Nat()
            self.ipv6_udp_nat = Nat()
            self.ipv6_udp_listen_port = 0

    async def start(self):
        if not globals.LOCAL_IPV4 and self.ipv4_enabled:
            raise RuntimeError("tun should get local ipv4")
        if not globals.LOCAL_IPV6 and self.ipv6_enabled:
            raise RuntimeError("tun should get local ipv6")
        self.tun.start()
        self._packet_thread = threading.Thread(target=self.packet_loop, daemon=True)
        self._packet_thread.start()
        self._tun_thread = threading.Thread(target=self.tun.receive_worker, daemon=True)
        self._tun_thread.start()
        luid = self.tun.get_luid()
        tasks: list[asyncio.Task] = []
        if self.ipv4_enabled:
            assert self.tun_ipv4
            create_ip_address(luid, self.tun_ipv4, 32)
            await self.ipv4_tcp_listener.start()
            self.ipv4_tcp_listen_port = self.get_tcp_ipv4_listen_port()
            self.ipv4_udp_listener = UdpClient()
            await self.ipv4_udp_listener.start(local_addr=(self.tun_ipv4, 0))
            self.ipv4_udp_listen_port = (await self.ipv4_udp_listener.local_addr())[1]
            asyncio.create_task(self.ipv4_udp_worker())
            assert self.tun_next_ipv4
            if not set_route(self.tun_name, self.tun_next_ipv4):
                raise RuntimeError("fail set route")
            task = asyncio.create_task(self.ipv4_tcp_listen_work())
            tasks.append(task)
        if self.ipv6_enabled:
            assert self.tun_ipv6
            create_ip_address(luid, self.tun_ipv6, 64)
            await self.ipv6_tcp_listener.start()
            self.ipv6_tcp_listen_port = self.get_tcp_ipv6_listen_port()
            self.ipv6_udp_listener = UdpClient()
            await self.ipv6_udp_listener.start(local_addr=(self.tun_ipv6, 0))
            self.ipv6_udp_listen_port = (await self.ipv6_udp_listener.local_addr())[1]
            assert self.tun_next_ipv6
            if not set_route(self.tun_name, self.tun_next_ipv6):
                raise RuntimeError("fail set route")
            task = asyncio.create_task(self.ipv6_tcp_listen_work())
            tasks.append(task)
        asyncio.gather(*tasks, return_exceptions=True)

    async def ipv4_tcp_listen_work(self):
        while True:
            connection = await self.ipv4_tcp_listener.accept()
            task = asyncio.create_task(self.tcp_handshake(connection))
            self.tasks.append(task)

    async def ipv6_tcp_listen_work(self):
        while True:
            connection = await self.ipv4_tcp_listener.accept()
            task = asyncio.create_task(self.tcp_handshake(connection))
            self.tasks.append(task)

    async def close(self):
        self.tun.stop()
        if self.ipv4_enabled:
            await self.ipv4_tcp_listener.close()
            self.ipv4_udp_listener.close()
        if self.ipv6_enabled:
            await self.ipv6_tcp_listener.close()
            self.ipv6_udp_listener.close()

    async def sessions(self) -> Session:
        return await self.tcp_queue.get()

    def get_tcp_ipv4_listen_port(self) -> int:
        assert self.ipv4_tcp_listener.server
        name = self.ipv4_tcp_listener.server.sockets[0].getsockname()
        assert isinstance(name[1], int)
        return name[1]

    def get_tcp_ipv6_listen_port(self) -> int:
        assert self.ipv6_tcp_listener.server
        name = self.ipv6_tcp_listener.server.sockets[0].getsockname()
        assert isinstance(name[1], int)
        return name[1]

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
        if (
            not flow_key
            or not self.ipv4_udp_listen_port
            or not self.tun_next_ipv4
            or not self.tun_ipv4
        ):
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
        if (
            not flow_key
            or not self.ipv4_udp_listen_port
            or not self.tun_next_ipv4
            or not self.tun_ipv4
        ):
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

    async def tcp_handshake(self, connection: TcpConnection):
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
        await self.tcp_queue.put(session)

    async def ipv4_udp_worker(self):
        while True:
            data, ip, nat_port = await self.ipv4_udp_listener.sessions()
            nat_session = self.ipv4_udp_nat.lookup_back(nat_port)
            if not nat_session:
                raise RuntimeError("fail to find nat session")
            client = UdpClient()
            await client.start(
                local_addr=(ipaddress.IPv4Address(globals.LOCAL_IPV4), 0)
            )
            client.send(
                data, ipaddress.IPv4Address(nat_session.dst_ip), nat_session.dst_port
            )
            self.ipv4_udp_dict[nat_session.src_port] = client
            asyncio.create_task(self.ipv4_udp_client_worker(client, nat_port))

    async def ipv4_udp_client_worker(self, client: UdpClient, nat_port: int):
        assert self.tun_next_ipv4
        while True:
            data, ip, nat_port = await client.sessions()
            self.ipv4_udp_listener.send(data, self.tun_next_ipv4, nat_port)

    # async def _handle_udp_client(self, data: bytes, addr: tuple[str, int]):
    #     nat_port = self.udp_client_map.get(addr)
    #     if not nat_port:
    #         raise RuntimeError("no nat port")
    #     self.transport.sendto(data, (str(self.tun_next_ipv4), nat_port))

    # async def _handle_udp_listener(self, data: bytes, addr: tuple[str, int]):
    #     nat_port = addr[1]
    #     # remote_transport = self.clients.get(nat_port)
    #     # if remote_transport:
    #     #     remote_transport.sendto(data, (nat_session.dst_ip, nat_session.dst_port))
    #     #     return
    #     loop = asyncio.get_running_loop()
    #     remote_transport, protocol = await loop.create_datagram_endpoint(
    #         lambda: UdpClient(self), local_addr=(globals.LOCAL_IPV4, 0)
    #     )
    #     remote_host, remote_port = transport_to_host_port(remote_transport)
    #     # self.clients[nat_port] = remote_transport
    #     # self.port_map[nat_port] = port
    #     self.udp_client_map[(str(nat_session.dst_ip), nat_session.dst_port)] = nat_port
    #     remote_transport.sendto(data, (str(nat_session.dst_ip), nat_session.dst_port))


# class UdpListener(asyncio.DatagramProtocol):
#     def __init__(self, tun: TunInbound) -> None:
#         # self.clients: dict[int, asyncio.DatagramTransport] = {}
#         # self.port_map: dict[int, int] = {}
#         self.tun = tun
#         self.tasks: list[asyncio.Task] = []

#     # def connection_made(self, transport: asyncio.DatagramTransport) -> None:
#     #     self.transport=transport
#     def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
#         task = asyncio.create_task(self.tun._handle_udp_listener(data, addr))
#         self.tasks.append(task)

#     # def handle_client(self,data:bytes, addr:tuple[str,int]):
#     #     self.transport.sendto(data,)


# class UdpClient(asyncio.DatagramProtocol):
#     def __init__(self, tun: TunInbound) -> None:
#         self.tun = tun
#         self.tasks: list[asyncio.Task] = []

#     # def connection_made(self, transport: asyncio.DatagramTransport) -> None:
#     #     self.transport=transport
#     def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
#         task = asyncio.create_task(self.tun._handle_udp_client(data, addr))
#         self.tasks.append(task)
#         # self.listener.handle_client(data, addr)
