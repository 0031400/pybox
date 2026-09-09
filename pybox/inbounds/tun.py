import asyncio
import ipaddress
import threading
from typing import Any, cast

from ..common.address import IPV4_Address, IPV6_Address
from ..common import globals
from ..common.log import log
from ..common.udp import UdpClient
from ..connections.tcp import TcpConnection
from .inbound import Inbound
from .listeners.tcp_listener import TcpListener
from .tunnel.ip import (
    is_ipv4_udp,
    is_ipv6,
    is_ipv6_tcp,
    is_ipv6_udp,
    parse_ipv4_flow,
    parse_ipv6_flow,
    replace_ipv4_flow,
    replace_ipv6_flow,
    update_ipv4_checksum,
    update_ipv4_tcp_checksum,
    is_ipv4,
    is_ipv4_tcp,
    update_ipv4_udp_checksum,
    update_ipv6_tcp_checksum,
    update_ipv6_udp_checksum,
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
        auto_route: bool,
    ) -> None:
        self.auto_route = auto_route
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
            self.ipv6_tcp_listener = TcpListener(str(self.tun_ipv6), 0)
            self.ipv6_tcp_nat = Nat()
            self.ipv6_udp_nat = Nat()
            self.ipv6_udp_listen_port = 0

    async def start(self):
        if self.ipv4_enabled:
            if not globals.LOCAL_IPV4:
                log("error", "tun fail to get local ipv4")
                self.ipv4_enabled = False
        if self.ipv6_enabled:
            if not globals.LOCAL_IPV6:
                log("error", "tun fail to get local ipv6")
                self.ipv6_enabled = False
        if not self.ipv4_enabled and not self.ipv6_enabled:
            raise RuntimeError("ipv4 or ipv6 must set one")
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
            task = asyncio.create_task(self.udp_worker(True))
            self.tasks.append(task)
            assert self.tun_next_ipv4
            if self.auto_route:
                if not set_route(self.tun_name, self.tun_next_ipv4):
                    raise RuntimeError("fail set route")
            task = asyncio.create_task(self.ipv4_tcp_listen_work())
            tasks.append(task)
        if self.ipv6_enabled:
            assert self.tun_ipv6
            create_ip_address(luid, self.tun_ipv6, 128)
            await self.ipv6_tcp_listener.start()
            self.ipv6_tcp_listen_port = self.get_tcp_ipv6_listen_port()
            self.ipv6_udp_listener = UdpClient()
            await self.ipv6_udp_listener.start(local_addr=(self.tun_ipv6, 0))
            self.ipv6_udp_listen_port = (await self.ipv6_udp_listener.local_addr())[1]
            task = asyncio.create_task(self.udp_worker(False))
            self.tasks.append(task)
            assert self.tun_next_ipv6
            if self.auto_route:
                if not set_route(self.tun_name, self.tun_next_ipv6):
                    raise RuntimeError("fail set route")
            task = asyncio.create_task(self.ipv6_tcp_listen_work())
            tasks.append(task)
        await asyncio.gather(*tasks, return_exceptions=True)

    async def ipv4_tcp_listen_work(self):
        while True:
            connection = await self.ipv4_tcp_listener.accept()
            task = asyncio.create_task(self.tcp_handshake(connection))
            self.tasks.append(task)

    async def ipv6_tcp_listen_work(self):
        while True:
            connection = await self.ipv6_tcp_listener.accept()
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
                    self.deal_packet_nat(packet, True, True)
                elif is_ipv4_udp(packet):
                    self.deal_packet_nat(packet, True, False)
            elif is_ipv6(packet):
                if is_ipv6_tcp(packet):
                    self.deal_packet_nat(packet, False, True)
                elif is_ipv6_udp(packet):
                    self.deal_packet_nat(packet, False, False)

    def deal_packet_nat(self, packet: bytearray, is_v4: bool, is_tcp: bool):
        if is_v4:
            if not self.tun_next_ipv4 or not self.tun_ipv4:
                return
            flow_key = parse_ipv4_flow(packet)
        else:
            if not self.tun_next_ipv6 or not self.tun_ipv6:
                return
            flow_key = parse_ipv6_flow(packet)

        if not flow_key:
            return
        flag = True
        if is_v4:
            if flow_key.src_ip != self.tun_ipv4:
                flag = False
            if is_tcp:
                if self.ipv4_tcp_listen_port != flow_key.src_port:
                    flag = False
            else:
                if self.ipv4_udp_listen_port != flow_key.src_port:
                    flag = False
        else:
            if flow_key.src_ip != self.tun_ipv6:
                flag = False
            if is_tcp:
                if self.ipv6_tcp_listen_port != flow_key.src_port:
                    flag = False
            else:
                if self.ipv6_udp_listen_port != flow_key.src_port:
                    flag = False

        if flag:
            if is_v4:
                if is_tcp:
                    nat_dict = self.ipv4_tcp_nat
                else:
                    nat_dict = self.ipv4_udp_nat
            else:
                if is_tcp:
                    nat_dict = self.ipv6_tcp_nat
                else:
                    nat_dict = self.ipv6_udp_nat
            nat_session = nat_dict.lookup_back(flow_key.dst_port)
            if not nat_session:
                return
            if is_v4:
                assert (
                    self.tun_next_ipv4
                    and self.tun_ipv4
                    and nat_session.dst_ip.version == 4
                    and nat_session.src_ip.version == 4
                )
                replace_ipv4_flow(
                    packet,
                    nat_session.dst_ip,
                    nat_session.src_ip,
                    nat_session.dst_port,
                    nat_session.src_port,
                )
            else:
                assert (
                    self.tun_next_ipv6
                    and self.tun_ipv6
                    and nat_session.dst_ip.version == 6
                    and nat_session.src_ip.version == 6
                )
                replace_ipv6_flow(
                    packet,
                    nat_session.dst_ip,
                    nat_session.src_ip,
                    nat_session.dst_port,
                    nat_session.src_port,
                )
        else:
            if is_v4:
                if is_tcp:
                    nat_port = self.ipv4_tcp_nat.lookup_or_create(flow_key)
                else:
                    nat_port = self.ipv4_udp_nat.lookup_or_create(flow_key)
            else:
                if is_tcp:
                    nat_port = self.ipv6_tcp_nat.lookup_or_create(flow_key)
                else:
                    nat_port = self.ipv6_udp_nat.lookup_or_create(flow_key)
            if is_v4:
                assert self.tun_next_ipv4 and self.tun_ipv4
                replace_ipv4_flow(
                    packet,
                    self.tun_next_ipv4,
                    self.tun_ipv4,
                    nat_port,
                    self.ipv4_tcp_listen_port if is_tcp else self.ipv4_udp_listen_port,
                )
            else:
                assert self.tun_next_ipv6 and self.tun_ipv6
                replace_ipv6_flow(
                    packet,
                    self.tun_next_ipv6,
                    self.tun_ipv6,
                    nat_port,
                    self.ipv6_tcp_listen_port if is_tcp else self.ipv6_udp_listen_port,
                )
        if is_v4:
            if is_tcp:
                update_ipv4_tcp_checksum(packet)
            else:
                update_ipv4_udp_checksum(packet)
            update_ipv4_checksum(packet)
        else:
            if is_tcp:
                update_ipv6_tcp_checksum(packet)
            else:
                update_ipv6_udp_checksum(packet)
        self.tun.send(bytes(packet))

    async def tcp_handshake(self, connection: TcpConnection):
        peer = connection.writer.get_extra_info("peername")
        nat_port = cast(int, peer[1])
        ip = ipaddress.ip_address(peer[0])
        if ip.version == 4:
            nat_session = self.ipv4_tcp_nat.lookup_back(nat_port)
        else:
            nat_session = self.ipv6_tcp_nat.lookup_back(nat_port)
        if not nat_session:
            raise RuntimeError("fail to find nat session")
        initial_data = await connection.read(4096)
        session = Session(
            connection,
            (
                IPV4_Address(nat_session.dst_ip, nat_session.dst_port)
                if nat_session.dst_ip.version == 4
                else IPV6_Address(nat_session.dst_ip, nat_session.dst_port)
            ),
            initial_data,
        )
        await self.tcp_queue.put(session)

    async def udp_worker(self, is_v4: bool):
        while True:
            if is_v4:
                data, ip, nat_port = await self.ipv4_udp_listener.sessions()
                nat_session = self.ipv4_udp_nat.lookup_back(nat_port)
                local_ip = globals.LOCAL_IPV4
            else:
                data, ip, nat_port = await self.ipv6_udp_listener.sessions()
                nat_session = self.ipv6_udp_nat.lookup_back(nat_port)
                local_ip = globals.LOCAL_IPV6
            if not nat_session:
                raise RuntimeError("fail to find nat session")
            client = UdpClient()
            await client.start(local_addr=(ipaddress.ip_address(local_ip), 0))
            client.send(
                data, ipaddress.ip_address(nat_session.dst_ip), nat_session.dst_port
            )
            if is_v4:
                self.ipv4_udp_dict[nat_session.src_port] = client
            else:
                self.ipv6_udp_dict[nat_session.src_port] = client
            asyncio.create_task(self.udp_client_worker(client, nat_port, is_v4))

    async def udp_client_worker(self, client: UdpClient, nat_port: int, is_v4: bool):
        while True:
            data, _, _ = await client.sessions()
            if is_v4:
                assert self.tun_next_ipv4
                self.ipv4_udp_listener.send(data, self.tun_next_ipv4, nat_port)
            else:
                assert self.tun_next_ipv6
                self.ipv6_udp_listener.send(data, self.tun_next_ipv6, nat_port)
