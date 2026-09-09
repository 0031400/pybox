import asyncio
import threading

import dns.message
import dns.rdatatype
from ..connections.connection import Connection
from ..dns.dns import DnsCenter, UdpSession
from ..dns.router import DnsRouteRule, DnsRouter
from ..inbounds.inbound import Inbound
from ..outbounds.outbound import Outbound
from .address import AddressType, DOMAIN_Address
from .log import log
from .router import Router
from .session import Session
from .sniff import sniff_tls_hostname
from dns.message import from_wire


class Core:
    def __init__(
        self,
        inbounds: list[Inbound],
        outbounds: dict[str, Outbound],
        router: Router,
        center: DnsCenter | None,
        dns_router: DnsRouter | None,
    ) -> None:
        self.inbounds = inbounds
        self.outbounds = outbounds
        self.router = router
        self.dns_center = center
        self.dns_router = dns_router
        self.tasks: list[asyncio.Task] = []

    async def start(self):
        # dns
        if self.dns_center:
            await self.dns_center.start()
            task = asyncio.create_task(self._dns_consume())
            self.tasks.append(task)
        for inbound in self.inbounds:
            task = asyncio.create_task(inbound.start())
            self.tasks.append(task)

    async def run(self):
        tasks: list[asyncio.Task] = []
        for inbound in self.inbounds:
            task = asyncio.create_task(self._consume(inbound))
            tasks.append(task)
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _consume(self, inbound: Inbound):
        tasks: list[asyncio.Task] = []
        while True:
            session = await inbound.sessions()
            task = asyncio.create_task(self._handle_session(session))
            tasks.append(task)

    async def _dns_consume(self):
        if not self.dns_center:
            return
        tasks: list[asyncio.Task] = []
        while True:
            session = await self.dns_center.sessions()
            task = asyncio.create_task(self._handle_dns_session(session))
            tasks.append(task)

    async def _handle_dns_session(self, session: UdpSession):
        if not self.dns_router or not self.dns_center:
            return
        domain = str(from_wire(session.data).question[0].name)
        tag = self.dns_router.route(domain)
        log("dns", f"{tag} <- {domain}")
        response_data = await self.dns_center.query(tag, session.data)
        response = dns.message.from_wire(response_data)
        ips: list[str] = []
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.CNAME:
                for rdata in rrset:
                    ips.append(str(rdata.target))
            if rrset.rdtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
                for rdata in rrset:
                    ips.append(str(rdata.address))
        log("dns", f"{domain} -> {tag} -> {','.join(ips)}")
        self.dns_center.send(UdpSession(response_data, session.ip, session.port))

    async def _handle_session(self, session: Session):
        hostname = sniff_tls_hostname(session.initial_data)
        if hostname and not isinstance(session.destination, DOMAIN_Address):
            log("sniff", f"{session.destination.authority()} -> {hostname}")
            session.destination = DOMAIN_Address(hostname, session.destination.port)
        outbound_tag = self.router.route(session.destination)
        outbound = self.outbounds.get(outbound_tag)
        if not outbound:
            raise RuntimeError("outbound not exist")
        log("route", f"{session.destination.authority()} -> {outbound_tag}")
        try:
            remote = await outbound.connect(session.destination, session.initial_data)
            await relay(session.connection, remote)
        except Exception:
            try:
                await session.connection.close()
            except (ConnectionError, OSError):
                pass


async def relay(left: Connection, right: Connection):
    async def forward(source: Connection, target: Connection):
        while True:
            data = await source.read(4096)
            if not data:
                break
            await target.write(data)

    task1 = asyncio.create_task(forward(left, right))
    task2 = asyncio.create_task(forward(right, left))
    done, pending = await asyncio.wait(
        [task1, task2], return_when=asyncio.FIRST_COMPLETED
    )
    for task in pending:
        task.cancel()
    await asyncio.gather(*done, return_exceptions=True)
    await left.close()
    await right.close()
