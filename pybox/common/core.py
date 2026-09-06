import asyncio

import dns.message
import dns.rdatatype
from ..connections.connection import Connection
from ..dns.dns import DnsCenter, DnsSession
from ..dns.router import DnsRouteRule, DnsRouter
from ..inbounds.inbound import Inbound
from ..outbounds.outbound import Outbound
from .address import AddressType, DOMAIN_Address
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

    async def start(self):
        # dns
        if self.dns_center:
            await self.dns_center.start()
            asyncio.create_task(self._dns_consume())
        for inbound in self.inbounds:
            asyncio.create_task(inbound.start())

    async def run(self):
        tasks = [
            asyncio.create_task(self._consume(inbound)) for inbound in self.inbounds
        ]
        await asyncio.gather(*tasks)

    async def _consume(self, inbound: Inbound):
        while True:
            session = await inbound.sessions()
            asyncio.create_task(self._handle_session(session))

    async def _dns_consume(self):
        if not self.dns_center:
            return
        while True:
            session = await self.dns_center.sessions()
            asyncio.create_task(self._handle_dns_session(session))

    async def _handle_dns_session(self, session: DnsSession):
        if not self.dns_router or not self.dns_center:
            return
        domain = str(from_wire(session.request).question[0].name)
        tag = self.dns_router.route(domain)
        response_data = await self.dns_center.query(tag, session.request)
        response = dns.message.from_wire(response_data)
        ips: list[str] = []
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.CNAME:
                for rdata in rrset:
                    ips.append(str(rdata.target))
            if rrset.rdtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
                for rdata in rrset:
                    ips.append(str(rdata.address))

        print(f"[dns] {domain} -> {','.join(ips)}")
        await self.dns_center.send(response_data, (str(session.ip), session.port))

    async def _handle_session(self, session: Session):
        hostname = sniff_tls_hostname(session.initial_data)
        if hostname and not isinstance(session.destination, DOMAIN_Address):
            print(f"[sniff] {session.destination.authority()} -> {hostname}")
            session.destination = DOMAIN_Address(hostname, session.destination.port)
        outbound_tag = self.router.route(session.destination)
        outbound = self.outbounds.get(outbound_tag)
        if not outbound:
            raise RuntimeError("outbound not exist")
        print(f"[route] {session.destination.authority()} -> {outbound_tag}")
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
