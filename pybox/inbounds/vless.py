import asyncio
from ..utils.address import host_port, get_ip_port
from ..utils.network import relay, close_writer
import ipaddress


class VLessInbound:
    def __init__(self, uuids: list[str], listen_addr: str, listen_port: int) -> None:
        self.uuids = uuids
        self.listen_addr = listen_addr
        self.listen_port = listen_port

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        client_writer: asyncio.StreamWriter | None = None
        version = (await reader.readexactly(1))[0]
        if version != 0:
            await close_writer(writer)
            return
        uuid = (await reader.readexactly(16)).hex()
        if uuid not in self.uuids:
            await close_writer(writer)
            return
        protobuf_len = (await reader.readexactly(1))[0]
        if protobuf_len != 0:
            await close_writer(writer)
            return
        await reader.readexactly(protobuf_len)
        cmd = (await reader.readexactly(1))[0]
        if cmd != 1:
            await close_writer(writer)
            return
        port = int.from_bytes((await reader.readexactly(2)), "big")
        atyp = (await reader.readexactly(1))[0]
        address = ""
        if atyp == 1:
            addr_bytes = await reader.readexactly(4)
            address = str(ipaddress.IPv4Address(addr_bytes))
        elif atyp == 2:
            domain_len = (await reader.readexactly(1))[0]
            address = (await reader.readexactly(domain_len)).decode()
        elif atyp == 3:
            addr_bytes = await reader.readexactly(16)
            address = str(ipaddress.IPv6Address(addr_bytes))
        else:
            await close_writer(writer)
            return
        peername = writer.get_extra_info("peername")
        print(f"{host_port(*get_ip_port(peername))} -> {host_port(address,port)}")
        client_reader, client_writer = await asyncio.open_connection(address, port)
        await writer.drain()
        writer.write(bytes([0, 0]))
        task1 = asyncio.create_task(relay(client_reader, writer))
        task2 = asyncio.create_task(relay(reader, client_writer))
        done, pending = await asyncio.wait(
            [task1, task2], return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        client_writer.close()
        writer.close()
        await client_writer.wait_closed()
        await writer.wait_closed()

    async def run(self):
        server = await asyncio.start_server(
            self.handle_client, self.listen_addr, self.listen_port
        )
        for socket in server.sockets:
            print(f"socks5 listen on {host_port(*get_ip_port(socket.getsockname()))}")
        async with server:
            await server.serve_forever()
