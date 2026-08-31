import asyncio
from ..utils.address import host_port, get_ip_port
from ..utils.network import close_writer, relay
import ipaddress


class Socks5:
    def __init__(
        self, users: dict[str, str], listen_addr: str, listen_port: int
    ) -> None:
        self.users = users
        self.listen_addr = listen_addr
        self.listen_port = listen_port

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        client_writer: asyncio.StreamWriter | None = None
        try:
            peername = writer.get_extra_info("peername")
            version = (await reader.readexactly(1))[0]
            if version != 5:
                await close_writer(writer)
                return
            auth_methods_len = (await reader.readexactly(1))[0]
            auth_methods_bytes = await reader.readexactly(auth_methods_len)
            choosed_auth = -1
            if len(self.users) == 0:
                for auth_method in auth_methods_bytes:
                    if auth_method == 0:
                        choosed_auth = 0
                        break
            else:
                for auth_method in auth_methods_bytes:
                    if auth_method == 2:
                        choosed_auth = 2
                        break
            auth_ok = False
            if choosed_auth == 0:
                auth_ok = True
            elif choosed_auth == 2:
                writer.write(bytes([5, 2]))
                await writer.drain()
                version = (await reader.readexactly(1))[0]
                if version != 1:
                    await close_writer(writer)
                    return
                username_len = (await reader.readexactly(1))[0]
                username = (await reader.readexactly(username_len)).decode()
                password_len = (await reader.readexactly(1))[0]
                password = (await reader.readexactly(password_len)).decode()
                if self.users.get(username) == password:
                    auth_ok = True
            else:
                writer.write(bytes([5, 255]))
                await writer.drain()
                await close_writer(writer)
                return

            if auth_ok:
                writer.write(bytes([5, 0]))
                await writer.drain()
            else:
                writer.write(bytes([5, 1]))
                await writer.drain()
                await close_writer(writer)
                return
            version = (await reader.readexactly(1))[0]
            if version != 5:
                raise RuntimeError("version error")
            cmd = (await reader.readexactly(1))[0]
            if cmd != 1:
                raise RuntimeError("cmd error")
            rsv = (await reader.readexactly(1))[0]
            if rsv != 0:
                raise RuntimeError("rsv error")
            atyp = (await reader.readexactly(1))[0]
            address = ""
            if atyp == 1:
                addr_bytes = await reader.readexactly(4)
                address = str(ipaddress.IPv4Address(addr_bytes))
            elif atyp == 3:
                domain_len = (await reader.readexactly(1))[0]
                address = (await reader.readexactly(domain_len)).decode()
            elif atyp == 4:
                addr_bytes = await reader.readexactly(16)
                address = str(ipaddress.IPv6Address(addr_bytes))
            else:
                raise RuntimeError("atyp error")
            port = int.from_bytes((await reader.readexactly(2)), "big")
            print(f"{host_port(*get_ip_port(peername))} -> {host_port(address,port)}")
            client_reader, client_writer = await asyncio.open_connection(address, port)
            writer.write(bytes([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]))
            await writer.drain()
            task1 = asyncio.create_task(relay(client_reader, writer))
            task2 = asyncio.create_task(relay(reader, client_writer))
            done, pending = await asyncio.wait(
                [task1, task2], return_when=asyncio.FIRST_COMPLETED
            )
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            await asyncio.gather(close_writer(writer), close_writer(client_writer))

        except Exception as e:
            print(f"errror: {e}")
            writer.close()
            await writer.wait_closed()
            if client_writer is not None:
                client_writer.close()
                await client_writer.wait_closed()

    async def run(self):
        server = await asyncio.start_server(
            self.handle_client, self.listen_addr, self.listen_port
        )
        for socket in server.sockets:
            print(f"socks5 listen on {host_port(*get_ip_port(socket.getsockname()))}")
        async with server:
            await server.serve_forever()
