import argparse
import asyncio
import ipaddress

from .inbounds.socks5 import Socks5
from .inbounds.vless import VLess


class App:
    def __init__(self) -> None:
        pass

    async def run(self):
        socks5 = Socks5({}, "localhost", 4000)
        vless = VLess(["04e5d30d-7ccb-49b3-ad5f-4b07d45d8dfd".replace('-','')], "localhost", 3000)
        await asyncio.gather(socks5.run(),vless.run())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--address", type=str, default="localhost", help="listen address"
    )
    parser.add_argument("--port", type=int, default=3000, help="listen port")
    args = parser.parse_args()
    app = App()
    asyncio.run(app.run())


if __name__ == "__main__":
    main()
