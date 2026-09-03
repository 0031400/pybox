import argparse
import asyncio
from .common.app import App


def main():
    parser = argparse.ArgumentParser(prog="pybox", description="A Network Tool")
    parser.add_argument(
        "-c", "--config", type=str, required=True, help="config file path"
    )
    args = parser.parse_args()
    app = App(args.config)
    asyncio.run(app.run())


if __name__ == "__main__":
    main()
