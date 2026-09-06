import ipaddress
import subprocess


def run_command(command: list[str]):
    print(" ".join(command))
    return subprocess.run(command, capture_output=True).returncode == 0


def add_ipv4_address(tun_name: str, ip: ipaddress.IPv4Address):
    return run_command(
        [
            "netsh",
            "interface",
            "ipv4",
            "set",
            "address",
            "name=" + tun_name,
            "static",
            str(ip),
            "255.255.255.0",
        ]
    )


def set_route(tun_name: str, ip: ipaddress.IPv4Address):
    return run_command(
        [
            "netsh",
            "interface",
            "ipv4",
            "add",
            "route",
            "220.181.111.232/32",
            tun_name,
            str(ip),
        ]
    )
