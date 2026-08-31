import ipaddress


def host_port(host: str, port: int) -> str:
    try:
        ip = ipaddress.ip_address(host)
        if ip.version == 6:
            return f"[{host}]:{port}"
        else:
            return f"{host}:{port}"
    except ValueError:
        return f"{host}:{port}"


def get_ip_port(address: tuple)->tuple[str,int]:
    return address[0], address[1]
