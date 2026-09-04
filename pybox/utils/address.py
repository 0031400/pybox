import ipaddress


def format_socket_address(address:dict) -> str:
    try:
        ip = ipaddress.ip_address(address[0])
        if ip.version==6:
            return f"[{address[0]}]:{address[1]}"
        else:
            return f"[{address[0]}]:{address[1]}"
    except ValueError:
        return f"{address[0]}:{address[1]}"