import ipaddress
import subprocess

import ctypes
import ipaddress

from ...common.log import log


class IN_ADDR(ctypes.Union):
    _fields_ = [
        ("S_addr", ctypes.c_ulong),
        ("S_un_b", ctypes.c_ubyte * 4),
        ("S_un_w", ctypes.c_ushort * 2),
    ]


class SOCKADDR_IN(ctypes.Structure):
    _fields_ = [
        ("sin_family", ctypes.c_ushort),
        ("sin_port", ctypes.c_ushort),
        ("sin_addr", IN_ADDR),
        ("sin_zero", ctypes.c_ubyte * 8),
    ]


class IN6_ADDR(ctypes.Union):
    _fields_ = [
        ("Byte", ctypes.c_ubyte * 16),
        ("Word", ctypes.c_ushort * 8),
    ]


class SOCKADDR_IN6(ctypes.Structure):
    _fields_ = [
        ("sin6_family", ctypes.c_ushort),
        ("sin6_port", ctypes.c_ushort),
        ("sin6_flowinfo", ctypes.c_ulong),
        ("sin6_addr", IN6_ADDR),
        ("sin6_scope_id", ctypes.c_ulong),
    ]


class SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = [
        ("lpSockaddr", ctypes.c_void_p),
        ("iSockaddrLength", ctypes.c_int),
    ]


class SOCKADDR_INET(ctypes.Union):
    _fields_ = [
        ("Ipv4", SOCKADDR_IN),
        ("Ipv6", SOCKADDR_IN6),
        ("si_family", ctypes.c_ushort),
    ]


class MIB_UNICASTIPADDRESS_ROW(ctypes.Structure):
    _fields_ = [
        ("Address", SOCKADDR_INET),
        ("InterfaceLuid", ctypes.c_ulonglong),
        ("InterfaceIndex", ctypes.c_ulong),
        ("PrefixOrigin", ctypes.c_int),
        ("SuffixOrigin", ctypes.c_int),
        ("ValidLifetime", ctypes.c_ulong),
        ("PreferredLifetime", ctypes.c_ulong),
        ("OnLinkPrefixLength", ctypes.c_ubyte),
        ("SkipAsSource", ctypes.c_ubyte),
        ("DadState", ctypes.c_int),
        ("ScopeId", ctypes.c_ulong),
        ("CreationTimeStamp", ctypes.c_ulonglong),
    ]


def create_ipv4_address(luid: int, ip: ipaddress.IPv4Address, prefix_length: int = 24):
    _iphlpapi = ctypes.WinDLL("iphlpapi.dll")

    _iphlpapi.CreateUnicastIpAddressEntry.argtypes = [
        ctypes.POINTER(MIB_UNICASTIPADDRESS_ROW),
    ]
    _iphlpapi.CreateUnicastIpAddressEntry.restype = ctypes.c_ulong
    _iphlpapi.InitializeUnicastIpAddressEntry.argtypes = [
        ctypes.POINTER(MIB_UNICASTIPADDRESS_ROW),
    ]
    _iphlpapi.InitializeUnicastIpAddressEntry.restype = None
    row = MIB_UNICASTIPADDRESS_ROW()
    # _iphlpapi.InitializeUnicastIpAddressEntry(ctypes.byref(row))
    row.Address.Ipv4.sin_family = 2
    row.Address.Ipv4.sin_port = 0
    row.Address.Ipv4.sin_addr.S_un_b[:] = ip.packed
    row.Address.Ipv4.sin_zero[:] = b"\x00" * 8
    row.InterfaceLuid = ctypes.c_ulonglong(luid)
    row.InterfaceIndex = 0
    row.PrefixOrigin = 1
    row.SuffixOrigin = 1
    row.ValidLifetime = 0xFFFFFFFF
    row.PreferredLifetime = 0xFFFFFFFF
    row.OnLinkPrefixLength = prefix_length
    row.SkipAsSource = False
    row.DadState = 4
    row.ScopeId = 0
    row.CreationTimeStamp = 0
    error = _iphlpapi.CreateUnicastIpAddressEntry(ctypes.byref(row))

    if error:
        raise RuntimeError(
            error,
            f"fail to set ip",
        )


def run_command(command: list[str]):
    log("cmd", f"<- {' '.join(command)}")
    task = subprocess.run(command, capture_output=True, text=True)
    if task.stdout:
        log("cmd out", f"-> {task.stdout}")
    if task.stderr:
        log("cmd err", f"-> {task.stderr}")
    return task.returncode == 0


def set_route(tun_name: str, ip: ipaddress.IPv4Address):
    return run_command(
        [
            "netsh",
            "interface",
            "ipv4",
            "add",
            "route",
            "0.0.0.0/0",
            tun_name,
            str(ip),
            "metric=20",
        ]
    )


def set_dns(tun_name: str):
    subprocess.Popen(
        [
            "netsh",
            "interface",
            "ip",
            "set",
            "dns",
            "name=" + tun_name,
            "static",
            "127.0.0.1",
        ]
    )
