import ipaddress
import subprocess

import ctypes
from ctypes import WinDLL, wintypes
import ipaddress

NET_LUID = ctypes.c_uint64
NET_IFINDEX = wintypes.ULONG
NL_PREFIX_ORIGIN = ctypes.c_int
NL_SUFFIX_ORIGIN = ctypes.c_int
NL_DAD_STATE = ctypes.c_int


class IN_ADDR(ctypes.Union):
    _fields_ = [
        ("S_addr", wintypes.ULONG),
    ]


class SOCKADDR_IN(ctypes.Structure):
    _fields_ = [
        ("sin_family", wintypes.USHORT),
        ("sin_port", wintypes.USHORT),
        ("sin_addr", IN_ADDR),
        ("sin_zero", ctypes.c_char * 8),
    ]


class IN6_ADDR(ctypes.Union):
    _fields_ = [
        ("Byte", ctypes.c_ubyte * 16),
        ("Word", ctypes.c_ushort * 8),
    ]


class SOCKADDR_IN6(ctypes.Structure):
    _fields_ = [
        ("sin6_family", wintypes.USHORT),
        ("sin6_port", wintypes.USHORT),
        ("sin6_flowinfo", wintypes.ULONG),
        ("sin6_addr", IN6_ADDR),
        ("sin6_scope_id", wintypes.ULONG),
    ]


class SOCKADDR_INET(ctypes.Union):
    _fields_ = [
        ("Ipv4", SOCKADDR_IN),
        ("Ipv6", SOCKADDR_IN6),
    ]


class SCOPE_ID(ctypes.Union):
    _fields_ = [
        ("Value", wintypes.ULONG),
    ]


LARGE_INTEGER = ctypes.c_int64


class MIB_UNICASTIPADDRESS_ROW(ctypes.Structure):
    _fields_ = [
        ("Address", SOCKADDR_INET),
        ("InterfaceLuid", NET_LUID),
        ("InterfaceIndex", NET_IFINDEX),
        ("PrefixOrigin", NL_PREFIX_ORIGIN),
        ("SuffixOrigin", NL_SUFFIX_ORIGIN),
        ("ValidLifetime", wintypes.ULONG),
        ("PreferredLifetime", wintypes.ULONG),
        ("OnLinkPrefixLength", ctypes.c_ubyte),
        ("SkipAsSource", wintypes.BOOLEAN),
        ("DadState", NL_DAD_STATE),
        ("ScopeId", SCOPE_ID),
        ("CreationTimeStamp", LARGE_INTEGER),
    ]


AF_INET = 2
IpPrefixOriginOther = 0
IpPrefixOriginManual = 1

IpSuffixOriginOther = 0
IpSuffixOriginManual = 1

IpDadStateInvalid = 0
IpDadStateTentative = 1
IpDadStateDuplicate = 2
IpDadStateDeprecated = 3
IpDadStatePreferred = 4

INFINITE = 0xFFFFFFFF


def create_ipv4_address(
    luid: int,
    address:  ipaddress.IPv4Address,
    prefix_length: int,
):
    row = MIB_UNICASTIPADDRESS_ROW()
    row.InterfaceLuid = luid
    row.InterfaceIndex = 0
    row.Address.Ipv4.sin_family = AF_INET
    row.Address.Ipv4.sin_port = 0
    row.Address.Ipv4.sin_addr.S_addr = int.from_bytes(
        address.packed,
        "little",
    )
    row.Address.Ipv4.sin_zero = b"\x00" * 8
    row.PrefixOrigin = IpPrefixOriginManual
    row.SuffixOrigin = IpSuffixOriginManual
    row.ValidLifetime = INFINITE
    row.PreferredLifetime = INFINITE
    row.OnLinkPrefixLength = prefix_length
    row.SkipAsSource = False
    row.DadState = IpDadStatePreferred
    row.ScopeId.Value = 0
    row.CreationTimeStamp = 0
    iphlpapi = WinDLL("iphlpapi.dll")
    ret = iphlpapi.CreateUnicastIpAddressEntry(ctypes.byref(row))
    if ret != 0:
        raise ctypes.WinError(ret)


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
            "0.0.0.0/0",
            tun_name,
            str(ip),
            "metric=20",
        ]
    )


def set_dns(tun_name: str):
    return run_command(
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
