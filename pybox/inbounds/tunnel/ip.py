import ipaddress
import struct

from .nat import FlowKey


def is_ipv4(packet: bytes | bytearray) -> bool:
    return 4 == packet[0] >> 4 and len(packet) >= 20


def is_ipv6(packet: bytes | bytearray) -> bool:
    return 6 == packet[0] >> 4 and len(packet) >= 40


def is_ipv4_tcp(packet: bytes | bytearray) -> bool:
    ihl = (packet[0] & 0x0F) * 4
    return len(packet) >= ihl + 20 and 6 == packet[9]


def is_udp(packet: bytes | bytearray) -> bool:
    return 17 == packet[9]


def parse_tcp_ipv4(packet: bytes | bytearray) -> FlowKey | None:
    src_ip = ipaddress.IPv4Address(bytes(packet[12:16]))
    dst_ip = ipaddress.IPv4Address(bytes(packet[16:20]))
    ihl = (packet[0] & 0x0F) * 4
    src_port, dst_port = struct.unpack_from(
        "!HH",
        packet,
        ihl,
    )
    return FlowKey(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
    )


def replace_ipv4_flow(
    packet: bytearray,
    src_ip: ipaddress.IPv4Address,
    dst_ip: ipaddress.IPv4Address,
    src_port: int,
    dst_port: int,
):
    ihl = (packet[0] & 0x0F) * 4
    packet[12:16] = src_ip.packed
    packet[16:20] = dst_ip.packed
    struct.pack_into(
        "!HH",
        packet,
        ihl,
        src_port,
        dst_port,
    )


def checksum(data: bytes | bytearray) -> int:
    if len(data) & 1:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def update_ipv4_checksum(packet: bytearray) -> None:
    ihl = (packet[0] & 0x0F) * 4
    packet[10:12] = b"\x00\x00"
    csum = checksum(packet[:ihl])
    struct.pack_into("!H", packet, 10, csum)


def update_ipv4_tcp_checksum(packet: bytearray) -> None:
    ihl = (packet[0] & 0x0F) * 4
    tcp_offset = ihl
    total_length = struct.unpack_from("!H", packet, 2)[0]
    tcp_length = total_length - ihl
    checksum_offset = tcp_offset + 16
    packet[checksum_offset : checksum_offset + 2] = b"\x00\x00"
    pseudo_header = (
        bytes(packet[12:16])
        + bytes(packet[16:20])
        + bytes(
            [
                0,
                packet[9],
            ]
        )
        + struct.pack("!H", tcp_length)
    )
    tcp_data = packet[tcp_offset : tcp_offset + tcp_length]
    csum = checksum(pseudo_header + tcp_data)
    struct.pack_into(
        "!H",
        packet,
        checksum_offset,
        csum,
    )


def update_ipv4_udp_checksum(packet: bytearray) -> None:
    ihl = (packet[0] & 0x0F) * 4
    udp_offset = ihl
    udp_length = struct.unpack_from(
        "!H",
        packet,
        udp_offset + 4,
    )[0]
    checksum_offset = udp_offset + 6
    packet[checksum_offset : checksum_offset + 2] = b"\x00\x00"
    pseudo_header = (
        bytes(packet[12:16])
        + bytes(packet[16:20])
        + bytes(
            [
                0,
                packet[9],
            ]
        )
        + struct.pack("!H", udp_length)
    )
    udp_data = packet[udp_offset : udp_offset + udp_length]
    csum = checksum(pseudo_header + udp_data)
    if csum == 0:
        csum = 0xFFFF
    struct.pack_into(
        "!H",
        packet,
        checksum_offset,
        csum,
    )
