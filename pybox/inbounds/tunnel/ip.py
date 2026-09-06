import ipaddress
import struct

from .nat import FlowKey


def parse_tcp_ipv4(packet: bytes | bytearray) -> FlowKey | None:
    if len(packet) < 20:
        return None
    if (packet[0] >> 4) != 4:
        return None
    if packet[9] != 6:
        return None
    ip_header_len = (packet[0] & 0x0F) * 4
    if len(packet) < ip_header_len + 20:
        return None
    src_ip = ipaddress.IPv4Address(packet[12:16])
    dst_ip = ipaddress.IPv4Address(packet[16:20])
    src_port, dst_port = struct.unpack_from(
        "!HH",
        packet,
        ip_header_len,
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
    ip_header_len = (packet[0] & 0x0F) * 4
    packet[12:16] = src_ip.packed
    packet[16:20] = dst_ip.packed
    struct.pack_into(
        "!HH",
        packet,
        ip_header_len,
        src_port,
        dst_port,
    )


def checksum(data: bytes | bytearray) -> int:
    if len(data) & 1:
        data += b"\x00"

    total = 0

    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]

    # 把高 16 位不断加回低 16 位
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def update_ipv4_checksum(packet: bytearray) -> None:
    ihl = (packet[0] & 0x0F) * 4

    # checksum 字段先清零
    packet[10:12] = b"\x00\x00"

    # 重新计算整个 IPv4 Header
    csum = checksum(packet[:ihl])

    struct.pack_into("!H", packet, 10, csum)


def update_tcp_checksum(packet: bytearray) -> None:
    ihl = (packet[0] & 0x0F) * 4

    tcp_offset = ihl

    # TCP Data Offset，单位是 4 bytes
    tcp_header_len = ((packet[tcp_offset + 12] >> 4) & 0x0F) * 4

    # TCP 总长度 = IPv4 total length - IP header length
    total_length = struct.unpack_from("!H", packet, 2)[0]
    tcp_length = total_length - ihl

    # TCP checksum 在 TCP header + 16
    checksum_offset = tcp_offset + 16

    # checksum 清零
    packet[checksum_offset : checksum_offset + 2] = b"\x00\x00"

    # pseudo header
    pseudo_header = (
        bytes(packet[12:16])
        + bytes(packet[16:20])
        + bytes(
            [
                0,
                packet[9],  # protocol = 6
            ]
        )
        + struct.pack("!H", tcp_length)
    )

    # TCP header + payload
    tcp_data = packet[tcp_offset : tcp_offset + tcp_length]

    csum = checksum(pseudo_header + tcp_data)

    struct.pack_into(
        "!H",
        packet,
        checksum_offset,
        csum,
    )


def update_udp_checksum(packet: bytearray) -> None:
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
                packet[9],  # protocol = 17
            ]
        )
        + struct.pack("!H", udp_length)
    )

    udp_data = packet[udp_offset : udp_offset + udp_length]

    csum = checksum(pseudo_header + udp_data)

    # UDP IPv4 checksum 计算结果为 0 时，
    # 发送时应该写成 0xFFFF
    if csum == 0:
        csum = 0xFFFF

    struct.pack_into(
        "!H",
        packet,
        checksum_offset,
        csum,
    )
