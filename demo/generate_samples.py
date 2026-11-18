#!/usr/bin/env python3
"""构造可重复的 Ethernet PCAP 演示样例。"""
import ipaddress
from pathlib import Path
import struct


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def ipv4(payload, protocol, reverse=False):
    source, destination = ("127.0.0.1", "127.0.0.2")
    if reverse:
        source, destination = destination, source
    addresses = ipaddress.ip_address(source).packed + ipaddress.ip_address(destination).packed
    header = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(payload), 1, 0x4000, 64, protocol, 0) + addresses
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00" + header + payload


def tcp(sequence, acknowledgement, flags, payload=b"", reverse=False):
    source, destination = (51000, 8080) if not reverse else (8080, 51000)
    header = struct.pack("!HHIIBBHHH", source, destination, sequence, acknowledgement, 0x50, flags, 65535, 0, 0)
    a, b = ("127.0.0.1", "127.0.0.2") if not reverse else ("127.0.0.2", "127.0.0.1")
    pseudo = ipaddress.ip_address(a).packed + ipaddress.ip_address(b).packed + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    header = header[:16] + struct.pack("!H", checksum(pseudo + header + payload)) + header[18:]
    return ipv4(header + payload, 6, reverse)


def packets():
    request = b"GET /lab HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: CourseSniffer-Demo\r\nConnection: close\r\n\r\n"
    body = b"CourseSniffer EX1A demonstration\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body
    data = [tcp(1000, 0, 0x02), tcp(7000, 1001, 0x12, reverse=True), tcp(1001, 7001, 0x10)]
    data += [tcp(1001, 7001, 0x18, request[:23]), tcp(1024, 7001, 0x18, request[23:])]
    data += [tcp(7001, 1001 + len(request), 0x18, response, True)]
    data += [tcp(7001, 1001 + len(request), 0x18, response, True)]
    data += [tcp(7001 + len(response), 1001 + len(request), 0x11, reverse=True),
             tcp(1001 + len(request), 7002 + len(response), 0x11),
             tcp(7002 + len(response), 1002 + len(request), 0x10, reverse=True)]
    udp_body = b"CourseSniffer IPv4 UDP"
    data.append(ipv4(struct.pack("!HHHH", 53000, 9999, 8 + len(udp_body), 0) + udp_body, 17))
    icmp = struct.pack("!BBHHH", 8, 0, 0, 2026, 1) + b"EX1A"
    icmp = icmp[:2] + struct.pack("!H", checksum(icmp)) + icmp[4:]
    data.append(ipv4(icmp, 1))
    source = ipaddress.ip_address("::1").packed
    dest = ipaddress.ip_address("::2").packed
    payload = struct.pack("!HHHH", 54000, 9999, 12, 0) + b"IPv6"
    check = checksum(source + dest + struct.pack("!I3xB", len(payload), 17) + payload)
    payload = payload[:6] + struct.pack("!H", check) + payload[8:]
    data.append(bytes.fromhex("02000000000202000000000186dd") + struct.pack("!IHBB", 6 << 28, len(payload), 17, 64) + source + dest + payload)
    return data


def main():
    path = Path(__file__).with_name("sample.pcap")
    with path.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for index, packet in enumerate(packets()):
            stream.write(struct.pack("<IIII", 1794960000, index * 25000, len(packet), len(packet)))
            stream.write(packet)
    print(f"已生成 {path.name}，包含 {len(packets())} 个构造报文。")


if __name__ == "__main__":
    main()
