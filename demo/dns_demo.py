#!/usr/bin/env python3
"""为回环演示提供 example.test 的固定 DNS 问答。"""
import socket
import struct


QNAME = b"\x07example\x04test\x00"
ANSWERS = {1: socket.inet_pton(socket.AF_INET, "192.0.2.123"),
           28: socket.inet_pton(socket.AF_INET6, "2001:db8::123")}


def make_query(identifier, qtype):
    return struct.pack("!6H", identifier, 0x0100, 1, 0, 0, 0) + QNAME + struct.pack("!HH", qtype, 1)


def make_response(data):
    if len(data) != 12 + len(QNAME) + 4:
        return None
    identifier, flags, questions, answers, authority, additional = struct.unpack("!6H", data[:12])
    if flags & 0xf800 or questions != 1 or answers or authority or additional:
        return None
    if data[12:-4] != QNAME:
        return None
    qtype, qclass = struct.unpack("!HH", data[-4:])
    if qtype not in ANSWERS or qclass != 1:
        return None
    content = ANSWERS[qtype]
    header = struct.pack("!6H", identifier, 0x8400 | (flags & 0x0100), 1, 1, 0, 0)
    answer = struct.pack("!HHHIH", 0xc00c, qtype, 1, 60, len(content)) + content
    return header + data[12:] + answer


def send_dns(family, host, port=53):
    results = []
    for qtype in (1, 28):
        identifier = 0x1a00 + qtype
        request = make_query(identifier, qtype)
        with socket.socket(family, socket.SOCK_DGRAM) as channel:
            channel.settimeout(3)
            channel.connect((host, port))
            channel.send(request)
            response = channel.recv(4096)
        if len(response) < 12:
            raise RuntimeError("DNS 响应长度不足")
        rid, flags, questions, answers, authority, additional = struct.unpack("!6H", response[:12])
        if rid != identifier or not flags & 0x8000 or flags & 0x000f or (questions, answers, authority, additional) != (1, 1, 0, 0):
            raise RuntimeError("DNS 响应头部未通过检查")
        expected = ANSWERS[qtype]
        offset = 12 + len(QNAME) + 4
        if len(response) != offset + 12 + len(expected):
            raise RuntimeError("DNS 响应记录长度未通过检查")
        name, kind, record_class, ttl, length = struct.unpack("!HHHIH", response[offset:offset + 12])
        if (name, kind, record_class, length) != (0xc00c, qtype, 1, len(expected)) or response[-length:] != expected:
            raise RuntimeError("DNS 响应记录内容未通过检查")
        results.append("DNS example.test " + ("A 192.0.2.123" if qtype == 1 else "AAAA 2001:db8::123"))
    return results
