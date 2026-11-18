#!/usr/bin/env python3
"""产生实际的本机 IPv4、IPv6、HTTP 和 UDP 通信。"""
import argparse
import http.client
import socket


def send_requests(http_port=8080, udp_port=9999, repeat=1):
    results = []
    for iteration in range(repeat):
        for family, host, label in [(socket.AF_INET, "127.0.0.1", "IPv4"),
                                    (socket.AF_INET6, "::1", "IPv6")]:
            connection = http.client.HTTPConnection(host, http_port, timeout=3)
            try:
                connection.request("GET", f"/lab?family={label}&request={iteration + 1}",
                                   headers={"Connection": "close", "User-Agent": "CourseSniffer-Demo/1.0"})
                response = connection.getresponse()
                content = response.read()
                if response.status != 200 or b"CourseSniffer EX1A" not in content:
                    raise RuntimeError(f"{label} HTTP 响应未通过检查")
                results.append(f"{label} HTTP 200，正文 {len(content)} 字节")
            finally:
                connection.close()
            with socket.socket(family, socket.SOCK_DGRAM) as channel:
                channel.settimeout(3)
                message = f"CourseSniffer {label} UDP {iteration + 1}".encode()
                channel.sendto(message, (host, udp_port))
                reply, _ = channel.recvfrom(4096)
                if reply != b"echo: " + message:
                    raise RuntimeError(f"{label} UDP 响应未通过检查")
                results.append(f"{label} UDP 回应，长度 {len(reply)} 字节")
    return results


def main():
    parser = argparse.ArgumentParser(description="产生本机演示通信")
    parser.add_argument("--repeat", type=int, default=1)
    args = parser.parse_args()
    if not 1 <= args.repeat <= 100:
        parser.error("重复次数需要在 1 至 100 之间。")
    try:
        for line in send_requests(repeat=args.repeat):
            print(line)
    except (OSError, RuntimeError) as error:
        parser.exit(1, f"演示请求失败：{error}\n请确认 demo_server.py 已经运行。\n")


if __name__ == "__main__":
    main()
