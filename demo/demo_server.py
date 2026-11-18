#!/usr/bin/env python3
"""提供绑定本机回环地址的 HTTP 和 UDP 演示服务。"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import signal
import socket
import socketserver
import threading


class HttpHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = ("CourseSniffer EX1A\n"
                f"request_target: {self.path}\n"
                "HTTP response over loopback.\n").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("X-Course-Lab", "EX1A")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def log_message(self, format, *args):
        print("HTTP", self.client_address[0], format % args, flush=True)


class Http6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


class UdpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, connection = self.request
        connection.sendto(b"echo: " + data, self.client_address)


class UdpServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class Udp6Server(UdpServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


class DemoServers:
    def __init__(self, http_port=8080, udp_port=9999):
        self.servers = []
        self.threads = []
        specs = [
            (ThreadingHTTPServer, ("127.0.0.1", http_port), HttpHandler),
            (Http6Server, ("::1", http_port), HttpHandler),
            (UdpServer, ("127.0.0.1", udp_port), UdpHandler),
            (Udp6Server, ("::1", udp_port), UdpHandler),
        ]
        try:
            for cls, address, handler in specs:
                server = cls(address, handler)
                server.daemon_threads = True
                self.servers.append(server)
        except OSError:
            for server in self.servers:
                server.server_close()
            raise

    def start(self):
        for server in self.servers:
            thread = threading.Thread(target=server.serve_forever,
                                      kwargs={"poll_interval": 0.05}, daemon=True)
            thread.start()
            self.threads.append(thread)

    def close(self):
        for server in self.servers:
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=2)


def main():
    parser = argparse.ArgumentParser(description="本机 HTTP 与 UDP 演示服务")
    parser.add_argument("--duration", type=float, default=0,
                        help="自动结束前的运行秒数，零表示等待终止操作")
    args = parser.parse_args()
    stop = threading.Event()
    for sig in [signal.SIGINT, signal.SIGTERM]:
        signal.signal(sig, lambda signum, frame: stop.set())
    try:
        services = DemoServers()
    except OSError as error:
        parser.exit(1, f"演示服务启动失败：{error}\n请检查端口 8080、9999 和 IPv6 回环支持。\n")
    services.start()
    print("服务已启动：HTTP 8080，UDP 9999；绑定 127.0.0.1 和 ::1。", flush=True)
    try:
        stop.wait(args.duration if args.duration > 0 else None)
    finally:
        services.close()
    print("演示服务已经结束。")


if __name__ == "__main__":
    main()
