#!/usr/bin/env python3
"""启动本机服务、发送演示请求并完整关闭服务。"""
import argparse
from demo_server import DemoServers
from demo_client import send_requests


def main():
    parser = argparse.ArgumentParser(description="执行本机演示通信")
    parser.add_argument("--repeat", type=int, default=3)
    args = parser.parse_args()
    if not 1 <= args.repeat <= 100:
        parser.error("重复次数需要在 1 至 100 之间。")
    services = None
    try:
        services = DemoServers()
        services.start()
        for line in send_requests(repeat=args.repeat):
            print(line)
        print("全部本机请求通过检查。")
    except (OSError, RuntimeError) as error:
        parser.exit(1, f"演示通信失败：{error}\n请检查 8080、9999 端口是否空闲。\n")
    finally:
        if services:
            services.close()


if __name__ == "__main__":
    main()
