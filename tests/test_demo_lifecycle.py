"""检查演示服务在部分启动失败时能够完成关闭。"""
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "demo"))
from demo_server import DemoServers


class DemoLifecycleTests(unittest.TestCase):
    def test_unstarted_services_release_ports(self):
        services = DemoServers(http_port=0, udp_port=0)
        sockets = [server.socket for server in services.servers]
        services.close()
        self.assertTrue(all(channel.fileno() == -1 for channel in sockets))

    def test_partial_thread_start_failure_closes_started_and_unstarted_servers(self):
        services = DemoServers(http_port=0, udp_port=0)
        sockets = [server.socket for server in services.servers]
        original = threading.Thread.start
        attempts = 0

        def start(thread):
            nonlocal attempts
            attempts += 1
            if attempts == 2:
                raise RuntimeError("controlled thread start failure")
            return original(thread)

        try:
            with patch.object(threading.Thread, "start", start):
                with self.assertRaises(RuntimeError):
                    services.start()
            running = list(services.threads)
        finally:
            services.close()
        self.assertTrue(all(not thread.is_alive() for thread in running))
        self.assertTrue(all(channel.fileno() == -1 for channel in sockets))
        services.close()


if __name__ == "__main__":
    unittest.main()
