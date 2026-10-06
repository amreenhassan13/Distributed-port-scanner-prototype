"""
Unit tests for the Distributed Port Scanner (standard library `unittest`).

Run from the project folder:
    python -m unittest discover -s tests -v

These tests do NOT need Nmap to be installed: the real Nmap is replaced by tiny
"stand-in" classes, so we can force situations that are hard to create for
real (Nmap missing, host down, a crash inside Nmap...).
"""

import json
import os
import socket
import sys
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "worker"))
sys.path.insert(0, os.path.join(ROOT, "controller"))

import nmap  # noqa: E402  (python-nmap)
import controller  # noqa: E402
import worker  # noqa: E402


class FakeNmap:
    """Context manager that swaps nmap.PortScanner for a stand-in class."""

    def __init__(self, scanner_class):
        self.scanner_class = scanner_class

    def __enter__(self):
        self.real = nmap.PortScanner
        nmap.PortScanner = self.scanner_class

    def __exit__(self, *exc):
        nmap.PortScanner = self.real


def task(ip="127.0.0.1", ports="1-100"):
    return {"task_id": 1, "ip": ip, "ports": ports}


class WorkerScanTests(unittest.TestCase):
    def test_nmap_not_installed_gives_clear_error(self):
        class NoNmap:
            def __init__(self):
                raise nmap.PortScannerError("nmap program was not found in path")

        with FakeNmap(NoNmap):
            result = worker.scan_task(task(), "")
        self.assertEqual(result["status"], "error")
        self.assertIn("Install Nmap", result["error"])

    def test_no_host_answered_is_host_down(self):
        class Nobody:
            def scan(self, **kwargs):
                pass

            def all_hosts(self):
                return []

        with FakeNmap(Nobody):
            result = worker.scan_task(task("10.9.9.9"), "")
        self.assertEqual(result["status"], "host_down")
        self.assertEqual(result["open_ports"], [])

    def test_host_listed_but_down_is_host_down(self):
        class ListedDown:
            def scan(self, **kwargs):
                pass

            def all_hosts(self):
                return ["10.9.9.9"]

            def __getitem__(self, host):
                class Host:
                    def state(self):
                        return "down"

                return Host()

        with FakeNmap(ListedDown):
            result = worker.scan_task(task("10.9.9.9"), "")
        self.assertEqual(result["status"], "host_down")

    def test_only_open_ports_are_kept_with_service_names(self):
        class Mixed:
            def scan(self, **kwargs):
                pass

            def all_hosts(self):
                return ["127.0.0.1"]

            def __getitem__(self, host):
                class Host:
                    def state(self):
                        return "up"

                    def all_protocols(self):
                        return ["tcp"]

                    def __getitem__(self, proto):
                        return {
                            22: {"state": "open", "name": "ssh"},
                            23: {"state": "closed", "name": "telnet"},
                            25: {"state": "filtered", "name": "smtp"},
                            80: {"state": "open", "name": ""},
                        }

                return Host()

        with FakeNmap(Mixed):
            result = worker.scan_task(task(), "")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(
            result["open_ports"],
            [
                {"host": "127.0.0.1", "port": 22, "protocol": "tcp", "service": "ssh"},
                {"host": "127.0.0.1", "port": 80, "protocol": "tcp", "service": "unknown"},
            ],
        )

    def test_unexpected_exception_becomes_error_result(self):
        class Boom:
            def scan(self, **kwargs):
                raise RuntimeError("kaboom")

        with FakeNmap(Boom):
            result = worker.scan_task(task(), "")
        self.assertEqual(result["status"], "error")
        self.assertIn("kaboom", result["error"])

    def test_option_injection_is_refused(self):
        for ip, ports in [("--script=evil", "80"), ("127.0.0.1", "80 -oN x"), ("127.0.0.1; rm -rf /", "80")]:
            result = worker.scan_task(task(ip, ports), "")
            self.assertEqual(result["status"], "error", (ip, ports))
            self.assertIn("refused", result["error"])


class FramingTests(unittest.TestCase):
    def setUp(self):
        self.a, self.b = socket.socketpair()
        self.sender = controller.Channel(self.a)
        self.receiver = worker.Channel(self.b)

    def tearDown(self):
        self.a.close()
        self.b.close()

    def test_huge_message_arrives_intact(self):
        # ~6 MB. The old recv(8192) would have cut this after 8 KB.
        big = {"open_ports": [{"port": i, "service": "x" * 30} for i in range(60000)]}
        thread = threading.Thread(target=lambda: self.sender.send(big))
        thread.start()
        received = self.receiver.recv()
        thread.join()
        self.assertEqual(received, big)

    def test_two_messages_in_one_chunk(self):
        self.a.sendall(b'{"n":1}\n{"n":2}\n')
        self.assertEqual(self.receiver.recv(), {"n": 1})
        self.assertEqual(self.receiver.recv(), {"n": 2})

    def test_one_message_split_over_two_sends(self):
        self.a.sendall(b'{"n"')
        self.a.sendall(b":3}\n")
        self.assertEqual(self.receiver.recv(), {"n": 3})

    def test_closed_connection_raises(self):
        self.a.close()
        with self.assertRaises(ConnectionError):
            self.receiver.recv()


class ControllerHelperTests(unittest.TestCase):
    def test_split_ports(self):
        self.assertEqual(controller.split_ports("1-10,20", 4), ["1-4", "5-8", "9-10,20"])
        self.assertEqual(controller.split_ports("22,80", 0), ["22,80"])
        self.assertEqual(controller.split_ports("1-5", 100), ["1-5"])

    def test_bad_ports_are_rejected(self):
        for bad in ["0-10", "70000", "80-20", "abc", "22,,80", "1-2-3", ""]:
            with self.assertRaises(ValueError, msg=bad):
                controller.parse_ports(bad)

    def test_parse_target_forms(self):
        self.assertEqual(controller.parse_target("127.0.0.1:20-25"), ("127.0.0.1", "20-25"))
        self.assertEqual(controller.parse_target("10.0.0.5 22,80"), ("10.0.0.5", "22,80"))
        self.assertEqual(controller.parse_target("localhost"), ("localhost", "1-1024"))

    def test_private_address_guard(self):
        for ok in ["127.0.0.1", "localhost", "192.168.1.1-20", "10.0.0.0/24"]:
            self.assertTrue(controller.looks_private(ok), ok)
        for not_ok in ["8.8.8.8", "scanme.nmap.org"]:
            self.assertFalse(controller.looks_private(not_ok), not_ok)

    def test_targets_file_with_comments(self):
        path = os.path.join(HERE, "_tmp_targets.txt")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("# comment\n127.0.0.1 22,80\n\n127.0.0.1:1000-1100  # trailing comment\n")
        try:
            self.assertEqual(
                controller.load_targets_file(path),
                [("127.0.0.1", "22,80"), ("127.0.0.1", "1000-1100")],
            )
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
