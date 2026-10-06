#!/usr/bin/env python3
"""
One-command demo of the Distributed Port Scanner (all on localhost, safe).

What it does:
    1. Opens a few harmless fake "services" on 127.0.0.1 so the scan has
       something to find (otherwise a clean laptop has almost no open ports).
    2. Starts the controller and N workers as separate processes.
    3. Lets you watch the live log, the summary and the timeline.

Try:
    python demo.py                 # 3 workers, normal run
    python demo.py --workers 1     # same work, one worker (compare the timeline!)
    python demo.py --crash         # worker-2 dies mid-task -> task is re-queued and finished by another worker
    python demo.py --hang          # worker-2 stops answering -> controller times out -> task re-queued
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CONTROLLER = os.path.join(HERE, "controller", "controller.py")
WORKER = os.path.join(HERE, "worker", "worker.py")

# Ports (all > 1024 so no admin rights are needed) and what Nmap will call them.
FAKE_SERVICE_PORTS = [1080, 1099, 1194, 1433, 1521, 1723]


class FakeServices:
    """Listens on a few localhost ports and immediately closes any connection."""

    def __init__(self, ports):
        self.requested = ports
        self.opened = []
        self._sockets = []
        self._stop = threading.Event()

    def start(self):
        for port in self.requested:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.bind(("127.0.0.1", port))
                sock.listen()
            except OSError:
                sock.close()  # port already used by something else - fine, skip it
                continue
            sock.settimeout(0.3)
            self._sockets.append(sock)
            self.opened.append(port)
            threading.Thread(target=self._serve, args=(sock,), daemon=True).start()
        return self

    def _serve(self, sock):
        while not self._stop.is_set():
            try:
                conn, _ = sock.accept()
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                return

    def stop(self):
        self._stop.set()
        for sock in self._sockets:
            sock.close()


_print_lock = threading.Lock()


def _pump(pipe):
    """Copy a child's output line by line. One lock = lines from different
    processes can never be torn in half on screen."""
    for line in pipe:
        with _print_lock:
            sys.stdout.write(line)
            sys.stdout.flush()


def spawn(cmd, env):
    """Start a child process whose output is shown through our single printer."""
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8", errors="replace")
    threading.Thread(target=_pump, args=(proc.stdout,), daemon=True).start()
    return proc


def start_workers(count, port, extra_for=None):
    """Start `count` worker processes. extra_for = {worker_number: [extra args]}."""
    env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8")
    procs = []
    for i in range(1, count + 1):
        cmd = [sys.executable, WORKER, "--host", "127.0.0.1", "--port", str(port), "--name", f"worker-{i}"]
        cmd += (extra_for or {}).get(i, [])
        procs.append(spawn(cmd, env))
    return procs


def main():
    parser = argparse.ArgumentParser(description="Local demo of the distributed port scanner")
    parser.add_argument("--workers", type=int, default=3, help="number of workers (default 3)")
    parser.add_argument("--ports", default="1-1800", help="port range to scan on 127.0.0.1 (default 1-1800)")
    parser.add_argument("--chunk-size", type=int, default=150, help="ports per task (default 150)")
    parser.add_argument("--port", type=int, default=5055, help="controller port (default 5055)")
    parser.add_argument("--crash", action="store_true", help="make worker-2 crash when it receives its 2nd task")
    parser.add_argument("--hang", action="store_true", help="make worker-2 go silent when it receives its 2nd task")
    args = parser.parse_args()

    if (args.crash or args.hang) and args.workers < 2:
        print("--crash/--hang need at least 2 workers (someone has to finish the lost task).")
        return 2

    services = FakeServices(FAKE_SERVICE_PORTS).start()
    print(f"Opened {len(services.opened)} fake services on 127.0.0.1: {services.opened}")
    print("A correct scan of 127.0.0.1 should find at least these ports.\n")

    extra = {}
    if args.crash:
        extra[2] = ["--simulate-crash-on-nth-task", "2"]
    if args.hang:
        extra[2] = ["--simulate-hang-on-nth-task", "2"]

    controller_cmd = [
        sys.executable, CONTROLLER,
        "--target", f"127.0.0.1:{args.ports}", "--chunk-size", str(args.chunk_size),
        "--port", str(args.port), "--min-workers", str(args.workers),
        "--output", os.path.join(HERE, "results", "demo.json"),
        "--task-timeout", "5" if args.hang else "120",
    ]
    env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8")
    if sys.stdout.isatty():
        env["FORCE_COLOR"] = "1"  # the controller's output goes through a pipe, so ask for colours explicitly
        if os.name == "nt":
            os.system("")  # enable ANSI colours in Windows 10+ consoles
    controller = spawn(controller_cmd, env)
    workers = start_workers(args.workers, args.port, extra)

    try:
        code = controller.wait()
    except KeyboardInterrupt:
        controller.terminate()
        code = 130
    finally:
        time.sleep(0.5)  # let the pump threads print the last lines
        for proc in workers:  # a crashed/hung demo worker may still be around
            if proc.poll() is None:
                proc.terminate()
        services.stop()

    report_path = os.path.join(HERE, "results", "demo.json")
    if (args.crash or args.hang) and os.path.exists(report_path):
        with open(report_path, encoding="utf-8") as handle:
            retries = json.load(handle)["summary"]["retries"]
        if retries == 0:
            print("\nNote: worker-2 never received a 2nd task, so no fault was injected this time. Run again.")
    print(f"\nOpen the HTML report in your browser: {os.path.join(HERE, 'results', 'demo.html')}")
    return code


if __name__ == "__main__":
    sys.exit(main())
