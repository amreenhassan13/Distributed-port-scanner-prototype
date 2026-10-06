#!/usr/bin/env python3
"""
Distributed Port Scanner - WORKER
=================================

What a worker does (the intuition):
    A worker is a "scanning employee". It phones the controller (the "manager"),
    says hello, and then repeats:  receive a task -> scan it with Nmap -> send
    back the answer.  When the manager says "no more tasks", it hangs up.

Messages are newline-delimited JSON (NDJSON): one JSON object per line, ending
with "\\n".  The newline is the "end of message" marker, so a long result can
never be cut in half (that was the old recv(8192) bug).

Messages the worker SENDS:
    {"type": "hello", "worker": "<name>", "pid": 1234}
    {"type": "result", "task_id": 3, "status": "ok" | "host_down" | "error",
     "open_ports": [{"host", "port", "protocol", "service"}], "error": null | "text",
     "scan_seconds": 1.23, ...}

Messages the worker RECEIVES:
    {"type": "task", "task_id": 3, "ip": "127.0.0.1", "ports": "1-500", "attempt": 1}
    {"type": "no_more_tasks"}

Run:
    python worker/worker.py --host 127.0.0.1 --port 5055 --name worker-1

Only scan machines you own or have explicit permission to scan.
"""

import argparse
import json
import os
import re
import socket
import sys
import time
from datetime import datetime

import nmap  # python-nmap: a thin wrapper that runs the real `nmap` program

MAX_MESSAGE_BYTES = 16 * 1024 * 1024  # refuse absurdly large messages

# Very small "allow-lists" so a task can never smuggle extra Nmap options in.
# (Without this, a target like "--script=evil" would be passed to nmap.)
PORTS_RE = re.compile(r"^\d+(-\d+)?(,\d+(-\d+)?)*$")  # e.g. 22,80,1000-2000
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-/]*$")  # host, IPv4, 1-20 range, CIDR

# -sT: TCP connect scan (works without admin rights on Windows/Linux/Mac)
# -T4: faster timing, --max-retries 1: don't hammer closed ports
DEFAULT_NMAP_ARGS = "-sT -T4 --max-retries 1"


# --------------------------------------------------------------------------
# Message framing (identical helper lives in controller.py)
# --------------------------------------------------------------------------
class Channel:
    """Send / receive one JSON message per line over a TCP socket."""

    def __init__(self, sock):
        self.sock = sock
        self.buffer = b""

    def send(self, message):
        line = json.dumps(message, separators=(",", ":")) + "\n"
        self.sock.sendall(line.encode("utf-8"))  # sendall: keeps going until ALL bytes are sent

    def recv(self):
        # TCP is a *stream*: one recv() may return half a message or two
        # messages glued together. So we keep reading until we see "\n".
        while b"\n" not in self.buffer:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("the other side closed the connection")
            self.buffer += chunk
            if len(self.buffer) > MAX_MESSAGE_BYTES:
                raise ValueError("message too large")
        line, self.buffer = self.buffer.split(b"\n", 1)
        return json.loads(line.decode("utf-8"))


# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------
def log(name, text):
    stamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"[{stamp}] {name:<11} {text}", flush=True)


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------
def scan_task(task, nmap_args):
    """Run one Nmap scan and return a result message. Never raises."""
    started = time.perf_counter()
    result = {
        "type": "result",
        "task_id": task.get("task_id"),
        "ip": task.get("ip"),
        "ports": task.get("ports"),
        "status": "ok",
        "open_ports": [],
        "error": None,
    }

    def finish(status, error=None):
        result["status"] = status
        result["error"] = error
        result["scan_seconds"] = round(time.perf_counter() - started, 3)
        return result

    ip, ports = str(task.get("ip", "")), str(task.get("ports", ""))
    if not HOST_RE.match(ip) or not PORTS_RE.match(ports):
        return finish("error", f"refused invalid task (ip={ip!r}, ports={ports!r})")

    try:
        scanner = nmap.PortScanner()  # raises PortScannerError if nmap is not installed
    except nmap.PortScannerError:
        return finish("error", "Nmap was not found on this worker. Install Nmap and make sure it is on PATH.")
    except Exception as exc:  # pragma: no cover - defensive
        return finish("error", f"could not start Nmap: {exc}")

    try:
        scanner.scan(hosts=ip, ports=ports, arguments=nmap_args)
    except nmap.PortScannerError as exc:
        return finish("error", f"Nmap error: {str(exc).strip()[:300]}")
    except Exception as exc:
        return finish("error", f"unexpected scan failure: {type(exc).__name__}: {exc}")

    # Nmap normally lists only hosts that answered host discovery, but be strict:
    # a host Nmap marks as "down" must never be counted as "scanned, nothing open".
    hosts = [h for h in scanner.all_hosts() if scanner[h].state() == "up"]
    if not hosts:
        return finish("host_down", "host appears to be down or unreachable (no reply to host discovery)")

    for host in hosts:
        for proto in scanner[host].all_protocols():
            for port, info in sorted(scanner[host][proto].items()):
                if info.get("state") == "open":  # keep ONLY open ports
                    result["open_ports"].append(
                        {
                            "host": host,
                            "port": int(port),
                            "protocol": proto,
                            "service": info.get("name") or "unknown",
                        }
                    )
    return finish("ok")


# --------------------------------------------------------------------------
# Main loop
# --------------------------------------------------------------------------
def connect_with_retry(host, port, attempts, name):
    """Workers may start before the controller; try a few times."""
    for attempt in range(1, attempts + 1):
        try:
            return socket.create_connection((host, port), timeout=5)
        except OSError as exc:
            if attempt == attempts:
                raise
            log(name, f"controller not reachable yet ({exc.__class__.__name__}), retry {attempt}/{attempts - 1}...")
            time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description="Distributed Port Scanner worker")
    parser.add_argument("--host", default="127.0.0.1", help="controller address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5055, help="controller TCP port (default 5055)")
    parser.add_argument("--name", default=None, help="worker name shown in logs (default worker-<pid>)")
    parser.add_argument("--nmap-args", default=DEFAULT_NMAP_ARGS,
                        help=f'arguments passed to Nmap (default "{DEFAULT_NMAP_ARGS}"). '
                             f'Write it with "=" so the leading dash is accepted, e.g. --nmap-args="-sT -sV"')
    parser.add_argument("--connect-retries", type=int, default=10, help="tries to reach the controller (default 10)")
    # Fault-tolerance demo aids. They exist only so you can SEE recovery working.
    parser.add_argument("--simulate-crash-on-nth-task", type=int, default=None, metavar="N",
                        help="demo: die abruptly when this worker receives its Nth task")
    parser.add_argument("--simulate-hang-on-nth-task", type=int, default=None, metavar="N",
                        help="demo: stop responding for 60s when this worker receives its Nth task")
    args = parser.parse_args()

    name = args.name or f"worker-{os.getpid()}"

    try:
        sock = connect_with_retry(args.host, args.port, args.connect_retries, name)
    except OSError as exc:
        log(name, f"ERROR: cannot connect to controller at {args.host}:{args.port}: {exc}")
        return 1

    sock.settimeout(None)  # wait as long as needed for the controller's next message
    channel = Channel(sock)
    log(name, f"connected to controller {args.host}:{args.port}")

    done = 0
    received = 0
    try:
        channel.send({"type": "hello", "worker": name, "pid": os.getpid()})
        while True:
            message = channel.recv()
            kind = message.get("type")

            if kind == "task":
                task_id = message.get("task_id")
                received += 1
                log(name, f"<- task #{task_id}: {message.get('ip')} ports {message.get('ports')} "
                          f"(attempt {message.get('attempt', 1)})")

                if args.simulate_crash_on_nth_task == received:
                    log(name, "!! SIMULATED CRASH (process dies without telling the controller)")
                    os._exit(1)
                if args.simulate_hang_on_nth_task == received:
                    log(name, "!! SIMULATED HANG (not answering for 60s)")
                    time.sleep(60)

                result = scan_task(message, args.nmap_args)

                if result["status"] == "ok":
                    shown = ", ".join(f"{p['port']}/{p['protocol']} {p['service']}" for p in result["open_ports"][:6])
                    more = "" if len(result["open_ports"]) <= 6 else f" (+{len(result['open_ports']) - 6} more)"
                    log(name, f"   scanned in {result['scan_seconds']}s -> {len(result['open_ports'])} open"
                              f"{': ' + shown + more if shown else ''}")
                else:
                    log(name, f"   scan problem [{result['status']}]: {result['error']}")

                channel.send(result)  # one line, however long
                log(name, f"-> result for task #{task_id} sent")
                done += 1

            elif kind == "no_more_tasks":
                log(name, f"controller says no more tasks. Finished {done} task(s). Bye.")
                return 0
            else:
                log(name, f"ignoring unknown message type: {kind!r}")

    except (ConnectionError, OSError) as exc:
        log(name, f"connection to controller lost ({exc}). Exiting.")
        return 1
    except KeyboardInterrupt:
        log(name, "interrupted by user")
        return 130
    finally:
        sock.close()


if __name__ == "__main__":
    # Windows consoles can choke on non-ASCII service names; never crash on printing.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    sys.exit(main())
