#!/usr/bin/env python3
"""
Distributed Port Scanner - CONTROLLER
=====================================

The intuition:
    The controller is a *manager with a to-do list*.
      1. It builds a list of scan tasks (a host + a slice of ports).
      2. Workers phone in. For EVERY worker the controller starts a separate
         thread, so a slow worker never blocks the others -> real parallelism.
      3. Each thread repeatedly: take a task from the shared queue, send it to
         "its" worker, wait for the answer, store it.
      4. If a worker crashes, goes silent (timeout) or sends garbage, the task
         is put back on the queue so another worker can do it.
      5. When every task is finished the controller prints a summary, an ASCII
         timeline of who did what when, and saves JSON + HTML reports.

Why threads and a Queue?
    queue.Queue is thread-safe: many threads can take tasks from it without
    two of them ever getting the same task. A threading.Lock protects the
    other shared data (counters, results).

Wire protocol: newline-delimited JSON (see worker.py for the message list).

Examples:
    python controller/controller.py --target 127.0.0.1:1-3000 --chunk-size 500 --min-workers 3
    python controller/controller.py --target 192.168.56.10:1-1024 --bind 0.0.0.0   # workers on other machines
    python controller/controller.py --targets-file targets.txt --output results/run1.json

Only scan machines you own or have explicit permission to scan.
"""

import argparse
import html
import ipaddress
import json
import math
import os
import platform
import queue
import re
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

DEFAULT_PORT = 5055
MAX_MESSAGE_BYTES = 16 * 1024 * 1024
HELLO_TIMEOUT = 10  # seconds a new connection has to introduce itself
DEFAULT_PORT_RANGE = "1-1024"

PORTS_RE = re.compile(r"^\d+(-\d+)?(,\d+(-\d+)?)*$")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-/]*$")


# --------------------------------------------------------------------------
# Message framing (identical helper lives in worker.py)
# --------------------------------------------------------------------------
class Channel:
    """Send / receive one JSON message per line over a TCP socket."""

    def __init__(self, sock):
        self.sock = sock
        self.buffer = b""

    def send(self, message):
        line = json.dumps(message, separators=(",", ":")) + "\n"
        self.sock.sendall(line.encode("utf-8"))

    def recv(self):
        # Keep reading until the end-of-message marker "\n" has arrived.
        while b"\n" not in self.buffer:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("the other side closed the connection")
            self.buffer += chunk
            if len(self.buffer) > MAX_MESSAGE_BYTES:
                raise ValueError("message too large")
        line, self.buffer = self.buffer.split(b"\n", 1)
        return json.loads(line.decode("utf-8"))


class ProtocolError(Exception):
    """The worker sent something that does not follow the protocol."""


# --------------------------------------------------------------------------
# Tasks and targets
# --------------------------------------------------------------------------
@dataclass
class Task:
    task_id: int
    ip: str
    ports: str
    attempts: int = 0
    status: str = "pending"  # pending -> running -> done | failed
    result: Optional[dict] = None
    error: Optional[str] = None
    history: list = field(default_factory=list)  # one record per attempt (for the timeline)


def parse_ports(spec):
    """'22,80,100-102' -> [22, 80, 100, 101, 102] (validated, sorted, unique)."""
    if not PORTS_RE.match(spec):
        raise ValueError(f"bad port list {spec!r} (use e.g. 22,80,1000-2000)")
    ports = set()
    for part in spec.split(","):
        low, _, high = part.partition("-")
        low, high = int(low), int(high or low)
        if not (1 <= low <= high <= 65535):
            raise ValueError(f"port range out of bounds: {part}")
        ports.update(range(low, high + 1))
    return sorted(ports)


def compress_ports(ports):
    """[1, 2, 3, 5] -> '1-3,5'."""
    parts, start, prev = [], ports[0], ports[0]
    for p in ports[1:] + [None]:
        if p is not None and p == prev + 1:
            prev = p
            continue
        parts.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = p
    return ",".join(parts)


def split_ports(spec, chunk_size):
    """Cut a port list into pieces of at most chunk_size ports (0 = don't cut)."""
    ports = parse_ports(spec)
    if not chunk_size or len(ports) <= chunk_size:
        return [compress_ports(ports)]
    return [compress_ports(ports[i:i + chunk_size]) for i in range(0, len(ports), chunk_size)]


def parse_target(text):
    """'127.0.0.1:20-25' or '127.0.0.1 20-25' or '127.0.0.1' -> (host, ports)."""
    text = text.strip()
    if any(c.isspace() for c in text):
        host, ports = text.split(None, 1)
    elif ":" in text:
        host, ports = text.rsplit(":", 1)
    else:
        host, ports = text, DEFAULT_PORT_RANGE
    if not HOST_RE.match(host):
        raise ValueError(f"bad host {host!r}")
    return host, ports.replace(" ", "")


def load_targets_file(path):
    entries = []
    with open(path, encoding="utf-8") as handle:
        for number, raw in enumerate(handle, 1):
            line = raw.split("#", 1)[0].strip()  # '#' starts a comment
            if line:
                try:
                    entries.append(parse_target(line))
                except ValueError as exc:
                    raise ValueError(f"{path}, line {number}: {exc}")
    return entries


def looks_private(host):
    """Convenience guard (NOT security): is this obviously my own machine/LAN?"""
    base = re.split(r"[-/]", host)[0]
    if base.lower() == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(base)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


# --------------------------------------------------------------------------
# Terminal colours (optional, works on Windows 10+ terminals)
# --------------------------------------------------------------------------
class Palette:
    CODES = {"green": "32", "yellow": "33", "red": "31", "cyan": "36", "dim": "2", "bold": "1"}

    def __init__(self, enabled):
        self.enabled = enabled

    def __call__(self, color, text):
        if not self.enabled or color is None:
            return text
        return f"\033[{self.CODES[color]}m{text}\033[0m"


# --------------------------------------------------------------------------
# The controller
# --------------------------------------------------------------------------
@dataclass
class WorkerInfo:
    name: str
    address: str
    connected: bool = True
    tasks_done: int = 0
    failures: int = 0
    busy_seconds: float = 0.0


class Controller:
    def __init__(self, tasks, args, color):
        self.args = args
        self.paint = color
        self.tasks = {t.task_id: t for t in tasks}
        self.queue = queue.Queue()  # thread-safe to-do list
        for task in tasks:
            self.queue.put(task)

        self.lock = threading.Lock()        # protects the shared state below
        self.print_lock = threading.Lock()  # keeps log lines from interleaving
        self.unfinished = len(tasks)        # tasks neither done nor permanently failed
        self.all_done = threading.Event()   # set when there is nothing left to do
        self.gate = threading.Event()       # set when scanning may begin
        self.workers = {}
        self.events = []                    # saved copy of the log for the reports
        self.threads = []
        self.interrupted = False
        self.abort_reason = None
        self.t0 = None                    # clock start (first dispatch)
        self.t_end = None
        self.started_at = None
        self.finished_at = None

    # ------------------------------------------------------------ logging
    def log(self, who, text, kind=None):
        now = time.perf_counter()
        rel = None if self.t0 is None else round(now - self.t0, 3)
        stamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        colors = {"ok": "green", "warn": "yellow", "bad": "red", "info": None, "head": "cyan"}
        with self.print_lock:
            print(f"[{stamp}] {who:<11} {self.paint(colors.get(kind), text)}", flush=True)
        self.events.append({"t": rel, "who": who, "event": text, "kind": kind or "info"})

    def progress_bar(self, width=20):
        finished = len(self.tasks) - self.unfinished
        filled = int(width * finished / len(self.tasks))
        return f"[{'#' * filled}{'-' * (width - filled)}] {finished}/{len(self.tasks)} tasks finished"

    # ------------------------------------------------------------ bookkeeping
    def _task_finished_locked(self):
        """Call with self.lock held when a task becomes done/failed."""
        self.unfinished -= 1
        if self.unfinished == 0:
            self.t_end = time.perf_counter()
            self.all_done.set()

    def register_worker(self, requested_name, address):
        with self.lock:
            name = str(requested_name or f"worker@{address}")[:40]
            base, n = name, 1
            while name in self.workers and self.workers[name].connected:
                n += 1
                name = f"{base}#{n}"
            self.workers[name] = WorkerInfo(name=name, address=address)
            return name

    def connected_count(self):
        with self.lock:
            return sum(1 for w in self.workers.values() if w.connected)

    def fail_attempt(self, task, worker_name, reason):
        """An attempt failed: retry on the queue, or give up after max attempts."""
        with self.lock:
            self.workers[worker_name].failures += 1
            if task.attempts < self.args.max_attempts:
                task.status = "pending"
                self.queue.put(task)  # another (or the same) worker will pick it up
                retry = True
            else:
                task.status = "failed"
                task.error = reason
                self._task_finished_locked()
                retry = False
        if retry:
            self.log("controller", f"task #{task.task_id} put back on the queue "
                                   f"(attempt {task.attempts}/{self.args.max_attempts} failed: {reason})", "warn")
        else:
            self.log("controller", f"task #{task.task_id} FAILED permanently after {task.attempts} attempts: {reason}", "bad")

    # ------------------------------------------------------------ one thread per worker
    def handle_worker(self, conn, addr):
        address = f"{addr[0]}:{addr[1]}"
        channel = Channel(conn)
        name = None
        current = None   # task this thread is working on right now
        attempt = None   # its attempt record
        reason = None
        outcome = "error"
        try:
            conn.settimeout(HELLO_TIMEOUT)
            hello = channel.recv()
            if hello.get("type") != "hello":
                raise ProtocolError("first message must be 'hello'")
            name = self.register_worker(hello.get("worker"), address)
            self.log(name, f"connected from {address}", "info")

            while not self.gate.is_set() and not self.all_done.is_set():
                time.sleep(0.05)  # everybody waits at the starting line

            while not self.all_done.is_set():
                try:
                    task = self.queue.get(timeout=0.25)  # wait for work (or for the end)
                except queue.Empty:
                    continue  # empty now, but a failed task might come back, so keep waiting

                with self.lock:
                    task.attempts += 1
                    task.status = "running"
                    start = time.perf_counter() - self.t0
                    attempt = {"worker": name, "start": round(start, 3), "end": None, "outcome": None}
                    task.history.append(attempt)
                current = task

                self.log("controller", f"-> {name}  task #{task.task_id}  {task.ip} ports {task.ports}"
                                       f"  (attempt {task.attempts})", "info")
                conn.settimeout(self.args.task_timeout)  # the answer must arrive within this time
                channel.send({"type": "task", "task_id": task.task_id, "ip": task.ip,
                              "ports": task.ports, "attempt": task.attempts})
                reply = channel.recv()

                if (reply.get("type") != "result" or reply.get("task_id") != task.task_id
                        or reply.get("status") not in ("ok", "host_down", "error")
                        or not isinstance(reply.get("open_ports", []), list)):
                    raise ProtocolError(f"unexpected reply: {str(reply)[:120]}")

                end = time.perf_counter() - self.t0
                attempt["end"], attempt["outcome"] = round(end, 3), reply["status"]
                took = end - attempt["start"]

                if reply["status"] == "error":
                    attempt["error"] = reply.get("error")
                    with self.lock:
                        self.workers[name].busy_seconds += took
                    current = None
                    self.log(name, f"<- task #{task.task_id} ERROR: {reply.get('error')}", "warn")
                    self.fail_attempt(task, name, reply.get("error") or "worker reported an error")
                    continue

                with self.lock:
                    task.status, task.result = "done", reply
                    self.workers[name].tasks_done += 1
                    self.workers[name].busy_seconds += took
                    self._task_finished_locked()
                current = None
                count = len(reply.get("open_ports", []))
                if reply["status"] == "ok":
                    text = f"<- {name}  task #{task.task_id}  OK  {count} open port(s)  in {took:.2f}s"
                else:
                    text = f"<- {name}  task #{task.task_id}  HOST DOWN ({reply.get('error')})  in {took:.2f}s"
                self.log("controller", f"{text}   {self.progress_bar()}", "ok" if reply["status"] == "ok" else "warn")

            conn.settimeout(5)
            channel.send({"type": "no_more_tasks"})

        except socket.timeout:
            reason = f"timeout: no answer within {self.args.task_timeout:g}s"
            outcome = "timeout"
        except (ConnectionError, OSError):
            reason = "worker disconnected / crashed"
            outcome = "disconnected"
        except (ProtocolError, ValueError) as exc:
            reason = f"bad message from worker ({exc})"
            outcome = "bad_message"
        except Exception as exc:  # a bug here must never lose a task silently
            reason = f"internal error in controller thread: {type(exc).__name__}: {exc}"
        finally:
            try:
                conn.close()
            except OSError:
                pass
            if name:
                with self.lock:
                    self.workers[name].connected = False
            if current is not None:  # the worker died while holding a task -> give it back
                end = time.perf_counter() - self.t0
                attempt["end"], attempt["outcome"] = round(end, 3), outcome
                with self.lock:
                    self.workers[name].busy_seconds += end - attempt["start"]
                self.log("controller", f"!! {name} lost while scanning task #{current.task_id}: {reason}", "bad")
                self.fail_attempt(current, name, reason)
            elif reason and name:
                self.log("controller", f"{name} dropped: {reason}", "warn")
            elif reason:
                self.log("controller", f"connection from {address} dropped before hello: {reason}", "warn")

    # ------------------------------------------------------------ main server loop
    def open_gate(self, why):
        self.t0 = time.perf_counter()
        self.started_at = datetime.now()
        self.gate.set()
        self.log("controller", f"START scanning ({why})", "head")

    def serve(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if os.name == "nt":
            # On Windows, SO_REUSEADDR would let a SECOND controller bind the same port
            # (unlike Linux). Ask for exclusive use so the second one fails with a clear error.
            server.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # allow quick restarts
        try:
            server.bind((self.args.bind, self.args.port))
        except OSError as exc:
            print(f"ERROR: cannot listen on {self.args.bind}:{self.args.port}: {exc}\n"
                  f"       (is another controller already running? try --port 5056)", file=sys.stderr)
            return False
        server.listen()
        server.settimeout(0.5)

        self.log("controller", f"listening on {self.args.bind}:{self.args.port}  |  "
                               f"{len(self.tasks)} task(s) queued  |  waiting for {self.args.min_workers} worker(s)", "head")
        deadline = time.perf_counter() + self.args.wait_timeout
        last_hint = time.perf_counter()
        no_worker_since = None
        try:
            while not self.all_done.is_set():
                now = time.perf_counter()
                ready = self.connected_count()
                if not self.gate.is_set():
                    if ready >= self.args.min_workers:
                        self.open_gate(f"{ready} worker(s) connected")
                    elif ready > 0 and now > deadline:
                        self.open_gate(f"waited {self.args.wait_timeout:g}s, starting with {ready} worker(s)")
                    elif now - last_hint > 10:
                        last_hint = now
                        self.log("controller", f"still waiting for workers ({ready}/{self.args.min_workers}). "
                                               f"Start one with: python worker/worker.py --port {self.args.port}", "warn")
                elif ready == 0:
                    # Scanning started but nobody is connected any more. Wait a while for a
                    # worker to (re)connect, then give up instead of hanging forever.
                    no_worker_since = no_worker_since or now
                    if now - no_worker_since > self.args.idle_timeout:
                        self.abort_reason = (f"no worker connected for {self.args.idle_timeout:g}s while "
                                             f"{self.unfinished} task(s) were unfinished")
                        self.log("controller", f"GIVING UP: {self.abort_reason}", "bad")
                        self.t_end = now
                        self.all_done.set()
                        break
                else:
                    no_worker_since = None
                try:
                    conn, addr = server.accept()
                except socket.timeout:
                    continue
                thread = threading.Thread(target=self.handle_worker, args=(conn, addr), daemon=True)
                thread.start()
                self.threads.append(thread)
        except KeyboardInterrupt:
            self.interrupted = True
            self.t_end = self.t_end or time.perf_counter()
            self.all_done.set()
            print()
            self.log("controller", "interrupted by user (Ctrl+C) - reporting what finished so far", "warn")
        finally:
            if self.t_end is None:
                self.t_end = time.perf_counter()
            self.finished_at = datetime.now()
            for thread in self.threads:  # let each thread send "no_more_tasks"
                thread.join(timeout=3)
            server.close()
        return True

    # ------------------------------------------------------------ reporting
    def elapsed(self):
        if self.t0 is None or self.t_end is None:
            return 0.0
        return self.t_end - self.t0

    def build_report(self):
        elapsed = self.elapsed()
        hosts = {}
        for task in self.tasks.values():
            if task.status == "done" and task.result:
                for port in task.result.get("open_ports", []):
                    hosts.setdefault(port["host"], []).append(
                        {"port": port["port"], "protocol": port["protocol"], "service": port["service"]})
        for ports in hosts.values():
            ports.sort(key=lambda p: (p["protocol"], p["port"]))

        work = sum((a["end"] - a["start"]) for t in self.tasks.values() for a in t.history
                   if a["end"] is not None and a["outcome"] in ("ok", "host_down"))
        statuses = [t.status for t in self.tasks.values()]
        retries = sum(max(0, t.attempts - 1) for t in self.tasks.values())

        workers = {}
        for w in self.workers.values():
            workers[w.name] = {
                "address": w.address, "tasks_completed": w.tasks_done, "failures": w.failures,
                "busy_seconds": round(w.busy_seconds, 3),
                "utilization": round(w.busy_seconds / elapsed, 3) if elapsed else 0.0,
            }
        return {
            "meta": {
                "started_at": self.started_at.isoformat(timespec="seconds") if self.started_at else None,
                "finished_at": self.finished_at.isoformat(timespec="seconds") if self.finished_at else None,
                "elapsed_seconds": round(elapsed, 3),
                "workers_expected": self.args.min_workers,
                "task_timeout_seconds": self.args.task_timeout,
                "max_attempts": self.args.max_attempts,
                "platform": f"{platform.system()} {platform.release()}",
                "python": platform.python_version(),
                "cpu_count": os.cpu_count(),
                "interrupted": self.interrupted,
                "aborted_reason": self.abort_reason,
            },
            "summary": {
                "tasks_total": len(self.tasks),
                "tasks_done": statuses.count("done"),
                "tasks_failed": statuses.count("failed"),
                "tasks_incomplete": statuses.count("pending") + statuses.count("running"),
                "retries": retries,
                "hosts_down": sum(1 for t in self.tasks.values() if t.result and t.result.get("status") == "host_down"),
                "open_ports_total": sum(len(v) for v in hosts.values()),
                "sum_of_task_seconds": round(work, 3),
                "average_tasks_running_at_once": round(work / elapsed, 2) if elapsed else 0.0,
            },
            "hosts": hosts,
            "tasks": [{
                "task_id": t.task_id, "ip": t.ip, "ports": t.ports, "status": t.status,
                "attempts": t.attempts, "error": t.error,
                "result_status": t.result.get("status") if t.result else None,
                "open_ports": t.result.get("open_ports", []) if t.result else [],
                "history": t.history,
            } for t in self.tasks.values()],
            "workers": workers,
            "events": self.events,
        }

    def render_timeline(self, report, width=60):
        """ASCII Gantt chart: one row per worker, time flows left -> right."""
        elapsed = report["meta"]["elapsed_seconds"] or 1e-9
        rows = {name: ["."] * width for name in sorted(self.workers)}
        for task in self.tasks.values():
            for att in task.history:
                if att["end"] is None or att["worker"] not in rows:
                    continue
                first = min(width - 1, int(att["start"] / elapsed * width))
                last = min(width, max(first + 1, math.ceil(att["end"] / elapsed * width)))
                mark = str(task.task_id % 10) if att["outcome"] in ("ok", "host_down") else "x"
                for col in range(first, last):
                    rows[att["worker"]][col] = mark
        pad = max([len(n) for n in rows] + [6])
        lines = [f"{n:<{pad}} |{''.join(cells)}|" for n, cells in rows.items()]
        axis = f"{'':<{pad}}  0s{' ' * (width - 2 - len(f'{elapsed:.1f}s'))}{elapsed:.1f}s"
        return lines + [axis,
                        f"{'':<{pad}}  digits = task id (last digit), x = failed attempt, . = idle"]

    def print_summary(self, report, json_path, html_path):
        p, m, s = self.paint, report["meta"], report["summary"]
        bar = "=" * 74
        print(f"\n{bar}\n{p('bold', 'SCAN SUMMARY')}\n{bar}")

        if report["hosts"]:
            print("Open ports found:")
            for host, ports in sorted(report["hosts"].items()):
                print(f"  {p('bold', host)}  ({len(ports)} open)")
                for port in ports:
                    print(f"      {port['port']:>5}/{port['protocol']:<4} {port['service']}")
        else:
            print("Open ports found: none")

        print("\nTasks:")
        print(f"  {'id':>3}  {'target':<18} {'ports':<16} {'status':<8} {'tries':>5}  {'open':>4}  note")
        for t in report["tasks"]:
            note = t["error"] or (t["result_status"] if t["result_status"] == "host_down" else "")
            ports = t["ports"] if len(t["ports"]) <= 16 else t["ports"][:13] + "..."
            print(f"  {t['task_id']:>3}  {t['ip']:<18} {ports:<16} {t['status']:<8} {t['attempts']:>5}  "
                  f"{len(t['open_ports']):>4}  {note}")

        print("\nWorkers:")
        print(f"  {'name':<14} {'tasks':>5} {'failures':>8} {'busy(s)':>8} {'busy %':>7}")
        for name, w in sorted(report["workers"].items()):
            print(f"  {name:<14} {w['tasks_completed']:>5} {w['failures']:>8} {w['busy_seconds']:>8.2f} "
                  f"{w['utilization'] * 100:>6.0f}%")

        print("\nTimeline (who was scanning what, and when):")
        for line in self.render_timeline(report):
            print("  " + line)

        print(f"\n{p('bold', 'Total elapsed time:')} {m['elapsed_seconds']:.2f} s "
              f"(from the first task being sent to the last result arriving)")
        print(f"If the same tasks had run one after another: about {s['sum_of_task_seconds']:.2f} s")
        print(f"Average tasks running at the same time: {s['average_tasks_running_at_once']:.2f} "
              f"(1.00 would mean no overlap at all)")
        verdict = (f"{s['tasks_done']}/{s['tasks_total']} tasks done, {s['tasks_failed']} failed, "
                   f"{s['tasks_incomplete']} incomplete, {s['retries']} retried attempt(s)")
        ok = s["tasks_done"] == s["tasks_total"]
        print(p("green" if ok else "red", verdict))
        if m["aborted_reason"]:
            print(p("red", f"Stopped early: {m['aborted_reason']}"))
        elif m["interrupted"]:
            print(p("red", "Stopped early: interrupted by user"))
        print(f"Saved: {json_path}" + (f"  and  {html_path}" if html_path else ""))
        print(bar)

    def write_json(self, report, path):
        folder = os.path.dirname(os.path.abspath(path))
        os.makedirs(folder, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)

    def write_html(self, report, path):
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(render_html(report))


# --------------------------------------------------------------------------
# HTML report (self-contained: no internet, no JavaScript)
# --------------------------------------------------------------------------
def render_html(report):
    e = html.escape
    meta, summary = report["meta"], report["summary"]
    elapsed = meta["elapsed_seconds"] or 1e-9
    palette = ["#2a78d6", "#1baa7d", "#d98a1c", "#a455d6", "#d6456b", "#4a9fb5", "#8a8f1c", "#6b7280"]

    # timeline rows
    rows = []
    for name in sorted(report["workers"]):
        bars = []
        for task in report["tasks"]:
            for att in task["history"]:
                if att["worker"] != name or att["end"] is None:
                    continue
                left = att["start"] / elapsed * 100
                width = max(0.6, (att["end"] - att["start"]) / elapsed * 100)
                good = att["outcome"] in ("ok", "host_down")
                color = palette[task["task_id"] % len(palette)] if good else "#c62828"
                tip = (f"task #{task['task_id']} {task['ip']} ports {task['ports']} - {att['outcome']} - "
                       f"{att['start']:.2f}s to {att['end']:.2f}s")
                label = f"#{task['task_id']}" if good else f"#{task['task_id']} ✕"
                bars.append(f'<div class="bar" style="left:{left:.2f}%;width:{width:.2f}%;background:{color}" '
                            f'title="{e(tip)}">{label}</div>')
        rows.append(f'<div class="lane"><div class="lname">{e(name)}</div><div class="track">{"".join(bars)}</div></div>')

    host_html = ""
    for host, ports in sorted(report["hosts"].items()):
        body = "".join(f"<tr><td>{p['port']}</td><td>{e(p['protocol'])}</td><td>{e(p['service'])}</td></tr>" for p in ports)
        host_html += f"<h3>{e(host)} <small>{len(ports)} open</small></h3><table><tr><th>Port</th><th>Proto</th><th>Service</th></tr>{body}</table>"
    if not host_html:
        host_html = "<p>No open ports found.</p>"

    task_rows = "".join(
        f"<tr><td>{t['task_id']}</td><td>{e(t['ip'])}</td><td>{e(t['ports'])}</td><td>{e(t['status'])}</td>"
        f"<td>{t['attempts']}</td><td>{len(t['open_ports'])}</td><td>{e(t['error'] or '')}</td></tr>"
        for t in report["tasks"])
    worker_rows = "".join(
        f"<tr><td>{e(n)}</td><td>{w['tasks_completed']}</td><td>{w['failures']}</td><td>{w['busy_seconds']:.2f}</td>"
        f"<td>{w['utilization'] * 100:.0f}%</td></tr>" for n, w in sorted(report["workers"].items()))
    event_rows = ""
    for ev in report["events"]:
        when = "" if ev["t"] is None else "%.2fs" % ev["t"]
        event_rows += (f"<tr class='{e(ev['kind'])}'><td>{when}</td><td>{e(ev['who'])}</td>"
                       f"<td>{e(ev['event'])}</td></tr>")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Distributed Port Scanner report</title>
<style>
:root{{--bg:#fafafa;--fg:#1c1c1e;--card:#fff;--line:#e2e2e6;--mute:#6b6b73}}
@media (prefers-color-scheme:dark){{:root{{--bg:#16161a;--fg:#ececf0;--card:#212127;--line:#34343c;--mute:#9a9aa4}}}}
body{{margin:0;padding:24px 16px;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,Segoe UI,sans-serif}}
main{{max-width:960px;margin:auto}} h1{{font-size:22px;margin:0 0 4px}} h2{{font-size:17px;margin:28px 0 8px}} h3{{font-size:15px}}
small,.mute{{color:var(--mute);font-weight:400}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:16px 0}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}}
.card b{{display:block;font-size:22px}}
table{{border-collapse:collapse;width:100%;background:var(--card);border:1px solid var(--line);font-size:14px;margin-bottom:8px}}
th,td{{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line)}}
.lane{{display:flex;align-items:center;margin:6px 0}} .lname{{width:110px;font-size:13px;flex:none}}
.track{{position:relative;flex:1;height:30px;background:var(--card);border:1px solid var(--line);border-radius:6px}}
.bar{{position:absolute;top:3px;bottom:3px;border-radius:4px;color:#fff;font-size:12px;line-height:22px;text-align:center;overflow:hidden;white-space:nowrap}}
tr.warn td{{color:#b26a00}} tr.bad td{{color:#c62828}} tr.ok td:nth-child(3){{color:#1b7f5c}}
details{{margin-top:8px}} .scroll{{overflow-x:auto}}
</style></head><body><main>
<h1>Distributed Port Scanner - run report</h1>
<div class="mute">{e(str(meta['started_at']))} on {e(meta['platform'])}, Python {e(meta['python'])}, {meta['cpu_count']} CPU(s)</div>
<div class="cards">
<div class="card"><b>{meta['elapsed_seconds']:.2f}s</b>total elapsed time</div>
<div class="card"><b>{summary['tasks_done']}/{summary['tasks_total']}</b>tasks done</div>
<div class="card"><b>{len(report['workers'])}</b>workers seen</div>
<div class="card"><b>{summary['open_ports_total']}</b>open ports</div>
<div class="card"><b>{summary['retries']}</b>retried attempts</div>
<div class="card"><b>{summary['average_tasks_running_at_once']:.2f}</b>avg tasks at once</div>
</div>
<h2>Timeline <small>each bar is one task attempt; red = failed attempt that was re-queued; hover for details</small></h2>
{''.join(rows)}
<div class="mute" style="margin-left:110px;display:flex;justify-content:space-between"><span>0s</span><span>{elapsed:.2f}s</span></div>
<h2>Open ports</h2>{host_html}
<h2>Workers</h2><table><tr><th>Name</th><th>Tasks</th><th>Failures</th><th>Busy (s)</th><th>Busy %</th></tr>{worker_rows}</table>
<h2>Tasks</h2><div class="scroll"><table><tr><th>ID</th><th>Target</th><th>Ports</th><th>Status</th><th>Tries</th><th>Open</th><th>Note</th></tr>{task_rows}</table></div>
<details><summary>Event log</summary><div class="scroll"><table><tr><th>Time</th><th>Who</th><th>Event</th></tr>{event_rows}</table></div></details>
</main></body></html>"""


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------
def build_tasks(args):
    entries = []
    for text in args.target or []:
        entries.append(parse_target(text))
    if args.targets_file:
        entries.extend(load_targets_file(args.targets_file))
    if not entries:
        raise ValueError("no targets given. Use --target 127.0.0.1:1-1000 or --targets-file targets.txt")

    for host, _ in entries:
        if not looks_private(host) and not args.i_have_permission:
            raise ValueError(f"{host!r} does not look like localhost or a private network address.\n"
                             f"       Only scan systems you own or have written permission to scan.\n"
                             f"       If that is the case, add --i-have-permission.")
    tasks, number = [], 1
    for host, ports in entries:
        for piece in split_ports(ports, args.chunk_size):
            tasks.append(Task(task_id=number, ip=host, ports=piece))
            number += 1
    return tasks


def main():
    parser = argparse.ArgumentParser(
        description="Distributed Port Scanner controller",
        epilog="Only scan systems you own or have explicit permission to scan.")
    parser.add_argument("--target", action="append", metavar="HOST[:PORTS]",
                        help="target to scan, repeatable. e.g. 127.0.0.1:1-1000  (default ports 1-1024)")
    parser.add_argument("--targets-file", metavar="FILE", help='text file, one "host ports" per line, # comments allowed')
    parser.add_argument("--chunk-size", type=int, default=0, metavar="N",
                        help="split each target's ports into tasks of N ports so more workers can help (default: don't split)")
    parser.add_argument("--bind", default="127.0.0.1",
                        help="address to listen on (default 127.0.0.1 = this computer only; use 0.0.0.0 to accept "
                             "workers from other machines. There is no authentication, so only do that on a network you trust)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"TCP port to listen on (default {DEFAULT_PORT})")
    parser.add_argument("--min-workers", type=int, default=1, metavar="N",
                        help="wait until N workers are connected before starting the clock (default 1)")
    parser.add_argument("--wait-timeout", type=float, default=30, metavar="SEC",
                        help="stop waiting for --min-workers after SEC and start anyway (default 30)")
    parser.add_argument("--task-timeout", type=float, default=120, metavar="SEC",
                        help="a worker that does not answer within SEC loses its task (default 120)")
    parser.add_argument("--idle-timeout", type=float, default=60, metavar="SEC",
                        help="give up if no worker is connected for SEC while tasks remain (default 60)")
    parser.add_argument("--max-attempts", type=int, default=3, metavar="N",
                        help="give up on a task after N failed attempts (default 3)")
    parser.add_argument("--output", default="results/scan_results.json", metavar="FILE",
                        help="JSON report path; an .html report is written next to it (default results/scan_results.json)")
    parser.add_argument("--no-html", action="store_true", help="do not write the HTML report")
    parser.add_argument("--no-color", action="store_true", help="plain output without colours")
    parser.add_argument("--i-have-permission", action="store_true",
                        help="allow targets that are not localhost/private addresses (you must have permission!)")
    args = parser.parse_args()

    try:
        tasks = build_tasks(args)
    except (ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    wants_color = sys.stdout.isatty() or os.environ.get("FORCE_COLOR")
    use_color = bool(wants_color) and not args.no_color and not os.environ.get("NO_COLOR")
    if use_color and os.name == "nt":
        os.system("")  # switches on ANSI colour support in Windows 10+ consoles

    controller = Controller(tasks, args, Palette(use_color))
    if not controller.serve():
        return 2

    report = controller.build_report()
    json_path = args.output
    html_path = None if args.no_html else os.path.splitext(json_path)[0] + ".html"
    controller.write_json(report, json_path)
    if html_path:
        controller.write_html(report, html_path)
    controller.print_summary(report, json_path, html_path)
    return 0 if report["summary"]["tasks_done"] == report["summary"]["tasks_total"] else 1


if __name__ == "__main__":
    sys.exit(main())
