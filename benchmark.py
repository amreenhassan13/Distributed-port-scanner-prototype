#!/usr/bin/env python3
"""
Benchmark: is the distributed scanner really faster with more workers?

How it works (the intuition):
    We give the system EXACTLY the same job several times, once per worker
    count (default: 1 and 3 workers), and measure how long the
    controller needs. The controller's clock starts when scanning begins
    (after all workers have connected), so starting Python processes does not
    pollute the numbers. We repeat each setup a few times, alternate the order,
    and report the median so one lucky/unlucky run does not decide.

    speed-up = (time with 1 worker) / (time with N workers)
    Perfect scaling would give N. Real results are lower because of process
    start-up and the controller's own overhead. On localhost there is an extra
    limit: every worker and every Nmap process shares YOUR computer's CPU cores,
    so the speed-up stops growing once workers outnumber cores. Over a real
    network most of a scan is *waiting* for replies, and there more workers
    keep helping.

The job runs against 127.0.0.1 by default (a few fake services are opened
so there is something to find). You can benchmark another machine that you
own with --target, but then network latency is part of what you measure.

Run:
    python benchmark.py
    python benchmark.py --workers 1 2 3 --repeats 5 --ports 1-1200 --chunk-size 100
"""

import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime

from demo import CONTROLLER, WORKER, HERE, FAKE_SERVICE_PORTS, FakeServices


def port_set(spec):
    """'1-600,8080' -> {1..600, 8080}"""
    ports = set()
    for part in spec.split(","):
        low, _, high = part.partition("-")
        ports.update(range(int(low), int(high or low) + 1))
    return ports


def nmap_version():
    try:
        out = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=10).stdout
        return out.splitlines()[0].replace("Nmap version ", "Nmap ") if out else "Nmap (version unknown)"
    except (OSError, subprocess.SubprocessError):
        return "Nmap (not found)"


def run_once(worker_count, args, workdir, run_label, port):
    """Run controller + N workers once; return (elapsed_seconds, report dict)."""
    out_json = os.path.join(workdir, f"{run_label}.json")
    cmd = [sys.executable, CONTROLLER, "--target", f"{args.target}:{args.ports}",
           "--chunk-size", str(args.chunk_size), "--port", str(port),
           "--min-workers", str(worker_count), "--output", out_json, "--no-html", "--no-color",
           "--task-timeout", "120"]
    if args.i_have_permission:
        cmd.append("--i-have-permission")

    controller = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    workers = [
        subprocess.Popen([sys.executable, WORKER, "--host", "127.0.0.1", "--port", str(port),
                          "--name", f"worker-{i}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for i in range(1, worker_count + 1)
    ]
    try:
        _, err = controller.communicate(timeout=600)
    finally:
        for proc in workers:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
    if controller.returncode != 0:
        raise RuntimeError(f"controller exited with code {controller.returncode}: {err.strip()[:300]}")
    with open(out_json, encoding="utf-8") as handle:
        report = json.load(handle)
    return report["meta"]["elapsed_seconds"], report


def main():
    parser = argparse.ArgumentParser(description="Benchmark 1 worker vs N workers")
    parser.add_argument("--workers", type=int, nargs="+", default=[1, 3], help="worker counts to compare (default: 1 3)")
    parser.add_argument("--target", default="127.0.0.1", help="host to scan (default 127.0.0.1)")
    parser.add_argument("--ports", default="1-300,1000-1199",
                        help="ports to scan, e.g. 1-300,1000-1199 (default; includes three fake services)")
    parser.add_argument("--chunk-size", type=int, default=50, help="ports per task (default 50)")
    parser.add_argument("--repeats", type=int, default=3, help="runs per setup (default 3)")
    parser.add_argument("--port", type=int, default=5055, help="controller port (default 5055)")
    parser.add_argument("--no-listeners", action="store_true", help="do not open fake services on localhost")
    parser.add_argument("--i-have-permission", action="store_true",
                        help="needed only for non-private targets: confirms you may scan them")
    args = parser.parse_args()

    services = None
    expected = []
    if args.target == "127.0.0.1" and not args.no_listeners:
        services = FakeServices(FAKE_SERVICE_PORTS).start()
        in_range = port_set(args.ports)
        expected = [p for p in services.opened if p in in_range]  # only ports inside the scanned range
        print(f"Opened fake services on 127.0.0.1: {services.opened} (expected in this scan: {expected})")

    print(f"Workload: scan {args.target} ports {args.ports} in chunks of {args.chunk_size}; "
          f"setups {args.workers}; {args.repeats} repeat(s) each")
    print("Note: scanning localhost on Windows is slow (roughly 0.15 s per port per worker), so this can take "
          "several minutes. Use a smaller --ports range for a quicker run.\n")

    times = {n: [] for n in args.workers}
    problems = []
    run_number = 0  # each run gets its own controller port, so a previous run can never get in the way
    try:
        with tempfile.TemporaryDirectory() as workdir:
            for rep in range(1, args.repeats + 1):
                order = args.workers if rep % 2 else list(reversed(args.workers))  # alternate order
                for n in order:
                    run_number += 1
                    elapsed, report = run_once(n, args, workdir, f"w{n}-r{rep}", args.port + run_number % 500)
                    found = {p["port"] for ports in report["hosts"].values() for p in ports}
                    missing = [p for p in expected if p not in found]
                    flag = "" if not missing else f"  !! MISSING open ports {missing}"
                    if missing:
                        problems.append(f"{n} worker(s), repeat {rep}: missing {missing}")
                    done = f"{report['summary']['tasks_done']}/{report['summary']['tasks_total']} tasks"
                    print(f"  repeat {rep}: {n} worker(s) -> {elapsed:6.2f} s   ({done}, "
                          f"{report['summary']['open_ports_total']} open ports found){flag}")
                    times[n].append(elapsed)
                    time.sleep(0.3)
    finally:
        if services:
            services.stop()

    base = statistics.median(times[args.workers[0]])
    print("\nResults (median of repeats)")
    print(f"  {'workers':>7}  {'median (s)':>10}  {'min (s)':>8}  {'max (s)':>8}  {'speed-up':>9}")
    lines = []
    for n in args.workers:
        med = statistics.median(times[n])
        speed = base / med
        print(f"  {n:>7}  {med:>10.2f}  {min(times[n]):>8.2f}  {max(times[n]):>8.2f}  {speed:>8.2f}x")
        lines.append((n, med, min(times[n]), max(times[n]), speed))

    env = (f"{platform.system()} {platform.release()}, Python {platform.python_version()}, "
           f"{nmap_version()}, {os.cpu_count()} CPU(s)")
    print("\nCopy-paste block for your report (it states where the numbers came from):\n")
    print(f"Environment: {env}.")
    print(f"Workload: {args.target}, ports {args.ports}, chunks of {args.chunk_size} ports; "
          f"{args.repeats} repeat(s) per setup, median reported; measured {datetime.now():%Y-%m-%d}.\n")
    print("| Workers | Median time (s) | Min (s) | Max (s) | Speed-up vs. 1 worker |")
    print("|---------|-----------------|---------|---------|-----------------------|")
    for n, med, lo, hi, speed in lines:
        print(f"| {n} | {med:.2f} | {lo:.2f} | {hi:.2f} | {speed:.2f}x |")

    os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
    out = os.path.join(HERE, "results", "benchmark_results.json")
    with open(out, "w", encoding="utf-8") as handle:
        json.dump({"environment": env, "target": args.target, "ports": args.ports, "chunk_size": args.chunk_size,
                   "repeats": args.repeats, "times_seconds": {str(k): v for k, v in times.items()},
                   "problems": problems, "measured_at": datetime.now().isoformat(timespec="seconds")},
                  handle, indent=2)
    print(f"\nRaw numbers saved to {out}")
    if problems:
        print("WARNING: some runs missed expected open ports:\n  " + "\n  ".join(problems))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
