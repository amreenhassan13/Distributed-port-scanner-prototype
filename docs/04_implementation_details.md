# Implementation Details

## Technology Stack

- Python 3.8+ (standard library only, plus `python-nmap`)
- `socket` and `threading` for communication and concurrency
- Nmap (run through `python-nmap`) for scanning
- JSON (newline-delimited) for messages; JSON and a self-contained HTML page for reports

## File Descriptions

| File | Purpose |
|---|---|
| `controller/controller.py` | Targets and task creation, thread-per-worker server, queue, timeouts and re-queue, live log, summary, ASCII timeline, JSON/HTML reports |
| `worker/worker.py` | Connects to the controller, loops over tasks, runs Nmap, keeps only open ports, turns every failure into a clear error result |
| `demo.py` | Local demo: fake services on 127.0.0.1, controller and N workers, optional `--crash` / `--hang` |
| `benchmark.py` | Runs the same job with different worker counts and prints times and speed-up |
| `tests/test_scanner.py` | Unit tests for framing, worker behaviour, input validation and target parsing |

## Important design decisions

1. **Newline-delimited JSON framing.** Replaces `recv(8192)`. Each side keeps a byte buffer and splits it at `\n`, so messages of any size (up to 16 MB) arrive whole.
2. **One thread per worker connection.** Removes the "serve one worker at a time" bottleneck. The task queue is `queue.Queue` (thread-safe); a `threading.Lock` guards counters and results.
3. **Persistent worker connections.** A worker handles many tasks over one connection instead of one task per connection.
4. **Timeouts and re-queueing.** The controller sets the socket timeout to `--task-timeout` while waiting for a result. Any failure while a worker holds a task puts the task back on the queue (limited by `--max-attempts`).
5. **Start barrier (`--min-workers`).** Workers wait until enough have connected before the clock starts, so measured time does not include staggered start-up.
6. **Open ports only.** The worker keeps ports whose Nmap state is `open` and reports `{host, port, protocol, service}`. A host Nmap marks as down is reported as `host_down`, never as "scanned, nothing found".
7. **TCP connect scan (`-sT`).** Works without administrator rights on Windows and Linux. Service names come from Nmap's port table; add `--nmap-args="-sT -sV"` on the worker for version detection.
8. **Input validation on both sides.** Ports must look like `22,80,1000-2000` (1-65535); hosts must match a conservative pattern. This also prevents option injection into the Nmap command line.
9. **Evidence of how it works.** The controller logs every dispatch and result, prints a per-worker table and an ASCII timeline, and saves the same data (including every attempt with start/end times) in JSON and HTML.

## Not implemented

UDP scans, authentication/encryption, a persistent task store, dynamic task sizing, and a controller that survives its own crash.
