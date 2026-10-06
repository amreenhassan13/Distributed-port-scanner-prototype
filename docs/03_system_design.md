# System Design

## Architecture

```
              +------------------------ CONTROLLER ------------------------+
 targets ---> |  task queue  ->  one thread per worker connection           |
              |  timeouts, re-queue, retry limit  ->  results + reports     |
              +-----+------------------------+-------------------------+----+
                    | TCP, newline-delimited JSON                        |
                 WORKER 1                  WORKER 2        ...       WORKER N
                  (nmap)                    (nmap)                    (nmap)
```

* **Controller** - builds the task list, accepts worker connections, hands out tasks, collects results, repairs failures, writes the reports.
* **Worker** - connects to the controller, receives a task, runs Nmap, returns only the open ports. It keeps one connection open for many tasks.
* **Task** - one unit of work: a host (or range) plus a port list, for example `127.0.0.1` ports `1001-1500`. `--chunk-size` cuts a long port range into several tasks so more workers can help.

## Sequence

1. The controller starts, validates the targets, fills the task queue and listens on TCP 5055.
2. A worker connects and sends `hello` with its name. The controller starts a dedicated thread for it.
3. When `--min-workers` workers are connected (or the wait timeout passes), the controller starts its clock and releases all worker threads at the same moment.
4. Each worker thread loops: take a task from the queue -> send it -> wait for the result (with a timeout) -> store it.
5. The worker scans with Nmap and replies with a `result` message (open ports only, or an error status).
6. When every task is finished, each thread sends `no_more_tasks`; the controller prints the summary and writes the JSON and HTML reports.

## Why threads?

The original controller was a single loop: accept a worker, wait for its answer, then accept the next one. Workers therefore ran one after another. With one thread per worker connection, a thread that is waiting for its worker's answer blocks only itself, so all workers scan at the same time. The shared task queue (`queue.Queue`) is thread-safe, so two threads never receive the same task; a lock protects the other shared data (counters, results).

## Task life cycle

```
 pending --(sent to a worker)--> running --(ok / host_down)--------------> done
    ^                               |
    |                               +--(timeout, disconnect, bad message, Nmap error)
    +------ re-queued (attempts < max) <-------+          |
                                                           +--(attempts = max)--> failed
```

* `host_down` is a finished result, not a failure: the target simply did not answer.
* Timeouts, disconnects, malformed replies and worker-side errors count as failed attempts. The task is re-queued, up to `--max-attempts` (default 3), then marked `failed`.

## Message protocol

One JSON object per line (newline-delimited JSON). TCP is a byte stream, so a single `recv()` may return part of a message or several messages. Both sides therefore buffer incoming bytes and cut them at newlines, which means a long result can never be truncated.

| Direction | Message |
|---|---|
| worker -> controller | `{"type":"hello","worker":"worker-1","pid":1234}` |
| controller -> worker | `{"type":"task","task_id":3,"ip":"127.0.0.1","ports":"1001-1500","attempt":1}` |
| worker -> controller | `{"type":"result","task_id":3,"status":"ok","open_ports":[{"host","port","protocol","service"}],"error":null,"scan_seconds":0.14}` |
| controller -> worker | `{"type":"no_more_tasks"}` |

`status` is `ok`, `host_down` or `error`. A message larger than 16 MB is refused.

## Failure handling summary

| Failure | Detected by | Reaction |
|---|---|---|
| Worker process killed | closed connection while waiting | task re-queued |
| Worker hangs | socket timeout (`--task-timeout`) | connection closed, task re-queued |
| Nmap missing / Nmap error | `status: "error"` in the result | task re-queued, then `failed` after the retry limit |
| Garbage reply | protocol validation | task re-queued |
| No workers left | `--idle-timeout` | controller stops and reports partial results |

## Security notes

* No authentication or encryption: use localhost or a trusted network. The controller listens on `127.0.0.1` by default.
* The worker only accepts targets and port lists that match strict patterns, so a task cannot smuggle extra options into the Nmap command line.
* The controller refuses non-private targets unless `--i-have-permission` is given (a reminder, not a security boundary).
