# Final Report – Distributed Port Scanner

## Introduction
This project implements a distributed port scanning system. A controller splits a scan into tasks and hands them to multiple worker processes, each of which runs Nmap on its task and returns the open ports. The goal was to show how a controller/worker architecture lets several scans run at the same time instead of one after another, and to measure what that is worth. The system is a student prototype: it is small, readable, and uses only Python's standard library plus `python-nmap`.

## Methodology
The distributed architecture consists of:
- A **controller** that builds a list of scan tasks (a host plus a slice of its ports), listens on a TCP socket, and starts one thread for every connected worker. All threads take tasks from one shared, thread-safe queue, so workers are served concurrently.
- Multiple **workers** (separate processes, on the same or on other machines) that connect to the controller, receive tasks one after another over a single connection, run Nmap with `python-nmap`, and send back only the ports whose state is `open` (port, protocol, service name).
- A **message protocol** based on newline-delimited JSON, so that results of any size arrive complete.
- **Fault tolerance:** every task has a timeout. If a worker crashes, disconnects, stops answering or reports an error, the task goes back on the queue and is retried by any available worker, up to a configurable limit. Unreachable hosts are reported as `host_down`; missing or failing Nmap is reported as an error result instead of crashing the worker.
- The controller merges all results into one summary, prints a live log and an ASCII timeline of which worker scanned what and when, and saves the run as JSON and as an HTML report.

Testing was done on a single computer using `127.0.0.1`: the worker processes and the scanned target were on the same machine, and a few harmless fake services were opened locally so that the scans had open ports to find. Behaviour under failure was tested by making a worker crash, hang, or return Nmap errors on purpose (see `docs/05_testing_plan.md`). The system was **not** tested on multiple physical or virtual machines or on a larger network.

## Results
**Functional results.** In the test runs, all tasks were completed and all of the open ports that had been opened for the test were found. A task whose result contained 400 open ports (about 31 KB, far above the 8192 bytes that the first version could receive) arrived complete. When a worker was made to crash while it held a task, the controller re-queued the task and another worker finished it, so the scan still completed. When a worker was made to stop answering, the controller gave up on it after the configured timeout and re-queued the task. When a worker's Nmap produced errors every time, the task was retried three times and then reported as failed, without hanging the controller. 15 automated unit tests (framing, open-port filtering, error handling, input validation) pass, on Linux and on Windows 11.

**Timing results.** The benchmark script (`benchmark.py`) runs the same job with different numbers of workers, alternating the order over several repeats, and reports the median of the time the controller needed from the first task being sent to the last result arriving. It was run on two computers.

*Windows 11 (the project author's computer).* Environment: Windows 11, Python 3.14.8, Nmap 7.80, 8 CPU cores. Job: `127.0.0.1`, ports 1-300 and 1000-1199 (500 ports), split into 10 tasks of 50 ports; 3 repeats per setup, median reported; measured 2026-10-06. All 10 tasks completed in every run and all three fake services opened for the test were found.

| Workers | Median time (s) | Min (s) | Max (s) | Speed-up vs. 1 worker |
|---------|-----------------|---------|---------|-----------------------|
| 1 | 116.76 | 114.71 | 118.53 | 1.00x |
| 3 | 45.36 | 45.19 | 45.67 | 2.57x |

Three workers needed 45 s for a job that took one worker 117 s, a speed-up of 2.57x against an ideal of 3x. The shortfall is expected: 10 tasks cannot be shared evenly by 3 workers (one has to take 4), and the controller adds a little overhead. The repeats of each setup agree within about 3 s. Scanning localhost with Nmap is slow on Windows (about 0.23 s per port for one worker here), which is why the job is small.

*Linux (test machine used during development).* Environment: Linux 6.18, Python 3.13.16, Nmap 7.94, 2 CPU cores. Job: `127.0.0.1`, ports 1-30000, split into 20 tasks of 1500 ports; 5 repeats per setup, median reported; measured 2026-10-06. The job is much bigger because Linux scans localhost far faster.

| Workers | Median time (s) | Min (s) | Max (s) | Speed-up vs. 1 worker |
|---------|-----------------|---------|---------|-----------------------|
| 1 | 1.22 | 1.12 | 1.36 | 1.00x |
| 2 | 0.61 | 0.55 | 0.81 | 1.99x |
| 3 | 0.65 | 0.59 | 0.77 | 1.87x |

On both computers, more workers made the scan faster, which shows that the workers really run concurrently (in the first version they ran one after another). On the 2-core Linux machine a third worker did not help beyond two: the workers and their Nmap processes compete for the same two cores. These figures describe scanning the local machine from one computer. They do not show how the system behaves on a real network, where scan time is mostly spent waiting for replies and additional workers can be expected to help for longer; that was not measured.

## Conclusion
The prototype shows that a thread-per-worker controller with a shared task queue lets several Nmap scans run concurrently, and on the author's Windows 11 computer three workers finished the benchmark job in about 45 s instead of about 117 s with one worker (2.57x faster); on a 2-core Linux machine two workers halved the scan time of a different job, from about 1.2 s to about 0.6 s. It also handles the failures that the first version could not: crashed or silent workers no longer hang the controller or lose tasks, unreachable hosts and Nmap errors produce clear results, and long results are no longer truncated.

The main limitations are: a single controller (if it stops, the run is lost); no authentication or encryption between controller and workers; TCP connect scans only; fixed-size tasks that can leave workers idle at the end of a run; and no measurements beyond a single computer scanning itself, so nothing in this report claims how the system scales on large networks or on several physical machines.

**Future work** may include:
- Testing on several physical or virtual machines and on a real network, to measure scaling where waiting for the network dominates.
- Authentication and encryption between controller and workers (for example a shared secret and TLS).
- UDP scans and Nmap service version detection by default.
- Adaptive task sizes and persistent task storage so that a controller restart does not lose a run.
- Replacing the raw sockets with a message queue system (RabbitMQ or ZeroMQ) if the project grows.
