# Testing Plan

## Automated tests

```
python -m unittest discover -s tests -v
```

| Area | What is checked |
|---|---|
| Message framing | a ~6 MB message arrives intact; two messages in one chunk are read separately; one message split over two sends is reassembled; a closed connection raises an error |
| Worker results | only `open` ports are kept (closed and filtered are dropped), empty service names become `unknown`; host down and "host listed as down" give `host_down`; missing Nmap and unexpected exceptions give an `error` result instead of a crash; option-injection attempts are refused |
| Controller helpers | port parsing and bounds, port chunking, target forms (`host:ports`, `host ports`, `host`), targets-file comments, private-address guard |

These tests replace Nmap with small stand-in classes, so they run without Nmap installed.

## Scenario tests (run with the real controller, workers and Nmap)

| # | Scenario | How | Expected |
|---|---|---|---|
| 1 | Normal parallel run | `python demo.py` | all tasks done, 6 demo ports found, timeline rows overlap |
| 2 | Worker crashes mid-task | `python demo.py --crash` | "task ... put back on the queue", all tasks done, 1 retried attempt |
| 3 | Worker stops answering | `python demo.py --hang` | timeout after 5 s, task re-queued, all tasks done |
| 4 | All workers lost | start a controller with `--idle-timeout 3`, then one worker with `--simulate-crash-on-nth-task 1` | controller gives up after 3 s, reports incomplete tasks, exit code 1 |
| 5 | Worker keeps failing | worker with `--nmap-args=--bogus` | 3 attempts, then task `failed`, exit code 1, no hang |
| 6 | Large result | 400 listening ports in one task | all 400 received (about 31 KB, far beyond the old 8192-byte limit) |
| 7 | Ctrl+C on the controller | interrupt with no workers | partial report written, exit code 1 |
| 8 | Invalid input | public IP without `--i-have-permission`; port `0-99999`; no targets | clear error message, exit code 2 |
| 9 | Port already in use | start two controllers on one port | clear error message |
| 10 | Worker starts before controller | start the worker first | worker retries every second and connects when the controller appears |

Scenarios 1-10 were run on a Linux test machine during development. Re-run 1-3 on your own computer (Windows) before relying on this document.

## Performance testing

```
python benchmark.py
```

Runs the same job with 1, 2 and 3 workers on `127.0.0.1` (5 repeats are recommended: `--repeats 5`), alternating the order, and reports the median time and the speed-up relative to 1 worker. Interpretation notes are in the README. The benchmark checks that every run found all of the demo's open ports, so a fast run that skipped work is flagged.
