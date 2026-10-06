# User Guide

## Prerequisites

- Python 3.8 or newer
- Nmap installed and reachable (`nmap --version` works in a new terminal)
- `pip install -r requirements.txt`

Only scan machines and networks you own or have explicit permission to scan.

## Fastest way to see it work

```powershell
python demo.py
```

Then open `results\demo.html` in a browser.

## Running the project manually

1. Start the controller (it waits for 3 workers, then starts the clock):

   ```powershell
   python controller/controller.py --target 127.0.0.1:1-1000 --chunk-size 125 --min-workers 3
   ```

2. Start each worker in its own terminal:

   ```powershell
   python worker/worker.py --host 127.0.0.1 --port 5055 --name worker-1
   python worker/worker.py --host 127.0.0.1 --port 5055 --name worker-2
   python worker/worker.py --host 127.0.0.1 --port 5055 --name worker-3
   ```

3. Watch the controller terminal: live log, summary, timeline and total elapsed time. Reports are saved to `results/scan_results.json` and `results/scan_results.html`.

## Choosing targets

- `--target HOST:PORTS` (repeatable), e.g. `--target 127.0.0.1:20-25 --target 127.0.0.1:80,443`
- `--targets-file targets.txt` with one `host ports` per line (see `targets.example.txt`)
- `--chunk-size N` splits long port ranges into tasks of N ports so that several workers can share one target

## Using other machines

Start the controller with `--bind 0.0.0.0` and run workers with `--host <controller address>`. There is no authentication, so use a trusted network only, and scan only systems you are allowed to scan (non-private targets also need `--i-have-permission`).

## Checking the speed-up

```powershell
python benchmark.py
```

## Speed note (Windows)

Scanning localhost on Windows is slow: expect very roughly 0.15 s of worker time per port (the demo's 1-1800 ports take a couple of minutes with 3 workers). Use smaller `--ports` ranges while experimenting.

## Troubleshooting

| Message | Meaning |
|---|---|
| `cannot listen on ...: Address already in use` (or a Windows "access permissions" error) | another controller is already running on that port; close that window (Ctrl+C), or use `--port` |
| `still waiting for workers (0/3)` | start the workers, or lower `--min-workers` |
| `Nmap was not found on this worker` | install Nmap and open a new terminal so PATH is refreshed |
| `host appears to be down or unreachable` | the target did not answer; check the address |
| `argument --nmap-args: expected one argument` | write it as `--nmap-args="-sT -sV"` (with `=`) |
