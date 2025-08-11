# System Design

## Architecture
[Controller] → assigns IP/port ranges → [Worker Nodes] → sends results → [Controller compiles report]

## Sequence Diagram
1. Controller starts and waits for workers.
2. Worker connects and requests task.
3. Controller sends IP/port range.
4. Worker scans using Nmap.
5. Worker sends results back.
