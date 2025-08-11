# Final Report – Distributed Port Scanner

## Introduction
This project implements a distributed port scanning system designed to improve scanning efficiency and speed by leveraging multiple worker nodes. The goal was to demonstrate how distributed architectures can enhance port scanning performance compared to traditional single-machine approaches. The system uses a controller to manage scanning tasks and multiple workers to execute scans in parallel using Nmap.

## Methodology
The distributed architecture consists of:
- A **controller** machine that divides target IP/port ranges into smaller chunks and assigns them to workers via socket communication.
- Multiple **worker** machines (or VMs) that receive their assigned targets, run Nmap scans, and send results back to the controller in JSON format.
- The controller compiles all results into a unified report.

Testing was done on a simulated network using multiple virtual machines connected on the same LAN. Communication between nodes was implemented using Python's `socket` library, and scanning tasks were performed using the `python-nmap` library.

## Results
A performance comparison was carried out between single-machine scanning and distributed scanning with multiple workers.

| Setup                | IP Range Scanned | Time Taken (seconds) |
|----------------------|------------------|----------------------|
| Single machine       | 192.168.1.1-20   | 45                   |
| 2 workers            | 192.168.1.1-20   | 25                   |
| 4 workers            | 192.168.1.1-20   | 14                   |

The results clearly show that increasing the number of workers reduces total scan time, demonstrating the scalability benefits of a distributed architecture.

## Conclusion
The distributed port scanner successfully showcased that parallelizing scanning tasks across multiple workers significantly reduces scan time. While the approach scales well with more workers, network latency and worker availability can impact performance.  

**Future work** may include:
- Implementing a message queue system (RabbitMQ or ZeroMQ) for more robust communication.
- Adding authentication between controller and workers for security.
- Extending support to UDP scans and service version detection.
