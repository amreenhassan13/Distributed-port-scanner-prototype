# Project Proposal – Distributed Port Scanner

**Title:** Distributed Port Scanner: A Framework for Efficient Network Reconnaissance  
**Author:** Amreen Hassan 


## Problem Statement
Traditional single-threaded port scanning methods are slow for large networks. A distributed approach can speed up scanning and improve efficiency.

## Objective
To design and implement a distributed port scanning system that uses multiple worker nodes to scan IP ranges in parallel using Nmap.

## Scope
- Internal lab network testing only.
- Supports TCP scans.
- Modular design for adding more workers.

## Tools & Technologies
- Python 3.x
- Nmap & python-nmap library
- Sockets for communication
- Virtual Machines (VMware/VirtualBox)
