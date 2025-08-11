# Requirements Specification

## Functional Requirements
1. Controller divides IP/port ranges into chunks.
2. Workers scan assigned chunks using Nmap.
3. Workers send results back to controller.
4. Controller compiles results into a final report.

## Non-functional Requirements
- Scalability: Should handle multiple workers.
- Efficiency: Parallel execution.
- Security: Limit scans to authorized networks.

## System Requirements
- OS: Linux/Kali or Windows
- Python 3.8+
- Nmap installed
