# Testing Plan

## Test Cases
1. Single worker scanning small range.
2. Multiple workers scanning different ranges.
3. Error handling when worker disconnects.

## Performance Testing
Compare scan time:
- Single Nmap process
- Distributed with 2 workers
- Distributed with 4 workers
