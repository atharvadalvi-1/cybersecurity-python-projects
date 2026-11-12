# Python Port Scanner

A multithreaded TCP port scanner built with Python's `socket` module.

## Features
- Scans a range of ports on a target host
- Multithreading (ThreadPoolExecutor) for fast scanning
- Maps well-known ports to services (SSH, HTTP, etc.)
- Basic banner grabbing

## Usage
```bash
python port_scanner.py 127.0.0.1
python port_scanner.py scanme.nmap.org -s 1 -e 1000 -t 200
```

## How it works
1. Create a TCP socket for each port.
2. `connect_ex()` returns 0 if the port accepts the connection (open).
3. A thread pool runs many checks in parallel.
4. Open ports are listed with service name and banner.

## Legal note
Only scan systems you own or have permission to test.

## Future improvements
UDP scanning, OS detection, export results to CSV/JSON.
