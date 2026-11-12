# SSH Log Analyzer (Brute-Force Detector)

Parses Linux authentication logs and flags IPs with many failed logins.

## Features
- Regex-based parsing of failed/successful SSH logins
- Counts failures per IP and number of usernames tried
- Configurable threshold for flagging suspicious IPs
- Suggests firewall block commands

## Usage
```bash
python generate_sample_log.py          # creates a fake auth.log
python log_analyzer.py auth.log -t 10
# On a real Linux machine: sudo python log_analyzer.py /var/log/auth.log
```

## How it works
Each line is matched with a regex, IPs are counted with `collections.Counter`,
and any IP at or above the threshold is reported as a possible brute-force source.

## Future improvements
Time-window detection, GeoIP lookup, email alerts, auto-blocking.
