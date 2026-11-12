"""
SSH Log Analyzer - detects brute-force attempts.
Usage: python log_analyzer.py auth.log [-t THRESHOLD]
"""
import re
import argparse
from collections import Counter, defaultdict

FAILED = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
ACCEPTED = re.compile(r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)")

def analyze(path, threshold):
    fails = Counter()
    users_tried = defaultdict(set)
    success = Counter()
    with open(path) as f:
        for line in f:
            m = FAILED.search(line)
            if m:
                user, ip = m.groups()
                fails[ip] += 1
                users_tried[ip].add(user)
                continue
            m = ACCEPTED.search(line)
            if m:
                success[m.group(2)] += 1

    print(f"Total failed logins : {sum(fails.values())}")
    print(f"Total successful    : {sum(success.values())}\n")
    print(f"{'IP ADDRESS':<18}{'FAILED':<9}{'USERS TRIED':<13}STATUS")
    print("-" * 55)
    suspicious = []
    for ip, n in fails.most_common():
        status = "SUSPICIOUS" if n >= threshold else "ok"
        if n >= threshold:
            suspicious.append(ip)
        print(f"{ip:<18}{n:<9}{len(users_tried[ip]):<13}{status}")

    print(f"\nFlagged {len(suspicious)} IP(s) with >= {threshold} failed attempts.")
    for ip in suspicious:
        extra = " (also had a successful login - investigate!)" if ip in success else ""
        print(f"  [!] {ip}: possible brute force{extra}")
        print(f"      Suggested action: sudo ufw deny from {ip}")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("logfile")
    p.add_argument("-t", "--threshold", type=int, default=10)
    a = p.parse_args()
    analyze(a.logfile, a.threshold)
