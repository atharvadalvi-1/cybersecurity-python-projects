"""Creates a fake SSH auth.log for testing the analyzer."""
import random
from datetime import datetime, timedelta

users = ["root", "admin", "ubuntu", "atharva", "test"]
attackers = ["203.0.113.45", "198.51.100.23"]
normal_ips = ["192.168.1.10", "192.168.1.15", "192.168.1.20"]
t = datetime(2026, 11, 12, 9, 0, 0)
lines = []
for _ in range(300):
    t += timedelta(seconds=random.randint(1, 40))
    ts = t.strftime("%b %d %H:%M:%S")
    r = random.random()
    if r < 0.45:   # brute-force attacker
        ip, u = random.choice(attackers), random.choice(users)
        lines.append(f"{ts} server sshd[1234]: Failed password for {u} from {ip} port {random.randint(30000,60000)} ssh2")
    elif r < 0.48: # honest typo
        ip = random.choice(normal_ips)
        lines.append(f"{ts} server sshd[1234]: Failed password for atharva from {ip} port 50022 ssh2")
    else:
        ip = random.choice(normal_ips)
        lines.append(f"{ts} server sshd[1234]: Accepted password for atharva from {ip} port 50022 ssh2")
open("auth.log", "w").write("\n".join(lines) + "\n")
print("auth.log created with", len(lines), "lines")
