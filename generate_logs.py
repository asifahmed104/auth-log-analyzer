"""
generate_logs.py
Creates a synthetic Linux SSH authentication log (auth.log format) for testing.

The log mixes normal user activity with three injected attack scenarios:
  1. Brute force    - one IP hammering a single account
  2. Password spray - one IP trying many usernames
  3. Compromise     - repeated failures followed by a successful login

All IP addresses come from reserved documentation ranges (RFC 5737) or
private ranges, so no real hosts are referenced.

Usage:
    python generate_logs.py --lines 5000 --output sample_auth.log
"""

import argparse
import random
from datetime import datetime, timedelta

HOST = "app-server-01"
LEGIT_USERS = ["jsmith", "mgarcia", "alee", "dpatel", "kchen", "svc_backup"]
INTERNAL_IPS = [f"10.0.1.{i}" for i in range(10, 30)]
SPRAY_USERNAMES = ["admin", "root", "test", "oracle", "postgres", "ubuntu",
                   "guest", "user", "ftp", "deploy", "git", "support"]

BRUTE_FORCE_IP = "203.0.113.45"
SPRAY_IP = "198.51.100.77"
COMPROMISE_IP = "192.0.2.150"


def fmt(ts, pid, message):
    """Format one line in syslog auth.log style."""
    return f"{ts.strftime('%b %d %H:%M:%S')} {HOST} sshd[{pid}]: {message}"


def failed(user, ip, port, invalid=False):
    prefix = "invalid user " if invalid else ""
    return f"Failed password for {prefix}{user} from {ip} port {port} ssh2"


def accepted(user, ip, port):
    return f"Accepted password for {user} from {ip} port {port} ssh2"


def generate(total_lines, seed):
    rng = random.Random(seed)
    start = datetime(2026, 10, 27, 0, 0, 0)
    events = []

    # Each employee logs in from their own workstation (1-2 fixed internal IPs)
    user_ips = {u: rng.sample(INTERNAL_IPS, rng.randint(1, 2)) for u in LEGIT_USERS}

    # Normal background traffic spread across 24 hours
    normal_count = int(total_lines * 0.85)
    for _ in range(normal_count):
        ts = start + timedelta(seconds=rng.randint(0, 86_399))
        user = rng.choice(LEGIT_USERS)
        ip = rng.choice(user_ips[user])
        port = rng.randint(40000, 65000)
        # Most legit logins succeed; occasional typo
        if rng.random() < 0.92:
            events.append((ts, accepted(user, ip, port)))
        else:
            events.append((ts, failed(user, ip, port)))

    # Scenario 1: brute force on 'admin' account (~2 attempts/sec for 3 min)
    t = start + timedelta(hours=2, minutes=14)
    for i in range(360):
        events.append((t + timedelta(seconds=i * 0.5),
                       failed("admin", BRUTE_FORCE_IP, rng.randint(40000, 65000), invalid=True)))

    # Scenario 2: password spray - many usernames, slow pace (1 every 20s)
    t = start + timedelta(hours=9, minutes=3)
    for i in range(120):
        user = SPRAY_USERNAMES[i % len(SPRAY_USERNAMES)]
        events.append((t + timedelta(seconds=i * 20),
                       failed(user, SPRAY_IP, rng.randint(40000, 65000), invalid=True)))

    # Scenario 3: failures against a real account, then a success (likely compromise)
    t = start + timedelta(hours=21, minutes=47)
    for i in range(25):
        events.append((t + timedelta(seconds=i * 3),
                       failed("dpatel", COMPROMISE_IP, rng.randint(40000, 65000))))
    events.append((t + timedelta(seconds=80),
                   accepted("dpatel", COMPROMISE_IP, rng.randint(40000, 65000))))

    events.sort(key=lambda e: e[0])
    return [fmt(ts, rng.randint(1000, 9999), msg) for ts, msg in events]


def main():
    parser = argparse.ArgumentParser(description="Generate a synthetic SSH auth log.")
    parser.add_argument("--lines", type=int, default=5000, help="approximate number of normal events")
    parser.add_argument("--output", default="sample_auth.log", help="output file path")
    parser.add_argument("--seed", type=int, default=42, help="random seed for reproducibility")
    args = parser.parse_args()

    lines = generate(args.lines, args.seed)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Wrote {len(lines):,} log lines to {args.output}")


if __name__ == "__main__":
    main()
