"""
log_analyzer.py
Parses a Linux SSH authentication log and flags suspicious login activity.

Detections:
  BRUTE_FORCE     - an IP exceeds N failed logins inside a sliding time window
  PASSWORD_SPRAY  - an IP attempts many distinct usernames
  POSSIBLE_COMPROMISE - an IP with repeated failures later logs in successfully
  INVALID_USER    - attempts against usernames that don't exist on the system

Usage:
    python log_analyzer.py sample_auth.log
    python log_analyzer.py sample_auth.log --threshold 10 --window 60 --csv report.csv
"""

import argparse
import csv
import re
import sys
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime

# Example line:
# Oct 27 02:14:00 app-server-01 sshd[4521]: Failed password for invalid user admin from 203.0.113.45 port 51234 ssh2
LINE_PATTERN = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) \S+ sshd\[\d+\]: "
    r"(?P<result>Failed|Accepted) password for (?P<invalid>invalid user )?"
    r"(?P<user>\S+) from (?P<ip>[\d.]+) port \d+"
)

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


@dataclass
class Event:
    ts: datetime
    success: bool
    user: str
    ip: str
    invalid_user: bool


@dataclass
class Alert:
    severity: str
    type: str
    ip: str
    detail: str
    first_seen: datetime


def parse_log(path, year):
    """Read the log file and return a list of Events. Unmatched lines are skipped."""
    events, skipped = [], 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = LINE_PATTERN.match(line)
            if not m:
                skipped += 1
                continue
            # auth.log has no year, so we supply one
            ts = datetime.strptime(f"{year} {m['ts']}", "%Y %b %d %H:%M:%S")
            events.append(Event(
                ts=ts,
                success=m["result"] == "Accepted",
                user=m["user"],
                ip=m["ip"],
                invalid_user=bool(m["invalid"]),
            ))
    events.sort(key=lambda e: e.ts)
    return events, skipped


def detect_brute_force(events, threshold, window_sec):
    """Sliding window: flag an IP if it has >= threshold failures within window_sec."""
    alerts = []
    windows = defaultdict(deque)
    already_flagged = set()
    for e in events:
        if e.success:
            continue
        q = windows[e.ip]
        q.append(e.ts)
        while (e.ts - q[0]).total_seconds() > window_sec:
            q.popleft()
        if len(q) >= threshold and e.ip not in already_flagged:
            already_flagged.add(e.ip)
            alerts.append(Alert("HIGH", "BRUTE_FORCE", e.ip,
                                f"{len(q)} failed logins within {window_sec}s", q[0]))
    return alerts


def detect_password_spray(events, min_users, window_sec):
    """Flag an IP that fails against min_users+ distinct usernames within window_sec."""
    alerts = []
    windows = defaultdict(deque)          # ip -> deque of (ts, user) failures
    already_flagged = set()
    for e in events:
        if e.success:
            continue
        q = windows[e.ip]
        q.append((e.ts, e.user))
        while (e.ts - q[0][0]).total_seconds() > window_sec:
            q.popleft()
        users = {u for _, u in q}
        if len(users) >= min_users and e.ip not in already_flagged:
            already_flagged.add(e.ip)
            alerts.append(Alert("HIGH", "PASSWORD_SPRAY", e.ip,
                                f"{len(users)} distinct usernames tried within {window_sec}s "
                                f"(e.g. {', '.join(sorted(users)[:4])})",
                                q[0][0]))
    return alerts


def detect_compromise(events, min_failures, window_sec):
    """Flag a successful login from an IP with min_failures+ failures in the preceding window."""
    alerts = []
    recent_failures = defaultdict(deque)  # ip -> deque of failure timestamps
    for e in events:
        q = recent_failures[e.ip]
        while q and (e.ts - q[0]).total_seconds() > window_sec:
            q.popleft()
        if not e.success:
            q.append(e.ts)
        else:
            if len(q) >= min_failures:
                alerts.append(Alert("HIGH", "POSSIBLE_COMPROMISE", e.ip,
                                    f"login as '{e.user}' succeeded after {len(q)} "
                                    f"failures in the previous {window_sec}s", e.ts))
            q.clear()                     # a success resets the counter
    return alerts


def detect_invalid_users(events, min_attempts):
    """Flag IPs probing for usernames that don't exist."""
    counts = defaultdict(int)
    first_seen = {}
    for e in events:
        if e.invalid_user:
            counts[e.ip] += 1
            first_seen.setdefault(e.ip, e.ts)
    return [
        Alert("MEDIUM", "INVALID_USER", ip, f"{n} attempts on non-existent accounts", first_seen[ip])
        for ip, n in counts.items() if n >= min_attempts
    ]


def summarize(events):
    total = len(events)
    failures = sum(1 for e in events if not e.success)
    return {
        "total_events": total,
        "failed_logins": failures,
        "successful_logins": total - failures,
        "unique_ips": len({e.ip for e in events}),
    }


def print_report(summary, alerts, skipped):
    print("=" * 72)
    print(" SSH AUTHENTICATION LOG ANALYSIS")
    print("=" * 72)
    print(f" Events parsed      : {summary['total_events']:,}  (skipped lines: {skipped})")
    print(f" Successful logins  : {summary['successful_logins']:,}")
    print(f" Failed logins      : {summary['failed_logins']:,}")
    print(f" Unique source IPs  : {summary['unique_ips']}")
    print("-" * 72)
    if not alerts:
        print(" No suspicious activity detected.")
        return
    print(f" ALERTS ({len(alerts)})")
    for a in alerts:
        print(f"  [{a.severity:<6}] {a.type:<20} {a.ip:<16} {a.first_seen:%m-%d %H:%M:%S}")
        print(f"           {a.detail}")
    print("=" * 72)


def write_csv(alerts, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["severity", "type", "source_ip", "first_seen", "detail"])
        for a in alerts:
            w.writerow([a.severity, a.type, a.ip, a.first_seen.isoformat(), a.detail])
    print(f" Alerts exported to {path}")


def main():
    p = argparse.ArgumentParser(description="Detect suspicious activity in SSH auth logs.")
    p.add_argument("logfile", help="path to auth.log-style file")
    p.add_argument("--threshold", type=int, default=10, help="failures that trigger brute-force alert")
    p.add_argument("--window", type=int, default=60, help="brute-force time window in seconds")
    p.add_argument("--spray-users", type=int, default=5, help="distinct usernames that trigger spray alert")
    p.add_argument("--compromise-failures", type=int, default=5,
                   help="prior failures before a success counts as possible compromise")
    p.add_argument("--lookback", type=int, default=600,
                   help="window in seconds for spray and compromise detection")
    p.add_argument("--year", type=int, default=datetime.now().year, help="year for log timestamps")
    p.add_argument("--csv", help="optional path to export alerts as CSV")
    args = p.parse_args()

    try:
        events, skipped = parse_log(args.logfile, args.year)
    except FileNotFoundError:
        sys.exit(f"Error: file not found: {args.logfile}")

    alerts = (
        detect_brute_force(events, args.threshold, args.window)
        + detect_password_spray(events, args.spray_users, args.lookback)
        + detect_compromise(events, args.compromise_failures, args.lookback)
        + detect_invalid_users(events, args.threshold)
    )
    alerts.sort(key=lambda a: (SEVERITY_ORDER[a.severity], a.first_seen))

    print_report(summarize(events), alerts, skipped)
    if args.csv:
        write_csv(alerts, args.csv)


if __name__ == "__main__":
    main()
