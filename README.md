# SSH Authentication Log Analyzer

A Python command-line tool that parses Linux SSH authentication logs (`auth.log` format) and flags suspicious login activity, the kind of first-pass triage a SOC analyst performs during incident detection.

Built with the Python standard library only (no external dependencies).

## What it detects

| Alert | Severity | Logic | MITRE ATT&CK |
|---|---|---|---|
| `BRUTE_FORCE` | HIGH | One IP reaches ≥ N failed logins inside a sliding time window | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Password Guessing |
| `PASSWORD_SPRAY` | HIGH | One IP fails against ≥ N distinct usernames inside a window | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Password Spraying |
| `POSSIBLE_COMPROMISE` | HIGH | A successful login from an IP with repeated recent failures | [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts |
| `INVALID_USER` | MEDIUM | Repeated attempts on usernames that don't exist (account enumeration) | [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force |

## Quick start

```bash
# 1. Generate a synthetic test log (normal traffic + 3 injected attacks)
python generate_logs.py --output sample_auth.log

# 2. Analyze it
python log_analyzer.py sample_auth.log --year 2026

# 3. Export alerts to CSV
python log_analyzer.py sample_auth.log --year 2026 --csv alerts_report.csv
```

## Sample output

```
========================================================================
 SSH AUTHENTICATION LOG ANALYSIS
========================================================================
 Events parsed      : 4,756  (skipped lines: 0)
 Successful logins  : 3,907
 Failed logins      : 849
 Unique source IPs  : 10
------------------------------------------------------------------------
 ALERTS (6)
  [HIGH  ] BRUTE_FORCE          203.0.113.45     10-27 02:14:00
           10 failed logins within 60s
  [HIGH  ] PASSWORD_SPRAY       198.51.100.77    10-27 09:03:00
           5 distinct usernames tried within 600s (e.g. admin, oracle, postgres, root)
  [HIGH  ] BRUTE_FORCE          192.0.2.150      10-27 21:47:00
           10 failed logins within 60s
  [HIGH  ] POSSIBLE_COMPROMISE  192.0.2.150      10-27 21:48:20
           login as 'dpatel' succeeded after 25 failures in the previous 600s
  [MEDIUM] INVALID_USER         203.0.113.45     10-27 02:14:00
           360 attempts on non-existent accounts
  [MEDIUM] INVALID_USER         198.51.100.77    10-27 09:03:00
           120 attempts on non-existent accounts
========================================================================
```

All three injected attack scenarios were detected, with **zero false positives** across ~4,000 normal login events from internal users.

## Tuning options

| Flag | Default | Meaning |
|---|---|---|
| `--threshold` | 10 | Failures that trigger a brute-force alert |
| `--window` | 60 | Brute-force sliding window (seconds) |
| `--spray-users` | 5 | Distinct usernames that trigger a spray alert |
| `--compromise-failures` | 5 | Recent failures before a success is flagged |
| `--lookback` | 600 | Window (seconds) for spray and compromise checks |
| `--csv` | — | Export alerts to a CSV file |

## Design notes

- **Sliding windows instead of all-day totals.** My first version counted failures across the whole log, which flagged normal employees who mistyped passwords a few times over a day. Switching to time-windowed detection (using `collections.deque`) removed those false positives. This is the same precision-vs-recall trade-off real detection rules face.
- **Regex parsing** with named groups. Lines that don't match (other sshd messages) are counted and skipped rather than crashing.
- **Safe test data.** The generator uses only RFC 5737 documentation IPs and private ranges, so no real hosts are referenced.

## Limitations and next steps

- Doesn't detect *distributed* attacks (many IPs, few attempts each).
- Only handles password authentication lines (not public-key or PAM messages).
- Next: GeoIP lookup for source IPs, JSON output for SIEM ingestion, and unit tests with `pytest`.
