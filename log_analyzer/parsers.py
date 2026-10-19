"""Turn raw log files into a common list of Event objects.

Supported inputs:
  * Linux auth logs (/var/log/auth.log or /var/log/secure): sshd and sudo lines
  * Windows Security events exported to CSV (see README for the export command)
"""

import csv
import re
from dataclasses import dataclass
from datetime import datetime


@dataclass
class Event:
    time: datetime
    source: str      # "linux" or "windows"
    action: str      # login_failed, login_success, invalid_user, sudo, user_created, added_to_admin_group, special_logon
    user: str = ""
    ip: str = ""
    host: str = ""
    raw: str = ""


SYSLOG_PREFIX = re.compile(r"^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<proc>[\w\-/]+)(?:\[\d+\])?: (?P<msg>.*)$")
LINUX_RULES = [
    ("invalid_user", re.compile(r"Failed password for invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")),
    ("login_failed", re.compile(r"Failed password for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")),
    # sshd also logs "Invalid user X from IP" for the same attempt; it is skipped to avoid double counting
    ("login_success", re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")),
    ("sudo", re.compile(r"^\s*(?P<user>\S+) : .*COMMAND=(?P<cmd>.*)$")),
    ("user_created", re.compile(r"new user: name=(?P<user>[^,]+)")),
]


def parse_linux_auth(path, year):
    events = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            m = SYSLOG_PREFIX.match(line)
            if not m:
                continue
            time = datetime.strptime(f"{year} {m['ts']}", "%Y %b %d %H:%M:%S")
            for action, rule in LINUX_RULES:
                hit = rule.search(m["msg"])
                if hit:
                    events.append(Event(time, "linux", action, hit.groupdict().get("user", ""),
                                        hit.groupdict().get("ip", ""), m["host"], line))
                    break
    return events


# Windows Security event IDs we care about
WINDOWS_IDS = {
    "4625": "login_failed",
    "4624": "login_success",
    "4672": "special_logon",
    "4720": "user_created",
    "4732": "added_to_admin_group",
}


def parse_windows_csv(path):
    """CSV columns: TimeCreated, Id, TargetUserName, IpAddress, Computer."""
    events = []
    with open(path, encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            action = WINDOWS_IDS.get(str(row.get("Id", "")).strip())
            if not action:
                continue
            ip = (row.get("IpAddress") or "").strip()
            events.append(Event(
                time=datetime.fromisoformat(row["TimeCreated"].strip()),
                source="windows",
                action=action,
                user=(row.get("TargetUserName") or "").strip(),
                ip="" if ip in ("-", "::1", "127.0.0.1") else ip,
                host=(row.get("Computer") or "").strip(),
                raw=",".join(row.values()),
            ))
    return events


def load(path, year=None):
    year = year or datetime.now().year
    if path.lower().endswith(".csv"):
        return parse_windows_csv(path)
    return parse_linux_auth(path, year)
