"""Detection rules. Each rule takes the sorted event list and returns Alerts.

Thresholds are deliberately simple and documented so an analyst can tune them.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


@dataclass
class Alert:
    rule: str
    severity: str
    mitre: str           # ATT&CK technique ID and name
    summary: str
    ip: str = ""
    user: str = ""
    first_seen: object = None
    last_seen: object = None
    evidence: list = field(default_factory=list)  # raw log lines


def brute_force(events, threshold=5, window=timedelta(minutes=10), max_users=3):
    """Many failed logins from one IP in a short window against one or a few accounts.

    Bursts spread across more than max_users accounts are left to password_spray.
    """
    alerts, by_ip = [], defaultdict(list)
    for e in events:
        if e.action in ("login_failed", "invalid_user") and e.ip:
            by_ip[e.ip].append(e)
    for ip, fails in by_ip.items():
        start = 0
        for end in range(len(fails)):
            while fails[end].time - fails[start].time > window:
                start += 1
            if end - start + 1 >= threshold:
                burst = fails[start:end + 1]
                users = sorted({f.user for f in burst})
                if len(users) > max_users:
                    break
                alerts.append(Alert(
                    "Brute force", "High", "T1110.001 Password Guessing",
                    f"{len(fails)} failed logins from {ip} (≥{threshold} within {int(window.total_seconds() // 60)} min) against {', '.join(users)}",
                    ip=ip, user=", ".join(users), first_seen=fails[0].time, last_seen=fails[-1].time,
                    evidence=[f.raw for f in burst[:5]]))
                break
    return alerts


def password_spray(events, min_users=4):
    """One IP failing against many different accounts."""
    alerts, users_by_ip = [], defaultdict(set)
    sample = defaultdict(list)
    for e in events:
        if e.action in ("login_failed", "invalid_user") and e.ip:
            users_by_ip[e.ip].add(e.user)
            sample[e.ip].append(e)
    for ip, users in users_by_ip.items():
        if len(users) >= min_users:
            alerts.append(Alert(
                "Password spraying / account enumeration", "Medium", "T1110.003 Password Spraying",
                f"{ip} tried {len(users)} different accounts: {', '.join(sorted(users))}",
                ip=ip, first_seen=sample[ip][0].time, last_seen=sample[ip][-1].time,
                evidence=[s.raw for s in sample[ip][:5]]))
    return alerts


def success_after_failures(events, min_failures=3):
    """A successful login from an IP that was just failing: possible compromised account."""
    alerts, fail_count = [], defaultdict(int)
    fails = defaultdict(list)
    for e in events:
        if e.action in ("login_failed", "invalid_user") and e.ip:
            fail_count[e.ip] += 1
            fails[e.ip].append(e)
        elif e.action == "login_success" and e.ip and fail_count[e.ip] >= min_failures:
            alerts.append(Alert(
                "Successful login after repeated failures", "High", "T1078 Valid Accounts",
                f"{e.user} logged in from {e.ip} after {fail_count[e.ip]} failed attempts – check if the password was guessed",
                ip=e.ip, user=e.user, first_seen=fails[e.ip][0].time, last_seen=e.time,
                evidence=[f.raw for f in fails[e.ip][-3:]] + [e.raw]))
            fail_count[e.ip] = 0
    return alerts


def off_hours_login(events, start_hour=0, end_hour=5):
    """Successful logins in the middle of the night."""
    return [Alert(
        "Off-hours login", "Low", "T1078 Valid Accounts",
        f"{e.user} logged in at {e.time:%H:%M} from {e.ip or 'local'} (outside normal hours)",
        ip=e.ip, user=e.user, first_seen=e.time, last_seen=e.time, evidence=[e.raw])
        for e in events if e.action == "login_success" and start_hour <= e.time.hour < end_hour]


def persistence_and_privilege(events):
    """New accounts and accounts added to admin groups."""
    alerts = []
    for e in events:
        if e.action == "user_created":
            alerts.append(Alert("New account created", "Medium", "T1136.001 Create Local Account",
                                f"Local account '{e.user}' was created on {e.host}",
                                user=e.user, first_seen=e.time, last_seen=e.time, evidence=[e.raw]))
        elif e.action == "added_to_admin_group":
            alerts.append(Alert("Account added to an admin group", "High", "T1098 Account Manipulation",
                                f"'{e.user}' was added to a privileged group on {e.host}",
                                user=e.user, first_seen=e.time, last_seen=e.time, evidence=[e.raw]))
    return alerts


ALL_RULES = [brute_force, password_spray, success_after_failures, off_hours_login, persistence_and_privilege]


def run_all(events):
    events = sorted(events, key=lambda e: e.time)
    alerts = []
    for rule in ALL_RULES:
        alerts.extend(rule(events))
    return sorted(alerts, key=lambda a: (SEVERITY_ORDER[a.severity], a.first_seen))
