"""Command line: python -m log_analyzer LOGFILE [LOGFILE ...] [--html report.html] [--json alerts.json]"""

import argparse
import sys

from . import detections, report
from .parsers import load


def main(argv=None):
    ap = argparse.ArgumentParser(prog="log_analyzer", description="Detect suspicious logins in Linux auth logs and Windows Security events.")
    ap.add_argument("logs", nargs="+", help="auth.log / secure files, or Windows Security CSV exports")
    ap.add_argument("--year", type=int, help="year for syslog timestamps (default: current year)")
    ap.add_argument("--html", help="write an HTML report to this file")
    ap.add_argument("--json", help="write alerts as JSON to this file")
    args = ap.parse_args(argv)

    events = []
    for path in args.logs:
        events.extend(load(path, args.year))
    alerts = detections.run_all(events)

    report.to_console(events, alerts)
    if args.html:
        report.to_html(events, alerts, args.html)
        print(f"HTML report: {args.html}")
    if args.json:
        report.to_json(events, alerts, args.json)
        print(f"JSON alerts: {args.json}")
    return 1 if any(a.severity == "High" for a in alerts) else 0


if __name__ == "__main__":
    sys.exit(main())
