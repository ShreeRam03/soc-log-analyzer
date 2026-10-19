"""Console, JSON and HTML output."""

import html
import json
from collections import Counter
from dataclasses import asdict

COLORS = {"High": "#d6453d", "Medium": "#e89b2d", "Low": "#3b82c4"}


def summary(events, alerts):
    return {
        "events": len(events),
        "failed_logins": sum(e.action in ("login_failed", "invalid_user") for e in events),
        "successful_logins": sum(e.action == "login_success" for e in events),
        "alerts": dict(Counter(a.severity for a in alerts)),
        "top_failing_ips": Counter(e.ip for e in events if e.action in ("login_failed", "invalid_user") and e.ip).most_common(5),
    }


def to_console(events, alerts):
    s = summary(events, alerts)
    print(f"\nEvents parsed: {s['events']}  |  failed logins: {s['failed_logins']}  |  successful logins: {s['successful_logins']}")
    print(f"Alerts: {len(alerts)}  " + "  ".join(f"{k}: {v}" for k, v in s["alerts"].items()) + "\n")
    for a in alerts:
        print(f"[{a.severity:<6}] {a.rule}  ({a.mitre})")
        print(f"         {a.summary}")
        print(f"         {a.first_seen:%Y-%m-%d %H:%M:%S} -> {a.last_seen:%H:%M:%S}\n")


def to_json(events, alerts, path):
    data = {"summary": summary(events, alerts), "alerts": [asdict(a) for a in alerts]}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def to_html(events, alerts, path, title="SOC Log Analysis Report"):
    s = summary(events, alerts)
    e = html.escape
    rows = []
    for a in alerts:
        evidence = "<br>".join(e(line) for line in a.evidence)
        rows.append(f"""
        <details class="alert" style="border-left-color:{COLORS[a.severity]}">
          <summary><span class="sev" style="background:{COLORS[a.severity]}">{a.severity}</span>
            <b>{e(a.rule)}</b> <span class="mitre">{e(a.mitre)}</span></summary>
          <p>{e(a.summary)}</p>
          <p class="time">{a.first_seen:%Y-%m-%d %H:%M:%S} → {a.last_seen:%Y-%m-%d %H:%M:%S}</p>
          <pre>{evidence}</pre>
        </details>""")
    top_ips = "".join(f"<tr><td>{e(ip)}</td><td>{n}</td></tr>" for ip, n in s["top_failing_ips"]) or "<tr><td colspan=2>none</td></tr>"
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{e(title)}</title>
<style>
 body{{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:0;background:#0f1622;color:#e6edf3}}
 main{{max-width:960px;margin:0 auto;padding:24px 16px}}
 h1{{font-size:22px}} .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}}
 .card{{background:#172133;border-radius:10px;padding:14px}} .card b{{font-size:26px;display:block}}
 .alert{{background:#172133;border-left:5px solid;border-radius:8px;margin:10px 0;padding:10px 14px}}
 summary{{cursor:pointer}} .sev{{color:#fff;border-radius:4px;padding:2px 8px;font-size:12px;margin-right:6px}}
 .mitre{{color:#8fa3bf;font-size:13px}} .time{{color:#8fa3bf;font-size:13px}}
 pre{{background:#0b111b;padding:10px;border-radius:6px;overflow-x:auto;font-size:12px;white-space:pre-wrap}}
 table{{border-collapse:collapse;width:100%;max-width:360px}} td{{border-bottom:1px solid #26334a;padding:6px}}
</style></head><body><main>
<h1>{e(title)}</h1>
<div class="cards">
 <div class="card"><b>{s['events']}</b>events parsed</div>
 <div class="card"><b>{s['failed_logins']}</b>failed logins</div>
 <div class="card"><b>{s['successful_logins']}</b>successful logins</div>
 <div class="card"><b>{len(alerts)}</b>alerts</div>
</div>
<h2>Alerts</h2>{''.join(rows) or '<p>No alerts.</p>'}
<h2>Top failing source IPs</h2><table>{top_ips}</table>
</main></body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)
