# SOC Log Analyzer

A small, rule-based detection tool for SOC triage. It reads **Linux auth logs** and **Windows Security events**, finds the login patterns an L1 analyst is expected to catch, maps each alert to **MITRE ATT&CK**, and writes a console summary, an HTML report and JSON.

Python standard library only. No SIEM needed: useful for a quick look at a log file, and for learning how SIEM correlation rules work.

## Detections

| Rule | Logic (default thresholds) | Severity | MITRE ATT&CK |
|---|---|---|---|
| Brute force | ≥ 5 failed logins from one IP within 10 minutes, against 1–3 accounts | High | T1110.001 Password Guessing |
| Successful login after repeated failures | A login succeeds from an IP that had ≥ 3 failures just before (password possibly guessed) | High | T1078 Valid Accounts |
| Password spraying / account enumeration | One IP fails against ≥ 4 different accounts | Medium | T1110.003 Password Spraying |
| Account added to an admin group | Windows event 4732 | High | T1098 Account Manipulation |
| New account created | Linux `useradd`, Windows event 4720 | Medium | T1136.001 Create Local Account |
| Off-hours login | Successful login between 00:00 and 05:00 | Low | T1078 Valid Accounts |

A single mistyped password followed by a normal login does **not** raise an alert. The tests check this, because a detector that fires on everything is useless.

## Example

```
$ python -m log_analyzer samples/auth.log samples/windows_security.csv --year 2026 --html report.html

Events parsed: 30  |  failed logins: 20  |  successful logins: 6
Alerts: 8  High: 4  Medium: 3  Low: 1

[High  ] Brute force  (T1110.001 Password Guessing)
         8 failed logins from 203.0.113.50 (≥5 within 10 min) against root
[High  ] Successful login after repeated failures  (T1078 Valid Accounts)
         root logged in from 203.0.113.50 after 8 failed attempts – check if the password was guessed
[High  ] Account added to an admin group  (T1098 Account Manipulation)
         'svc_backup2' was added to a privileged group on SRV-DC-01
[Medium] Password spraying / account enumeration  (T1110.003 Password Spraying)
         198.51.100.77 tried 5 different accounts: admin, guest, oracle, test, ubuntu
...
```

The sample logs tell one story: an attacker brute-forces `root`, gets in, and creates a `sysupdate` account; another IP sprays common usernames; on Windows, `Administrator` is brute-forced and a new account is added to an admin group.

## Usage

Requires Python 3.9+.

```bash
git clone https://github.com/ShreeRam03/soc-log-analyzer.git
cd soc-log-analyzer

python -m log_analyzer /var/log/auth.log --html report.html
python -m log_analyzer security.csv --json alerts.json
```

The exit code is `1` when any High alert is found, so it can be used in scripts or scheduled jobs.

### Exporting Windows Security events

Run in an elevated PowerShell:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4720,4732} -MaxEvents 5000 |
  ForEach-Object {
    $x = [xml]$_.ToXml(); $d = @{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{ TimeCreated = $_.TimeCreated.ToString('s'); Id = $_.Id;
      TargetUserName = $d.TargetUserName; IpAddress = $d.IpAddress; Computer = $_.MachineName }
  } | Export-Csv security.csv -NoTypeInformation
```

## Tests

```bash
python -m unittest discover -s tests -t . -v
```

## Project layout

```
log_analyzer/
  parsers.py     Linux auth.log and Windows CSV → common Event objects
  detections.py  detection rules, thresholds and MITRE mapping
  report.py      console, JSON and HTML output
  __main__.py    command-line interface
samples/         synthetic logs (documentation IP ranges, fake hosts)
tests/           unit tests
```

## Limitations and next steps

- Rule-based with fixed thresholds; real SIEMs tune these per environment.
- Syslog lines have no year, so pass `--year` for older logs.
- Next: GeoIP / threat-intel lookups on source IPs, and Sigma rule export.

## Author

Shreeram Perumalla · [LinkedIn](https://www.linkedin.com/in/shreeram-perumalla) · [Blog](https://shreeram03.github.io)
