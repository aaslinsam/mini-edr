# Mini-EDR — Endpoint Detection & Response (Python, stdlib only)

A lightweight EDR agent for Windows that **monitors processes and files, detects attacker behaviour,
responds automatically (kill / quarantine), and shows alerts on a live web dashboard.**
No external libraries are needed, just Python 3.

## Architecture
```
 ┌──────────────┐   ┌──────────────┐
 │ Process      │   │ File         │   Sensors (telemetry)
 │ Monitor      │   │ Monitor      │
 └──────┬───────┘   └──────┬───────┘
        └────────┬─────────┘
          ┌──────▼──────┐
          │ Detection   │  Rules: regex on cmdlines, IOC hashes,
          │ Engine      │  suspicious names, ransomware heuristics
          └──────┬──────┘
          ┌──────▼──────┐
          │ Response    │  Kill process tree / quarantine file
          └──────┬──────┘
          ┌──────▼──────┐
          │ Alerts +    │  alerts.jsonl + dashboard at :8080
          │ Dashboard   │
          └─────────────┘
```

## Detections (mapped to MITRE ATT&CK)
| Rule | Severity | MITRE | Response |
|---|---|---|---|
| Encoded PowerShell (`-enc`) + decodes the payload | HIGH | T1059.001 | Kill process |
| PowerShell download cradle | HIGH | T1105 | Kill process |
| Recon commands (whoami, net user, systeminfo…) | MEDIUM | T1033 | Log |
| Shadow copy deletion | CRITICAL | T1490 | Kill process |
| LOLBin abuse (certutil, mshta, regsvr32) | MEDIUM | T1218 | Log |
| Credential dumping (mimikatz, lsass dump) | CRITICAL | T1003 | Kill process |
| Known malware SHA256 (IOC) | CRITICAL | T1204 | Quarantine file |
| Hacking-tool filename dropped | HIGH | T1105 | Log |
| Ransomware extension (.locked/.encrypted) | HIGH | T1486 | Log |
| Mass file modification burst | CRITICAL | T1486 | Log |

## Run the demo
Double-click **`run_demo.bat`**, or run it by hand:
```
python edr.py          # terminal 1: agent + dashboard on http://127.0.0.1:8080
python attack_sim.py   # terminal 2: harmless attack simulation
```
The simulator is **completely harmless**. It runs a PowerShell command that only prints and sleeps,
a `whoami`, plain text files acting as "malware", and dummy files renamed inside `watched/sandbox`.

## Files
- `edr.py`: the agent (sensors, rules, response, web server)
- `attack_sim.py`: attack simulator
- `dashboard.html`: the live security console
- `alerts.jsonl`: alert log (SIEM-friendly JSON lines)
- `quarantine/`: quarantined files

## Limitations / future work
Uses polling instead of kernel callbacks (ETW/Sysmon/minifilter driver). It only watches one folder,
and there is no central server for multiple endpoints. Possible next steps: Sysmon/ETW integration,
YARA scanning, network connection monitoring, and a multi-agent management server.
