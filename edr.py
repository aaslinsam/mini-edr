"""
Mini-EDR  -  a minimal Endpoint Detection & Response agent (stdlib only, Windows)

Components
  1. Process Monitor   - polls running processes, detects suspicious command lines
  2. File Monitor      - watches a folder: IOC hash matches, suspicious names, ransomware-like bursts
  3. Response Engine   - kills malicious processes, quarantines malicious files
  4. Alert Store       - alerts.jsonl (one JSON alert per line)
  5. Dashboard         - http://127.0.0.1:8080  (live web UI)

Run:  python edr.py
"""
import base64, hashlib, http.server, json, os, re, shutil, subprocess, threading, time
from collections import deque
from datetime import datetime

BASE = os.path.dirname(os.path.abspath(__file__))
WATCH_DIR = os.path.join(BASE, "watched")
QUARANTINE_DIR = os.path.join(BASE, "quarantine")
ALERT_FILE = os.path.join(BASE, "alerts.jsonl")
PORT = 8080
AUTO_RESPONSE = True          # kill / quarantine automatically on HIGH+ severity

# ---------------- Detection rules (process) ----------------
PROC_RULES = [
    # (rule id, severity, regex on command line, description, MITRE technique)
    ("PS_ENCODED", "HIGH", r"powershell.*\s-(e|enc|encodedcommand)\s", "Encoded PowerShell command", "T1059.001"),
    ("PS_DOWNLOAD", "HIGH", r"(downloadstring|downloadfile|invoke-webrequest|iwr\s|net\.webclient)", "PowerShell download cradle", "T1105"),
    ("RECON_CMD", "MEDIUM", r"\b(whoami|systeminfo|net\s+user|net\s+localgroup|ipconfig\s+/all|nltest)\b", "Discovery / recon command", "T1033"),
    ("SHADOW_DEL", "CRITICAL", r"vssadmin.*delete\s+shadows|wmic.*shadowcopy.*delete", "Shadow copy deletion (ransomware)", "T1490"),
    ("LOLBIN", "MEDIUM", r"\b(certutil.*-urlcache|mshta\s+http|regsvr32.*/i:http|rundll32.*javascript)", "LOLBin abuse", "T1218"),
    ("CRED_TOOL", "CRITICAL", r"(mimikatz|sekurlsa|procdump.*lsass)", "Credential dumping tool", "T1003"),
]
SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# ---------------- Detection rules (file) ----------------
SUSPICIOUS_NAMES = re.compile(r"(mimikatz|lazagne|psexec|nc\.exe|ncat|rubeus|cobalt)", re.I)
RANSOM_EXT = re.compile(r"\.(locked|encrypted|crypt|wncry|enc)$", re.I)
# IOC hash list: SHA256 of the demo "malware" payload (harmless text, see attack_sim.py)
DEMO_PAYLOAD = b"MINI-EDR-DEMO-MALWARE-SAMPLE :: this file is harmless, used only for detection testing"
IOC_HASHES = {hashlib.sha256(DEMO_PAYLOAD).hexdigest(): "Demo.Trojan.Generic"}
RANSOM_THRESHOLD = 10          # file changes ...
RANSOM_WINDOW = 5              # ... within N seconds

alerts = deque(maxlen=500)
stats = {"processes_scanned": 0, "files_scanned": 0, "killed": 0, "quarantined": 0, "started": datetime.now().isoformat(timespec="seconds")}
lock = threading.Lock()


def raise_alert(source, rule, severity, desc, details, mitre="", action="logged"):
    a = {"time": datetime.now().strftime("%H:%M:%S"), "source": source, "rule": rule, "severity": severity,
         "description": desc, "mitre": mitre, "details": details, "action": action}
    with lock:
        alerts.appendleft(a)
        with open(ALERT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(a) + "\n")
    colors = {"LOW": "\033[37m", "MEDIUM": "\033[33m", "HIGH": "\033[91m", "CRITICAL": "\033[41m\033[97m"}
    print(f"{colors.get(severity,'')}[{a['time']}] [{severity}] {rule}: {desc}\033[0m  -> {action}\n      {details}")


# ================= Process monitor =================
PS_QUERY = ("Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath "
            "| ConvertTo-Json -Compress")


def list_processes():
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", PS_QUERY], capture_output=True, text=True,
                             timeout=30, creationflags=0x08000000).stdout
        data = json.loads(out) if out.strip() else []
        return {p["ProcessId"]: p for p in (data if isinstance(data, list) else [data])}
    except Exception as e:
        print("process query failed:", e)
        return {}


def decode_ps(cmd):
    m = re.search(r"-(?:e|enc|encodedcommand)\s+([A-Za-z0-9+/=]+)", cmd, re.I)
    if m:
        try:
            return base64.b64decode(m.group(1)).decode("utf-16-le")
        except Exception:
            pass
    return None


def kill(pid):
    r = subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, text=True)
    return r.returncode == 0


def process_monitor():
    seen = set(list_processes().keys())      # baseline: don't alert on already-running processes
    print(f"[proc] baseline: {len(seen)} processes")
    while True:
        procs = list_processes()
        for pid, p in procs.items():
            if pid in seen:
                continue
            seen.add(pid)
            stats["processes_scanned"] += 1
            cmd = p.get("CommandLine") or p.get("Name") or ""
            if "Get-CimInstance Win32_Process" in cmd:   # ignore our own sensor
                continue
            for rid, sev, rx, desc, mitre in PROC_RULES:
                if re.search(rx, cmd, re.I):
                    details = f"PID={pid} PPID={p.get('ParentProcessId')} CMD={cmd[:300]}"
                    dec = decode_ps(cmd)
                    if dec:
                        details += f" | DECODED: {dec[:200]}"
                    action = "logged"
                    if AUTO_RESPONSE and SEVERITY_RANK[sev] >= SEVERITY_RANK["HIGH"]:
                        if kill(pid):
                            stats["killed"] += 1
                            action = "PROCESS KILLED"
                        else:
                            action = "kill failed (already exited?)"
                    raise_alert("process", rid, sev, desc, details, mitre, action)
        seen &= set(procs.keys()) | seen   # keep growing set (PIDs rarely reused in demo window)
        time.sleep(1)


# ================= File monitor =================
def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot():
    snap = {}
    for root, _, files in os.walk(WATCH_DIR):
        for n in files:
            p = os.path.join(root, n)
            try:
                snap[p] = os.path.getmtime(p)
            except OSError:
                pass
    return snap


def quarantine(path):
    dest = os.path.join(QUARANTINE_DIR, os.path.basename(path) + f".{int(time.time())}.quarantine")
    shutil.move(path, dest)
    stats["quarantined"] += 1
    return dest


def file_monitor():
    prev = snapshot()
    print(f"[file] watching {WATCH_DIR} ({len(prev)} files)")
    changes = deque()
    ransom_alerted_at = 0
    while True:
        time.sleep(1)
        cur = snapshot()
        new_or_mod = [p for p in cur if p not in prev or cur[p] != prev[p]]
        deleted = [p for p in prev if p not in cur]
        now = time.time()
        for _ in new_or_mod + deleted:
            changes.append(now)
        while changes and now - changes[0] > RANSOM_WINDOW:
            changes.popleft()

        ransom_files = []
        for p in new_or_mod:
            stats["files_scanned"] += 1
            name = os.path.basename(p)
            try:
                h = sha256(p)
            except OSError:
                continue
            if h in IOC_HASHES:
                action = f"QUARANTINED -> {quarantine(p)}" if AUTO_RESPONSE else "logged"
                raise_alert("file", "IOC_HASH", "CRITICAL", f"Known malware hash ({IOC_HASHES[h]})",
                            f"{p} sha256={h[:16]}...", "T1204", action)
                cur.pop(p, None)
                continue
            if SUSPICIOUS_NAMES.search(name):
                raise_alert("file", "SUSPICIOUS_NAME", "HIGH", "Hacking-tool filename dropped", p, "T1105")
            if RANSOM_EXT.search(name):
                ransom_files.append(name)
        if ransom_files:
            raise_alert("file", "RANSOM_EXT", "HIGH", f"{len(ransom_files)} file(s) with ransomware-style extension",
                        ", ".join(ransom_files[:5]) + (" ..." if len(ransom_files) > 5 else ""), "T1486")

        if len(changes) >= RANSOM_THRESHOLD and now - ransom_alerted_at > RANSOM_WINDOW:
            ransom_alerted_at = now
            raise_alert("file", "MASS_FILE_CHANGE", "CRITICAL",
                        f"Ransomware behaviour: {len(changes)} file changes in {RANSOM_WINDOW}s",
                        WATCH_DIR, "T1486")
        prev = cur


# ================= Dashboard =================
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/api"):
            with lock:
                body = json.dumps({"alerts": list(alerts), "stats": stats}).encode()
            ctype = "application/json"
        else:
            with open(os.path.join(BASE, "dashboard.html"), "rb") as f:
                body = f.read()
            ctype = "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body)


def main():
    os.system("")  # enable ANSI colours in Windows console
    os.makedirs(WATCH_DIR, exist_ok=True)
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    print("=" * 60 + "\n  MINI-EDR agent starting\n" + "=" * 60)
    threading.Thread(target=process_monitor, daemon=True).start()
    threading.Thread(target=file_monitor, daemon=True).start()
    print(f"[web] dashboard: http://127.0.0.1:{PORT}")
    http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
