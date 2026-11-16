"""
Attack simulator for the Mini-EDR demo.  EVERYTHING HERE IS HARMLESS:
 - commands only print text / sleep
 - "malware" is a plain text file
 - "ransomware" only renames dummy files inside ./watched/sandbox
Run while edr.py is running:  python attack_sim.py
"""
import base64, os, subprocess, time

BASE = os.path.dirname(os.path.abspath(__file__))
WATCH = os.path.join(BASE, "watched")
SANDBOX = os.path.join(WATCH, "sandbox")
DEMO_PAYLOAD = b"MINI-EDR-DEMO-MALWARE-SAMPLE :: this file is harmless, used only for detection testing"
HOLD = "ping -n 8 127.0.0.1 >nul"   # keep process alive a few seconds so the sensor sees it


def step(n, title):
    print(f"\n[ATTACK {n}] {title}")
    time.sleep(1)


step(1, "Encoded PowerShell (T1059.001) -> expect HIGH alert + process KILLED")
enc = base64.b64encode("Write-Output 'Mini-EDR demo payload'; Start-Sleep 30".encode("utf-16-le")).decode()
subprocess.Popen(["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-enc", enc])
time.sleep(5)

step(2, "Discovery commands (T1033) -> expect MEDIUM alert")
subprocess.Popen(f"cmd /c whoami & {HOLD}", shell=True, stdout=subprocess.DEVNULL)
time.sleep(4)

step(3, "Drop known-malware file (IOC hash) -> expect CRITICAL + QUARANTINE")
with open(os.path.join(WATCH, "invoice_2026.pdf.exe"), "wb") as f:
    f.write(DEMO_PAYLOAD)
time.sleep(3)

step(4, "Drop hacking-tool named file -> expect HIGH alert")
with open(os.path.join(WATCH, "mimikatz.exe"), "w") as f:
    f.write("just a text file with a scary name")
time.sleep(3)

step(5, "Ransomware simulation: encrypt+rename 15 files (T1486) -> expect CRITICAL")
os.makedirs(SANDBOX, exist_ok=True)
for i in range(15):
    with open(os.path.join(SANDBOX, f"document_{i}.txt"), "w") as f:
        f.write("important data")
time.sleep(2)
for i in range(15):
    p = os.path.join(SANDBOX, f"document_{i}.txt")
    with open(p, "w") as f:
        f.write(base64.b64encode(os.urandom(32)).decode())   # "encrypt"
    os.rename(p, p + ".locked")
time.sleep(4)

print("\n[+] Simulation complete. Check the EDR console and http://127.0.0.1:8080")
