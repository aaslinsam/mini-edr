@echo off
cd /d "%~dp0"
REM reset previous demo state
if exist watched rmdir /s /q watched
if exist quarantine rmdir /s /q quarantine
if exist alerts.jsonl del alerts.jsonl
echo Starting Mini-EDR agent in a new window...
start "Mini-EDR Agent" python edr.py
timeout /t 8 /nobreak >nul
start http://127.0.0.1:8080
echo.
echo Press any key to launch the ATTACK SIMULATION...
pause >nul
python attack_sim.py
pause
