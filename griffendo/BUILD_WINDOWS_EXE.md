# Getting Griffendo as a double-clickable `Griffendo.exe`

Short answer: **the `.exe` has to be built on Windows.** This page tells you exactly how,
in about three minutes, and what the result does.

---

## Why it isn't already a download link

A Windows `.exe` cannot be produced on Linux or macOS. PyInstaller packages the interpreter
of the machine it runs on, and Griffendo's build was developed on a Linux CI box — so
shipping a "`.exe`" from there would give you a file Windows refuses to run.

`tools/repack_exe.py` can rebuild a *new* exe from an *old* one, but it needs the original
`Griffendo.exe`, which is not part of this repository. That is why the build recipe below
exists instead: it is reproducible, and it always matches the current sources.

---

## Build it (on the Windows machine you want to monitor)

Open **PowerShell** and run:

```powershell
cd griffendo
py -3.12 -m pip install pyinstaller fastapi uvicorn pydantic requests
py -3.12 tools\build_exe.py
```

That is it. The result is:

```
griffendo\dist\Griffendo.exe
```

Double-click it.

If you prefer one command that also installs the dependencies:

```powershell
py -3.12 tools\build_exe.py install
py -3.12 tools\build_exe.py
```

Faster start-up variant (extracts nothing at each launch, ~1 s instead of ~4 s):

```powershell
py -3.12 tools\build_exe.py --onedir
```

→ `griffendo\dist\Griffendo\Griffendo.exe` (keep the whole folder together).

---

## What happens when you double-click it

1. **Windows shows a UAC prompt.** Griffendo's embedded manifest requests
   `highestAvailable` elevation, because the **Security** event log is not readable without
   Administrator. Without elevation you get the dashboard but no Security-log rules
   (failed logons, process creation, account changes). Click **Yes**.
2. A console window shows progress, then:
   ```
   ============================================================
    Griffendo | Windows Event Intelligence
   ============================================================
    Starting dashboard...
    Dashboard ready: http://127.0.0.1:8000/
    Collecting Windows event logs continuously (N channels):
      - Security
      - System
      ...
   ```
3. Your browser opens **http://127.0.0.1:8000/** — the dashboard, on the loopback address,
   exactly as you asked. It never binds to a network interface, so nothing is exposed off
   the machine.
4. **Event collection starts immediately.** History is backfilled in the background
   (default 336 h for System/Security/Setup/Application, 192 h for added channels) and live
   events follow every ~2 seconds. Detections appear as rules fire.
5. Closing the console window stops everything. Collected data stays in
   `%LOCALAPPDATA%\Griffendo` and is picked up again next launch.

### If port 8000 is busy

The launcher prefers 8000 and automatically uses the next free port, printing the real
address (e.g. `Dashboard ready: http://127.0.0.1:8001/`). To force a port:

```powershell
Griffendo.exe --port 8000
```

---

## Useful flags

| Flag | Effect |
|---|---|
| `--port 8000` | Preferred port (a free one is used if it is taken) |
| `--no-browser` | Do not open the browser automatically |
| `--no-collect` | Dashboard only, do not read event logs |
| `--snapshot` | Read each log once at start instead of continuously |
| `--interval 5` | Seconds between live collection passes |

---

## "It runs but Detections is empty" — almost always a Windows audit setting

Griffendo can only detect what Windows logs. The Security log does **not** record most
activity by default. On an Administrator PowerShell:

```powershell
# Failed/successful logons, logoffs, privilege use
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Special Logon" /success:enable

# Process creation WITH command lines (needed for most process rules)
auditpol /set /subcategory:"Process Creation" /success:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# Account management (user created/added to group/locked out)
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable

# PowerShell script-block logging (script content rules)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
```

Reboot or wait for the policy to apply, then use the dashboard's **Refresh** button.

**Sysmon gives you the rest** — file creation/deletion, registry changes, network
connections, DNS, exact process lineage (GUIDs). Windows does not log these by default.
Install it from Sysinternals and Griffendo picks the channel up automatically:

```powershell
# download Sysmon + a config, then:
sysmon64.exe -accepteula -i sysmonconfig.xml
```

Without Sysmon, the Process page shows `probable` (PID-based) lineage instead of `exact`
(GUID-based) — the UI labels which is which, so you always know what the evidence supports.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Dashboard opens, Security detections never appear | Not elevated, or audit policy off (see above) |
| "Access is denied" for a channel | Run as Administrator |
| Console closes instantly | Run it from PowerShell (`.\dist\Griffendo.exe`) to see the error |
| Antivirus quarantines the exe | Unsigned PyInstaller binaries are often flagged; sign it or add an exclusion |
| Slow first launch (single-file build) | Use `--onedir` |
| Want it to start at boot | Task Scheduler → Run whether user is logged on or not → *Run with highest privileges* → `dist\Griffendo.exe` |

---

## Verifying the sources before you build

```powershell
cd griffendo
python -m pip install -r requirements-dev.txt
python -m pytest tests        # expect: 102 passed
```
