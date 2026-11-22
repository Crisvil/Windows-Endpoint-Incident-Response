# Windows Endpoint Incident Response Walkthrough

**Last Updated:** November 22, 2026

This guide provides step-by-step instructions for using the scripts in this repository to perform rapid triage and deeper incident response on Windows endpoints.

---

## 1. Preparation
- Run all scripts from an **elevated** PowerShell session (Run as Administrator). `netcap.ps1` and `memdump.ps1` refuse to run without it; the others warn and collect what they can.
- If the execution policy blocks the scripts: `Set-ExecutionPolicy Bypass -Scope Process`
- Sysinternals tools are optional. Place `procdump64.exe` and `autorunsc64.exe` in a `Tools` folder next to the scripts (or pass `-ToolsPath`).
- Every script accepts `-OutputRoot <folder>` so you can write evidence to external/USB media instead of the suspect disk.
- Output folders are named `<Type>_<COMPUTERNAME>_<yyyyMMdd_HHmmss>`.

---

## 2. Main Triage Script (`WE_IR.ps1`)
- **Purpose:** Collects volatile and semi-volatile artifacts, flags suspicious processes, exports event logs, hashes everything and zips the result.
- **Usage:**
  ```powershell
  .\WE_IR.ps1                                  # default: C:\IR_Collection\<HOST>_<timestamp>
  .\WE_IR.ps1 -OutputRoot E:\Evidence -MaxEvents 20000
  .\WE_IR.ps1 -NoZip
  ```
- **Key Outputs:**
  - `SystemInfo.txt`, `ComputerSystem.txt`, `TimeZone.txt`, `Hotfixes.csv`
  - `LocalUsers.csv`, `LocalGroups.csv`, `LocalAdministrators.csv`, `LoggedOnSessions.txt`
  - `Processes_Full.csv` (with owner and SHA-256 of each executable), `Suspicious_Processes.csv`
  - `TCP_Connections.csv`, `UDP_Endpoints.csv` (with process names), `IPConfiguration.txt`, `ARPCache.csv`, `SMBSessions.csv`, `SMBShares.csv`, `HostsFile.txt`, `DNSCache.csv`
  - `Services.csv`, `ScheduledTasks.csv`, `RunKeys.csv`, `StartupItems.csv` (all user profiles)
  - `DefenderStatus.txt`, `DefenderExclusions.txt`, `DefenderDetections.csv`
  - Event logs: Security, System, Application, PowerShell/Operational, Defender/Operational, TaskScheduler/Operational
  - `transcript.txt`, `Errors.txt` (if any section failed), `SHA256_Manifest.csv`, and a `.zip` with its SHA-256 printed to the console
- **Suspicious process heuristics:** no image path, image in Temp/AppData/Downloads/Public/PerfLogs/Recycle Bin, or a LOLBin (powershell, mshta, rundll32, certutil, …) with an encoded/download-style command line.

---

## 3. Memory Dump Collection (`memdump.ps1`)
- **Purpose:** Capture a full process memory dump (LSASS by default) with ProcDump.
- **Usage:**
  ```powershell
  .\memdump.ps1                       # dumps lsass
  .\memdump.ps1 -ProcessName explorer
  .\memdump.ps1 -ProcessId 4321
  ```
- **Output:** `MemDump_<HOST>_<timestamp>\<name>_<pid>.dmp` and `SHA256.txt`
- **Notes:**
  - This is a *process* dump, not a physical RAM image. Use WinPmem or Magnet RAM Capture for full memory.
  - LSASS dumps contain credentials — treat them as highly sensitive. LSA protection (RunAsPPL) or EDR may block the dump.

---

## 4. Network Capture (`netcap.ps1`)
- **Purpose:** Capture network traffic for a set duration using built-in `netsh trace`.
- **Usage:**
  ```powershell
  .\netcap.ps1 -Duration 120 -MaxSizeMB 1024
  ```
- **Output:** `NetCap_<HOST>_<timestamp>\netcap.etl` (SHA-256 printed)
- **Notes:** The trace is always stopped, even on Ctrl+C. Convert to pcapng with [etl2pcapng](https://github.com/microsoft/etl2pcapng) for Wireshark.

---

## 5. Persistence Checks (`persistence_checks.ps1`)
- **Purpose:** Enumerate common persistence mechanisms.
- **Usage:**
  ```powershell
  .\persistence_checks.ps1
  ```
- **Output:** `Persistence_<HOST>_<timestamp>\`
  - `ScheduledTasks.csv`, `Services.csv`, `StartupItems.csv`
  - `WMI_EventFilters.csv`, `WMI_EventConsumers.csv`, `WMI_Bindings.csv`
  - `Registry_Autostarts.csv` — Run/RunOnce, Winlogon Shell/Userinit, AppInit_DLLs, LSA packages, BootExecute, IFEO debuggers, Active Setup
  - `Autoruns.csv` (with hashes and signature verification) when autorunsc is in `Tools`

---

## 6. Quick Triage (`quick_triage.ps1`)
- **Purpose:** Seconds-long first look at processes, connections, users and sessions.
- **Usage:**
  ```powershell
  .\quick_triage.ps1
  ```
- **Output:** `Quick_<HOST>_<timestamp>\Processes.csv`, `TCP_Connections.csv`, `LocalUsers.csv`, `LoggedOnSessions.txt`

---

## 7. Compiled Launcher (`IR_Triage_Tool.exe`)
- Built from `IR_Triage_Launcher.cs` (see `IR_Triage_Launcher Walkthrough.md`). CI publishes a self-contained single-file exe as a build artifact.
- Self-elevates, then offers Basic / Advanced Memory / Full collection.
- Non-interactive: `IR_Triage_Tool.exe --mode basic|advanced|full`

---

## 8. Next Steps & Analysis
- Transfer the zip and verify its SHA-256 on the analysis workstation.
- Review suspicious processes, autoruns, WMI subscriptions and event logs for indicators of compromise.
- Use KAPE, Velociraptor, or commercial EDR for deeper analysis if available.

---

## 9. References
- [Sysinternals Suite](https://learn.microsoft.com/sysinternals/downloads/sysinternals-suite)
- [SANS Windows IR Poster](https://www.sans.org/posters/windows-incident-response-poster/)
- [KAPE](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape)
