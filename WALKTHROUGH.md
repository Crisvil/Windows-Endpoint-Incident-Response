
# Windows Endpoint Incident Response Walkthrough

**Last Updated:** February 05, 2026

This guide provides step-by-step instructions for using the scripts in this repository to perform rapid triage and deeper incident response on Windows endpoints.

---

## 1. Preparation
- Run all scripts as Administrator for best results.
- Ensure you have write access to the output directory (default: `./IR_Collection_<timestamp>`).
- If using Sysinternals tools (e.g., ProcDump, Autoruns), download and extract them to a known location (e.g., `./Tools`).

---

## 2. Main Triage Script (`WE_IR.ps1`)
- **Purpose:** Collects volatile and semi-volatile artifacts, highlights suspicious processes, and exports key system, user, process, network, and event log data.
- **Usage:**
  1. Open PowerShell as Administrator.
  2. Run: `powershell -ExecutionPolicy Bypass -File ./WE_IR.ps1`
  3. Review the output folder (e.g., `./IR_Collection_YYYYMMDD_HHMMSS`).
- **Key Outputs:**
  - SystemInfo.txt, Hotfixes.txt, LocalUsers.csv, LocalGroups.csv
  - Processes_Full.csv, Suspicious_Processes.txt
  - TCP_Connections.csv, UDP_Endpoints.csv, Services.csv
  - ScheduledTasks.csv, StartupItems.txt, DNSCache.txt
  - SecurityEvents.csv, SystemEvents.csv, ApplicationEvents.csv

---

## 3. Memory Dump Collection (`memdump.ps1`)
- **Purpose:** Capture a full memory dump for deeper forensic analysis.
- **Usage:**
  - With Sysinternals ProcDump:
    ```powershell
    ./memdump.ps1
    ```
  - Output: `./IR_Collection_*/memdump.dmp`
- **Note:** If ProcDump is not available, script will prompt for manual dump (Task Manager or built-in tools).

---

## 4. Network Capture (`netcap.ps1`)
- **Purpose:** Capture network traffic for a specified duration.
- **Usage:**
  ```powershell
  ./netcap.ps1 -Duration 60
  ```
  - Output: `./IR_Collection_*/netcap.etl`
- **Note:** Uses built-in `netsh trace` (no third-party tools required).

---

## 5. Persistence Checks (`persistence_checks.ps1`)
- **Purpose:** Enumerate common persistence mechanisms (scheduled tasks, WMI, services, autoruns).
- **Usage:**
  ```powershell
  ./persistence_checks.ps1
  ```
  - Output: `./IR_Collection_*/persistence_checks.txt`
- **Note:** If Sysinternals Autoruns is available, script will use it for deeper checks.

---

## 6. Quick Triage (`quick_triage.ps1`)
- **Purpose:** Minimal, fast collection of volatile evidence (processes, network, users).
- **Usage:**
  ```powershell
  ./quick_triage.ps1
  ```
  - Output: `./IR_Collection_*/quick_triage.txt`

---

## 7. Next Steps & Analysis
- Zip and transfer the collection folder to a secure analysis workstation.
- Review suspicious processes, autoruns, and event logs for indicators of compromise.
- Use tools like KAPE, Velociraptor, or commercial EDR for deeper analysis if available.

---

## 8. References
- [Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)
- [SANS Windows IR Poster](https://www.sans.org/posters/windows-incident-response-poster/)
- [KAPE](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape)
