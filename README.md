# Windows-Endpoint-Incident-Response
In the early stages of IR (Triage/Containment phase), you need fast, reliable collection of volatile and semi-volatile data before the system is powered off or deeper forensics tools are deployed. This script automates the collection of key artifacts that analysts commonly review first.

Running processes (with command lines and owners) → spot injected/malware processes
Network connections → identify potential C2 or data exfiltration
Persistence mechanisms (registry Run keys, startup folders, scheduled tasks) → common persistence locations
Services, users, DNS cache, system info → context and additional indicators
Basic flagging of suspicious processes (no path, running from Temp/AppData/Downloads, etc.) → quick wins for triage

It creates a timestamped folder (on C:) and exports everything to CSV/text files for easy offline review (Excel, notepad, or import into timeline tools).
Run as Administrator for maximum visibility (some data like process owners requires elevated privileges).

# Requirements

Windows 10/11 or Server 2016+ (uses built-in PowerShell 5.1+ cmdlets)
No external dependencies or installations

How to run
Open PowerShell as Administrator.
If needed, bypass execution policy for the session:
Set-ExecutionPolicy Bypass -Scope Process
Paste the script into a file (e.g., IR-Triage.ps1) or run it directly.
Execute: .\IR-Triage.ps1
After completion, zip the output folder and transfer it off the compromised host securely.

# Step-by-Step Testing Instructions

Prepare a Windows Test Environment
Windows 10/11 or Server 2016+ (PowerShell 5.1+ is built-in).
Log in as a local Administrator (or a user with admin privileges).

Open PowerShell as Administrator
Search for "PowerShell" in the Start menu.
Right-click → "Run as administrator".

