# Windows-Endpoint-Incident-Response
In the early stages of IR (Triage/Containment phase), you need fast, reliable collection of volatile and semi-volatile data before the system is powered off or deeper forensics tools are deployed. This script automates the collection of key artifacts that analysts commonly review first.

Running processes (with command lines and owners) → spot injected/malware processes
Network connections → identify potential C2 or data exfiltration
Persistence mechanisms (registry Run keys, startup folders, scheduled tasks) → common persistence locations
Services, users, DNS cache, system info → context and additional indicators
Basic flagging of suspicious processes (no path, running from Temp/AppData/Downloads, etc.) → quick wins for triage

It creates a timestamped folder (on C:) and exports everything to CSV/text files for easy offline review (Excel, notepad, or import into timeline tools).
Run as Administrator for maximum visibility (some data like process owners requires elevated privileges).
