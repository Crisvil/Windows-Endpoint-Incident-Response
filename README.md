# Windows-Endpoint-Incident-Response

In the early stages of IR (Triage/Containment phase), you need fast, reliable collection of volatile and semi-volatile data before the system is powered off or deeper forensics tools are deployed. These scripts automate the collection of key artifacts that analysts commonly review first.

- **Running processes** (command lines, owners, SHA-256 of executables) → spot injected/malware processes
- **Network connections** mapped to process names, ARP, SMB sessions, DNS cache → identify C2 or exfiltration
- **Persistence** (Run/RunOnce, Winlogon, IFEO, WMI subscriptions, scheduled tasks, services, startup folders)
- **Users, local admins, logged-on sessions, Defender status/exclusions, system info** → context and indicators
- **Event logs** (Security, System, Application, PowerShell, Defender, Task Scheduler)
- **Heuristic flagging** of suspicious processes (no path, user-writable locations, LOLBins with encoded/download command lines)

Output goes to a timestamped `<HOST>_<timestamp>` folder as CSV/text, with a SHA-256 manifest and a zip for chain of custody.

## Contents

| File | Purpose |
|------|---------|
| `WE_IR.ps1` | Main triage collection |
| `quick_triage.ps1` | Seconds-long first look |
| `persistence_checks.ps1` | Persistence enumeration (+ Autoruns if available) |
| `netcap.ps1` | Packet capture via `netsh trace` |
| `memdump.ps1` | Process memory dump via ProcDump |
| `IR_Triage_Launcher.cs` / `IRTriageLauncher.csproj` | Self-elevating single-exe launcher |

## Requirements

- Windows 10/11 or Server 2016+ (Windows PowerShell 5.1+ or PowerShell 7)
- No external dependencies; Sysinternals ProcDump/Autoruns are optional (place in `.\Tools`)

## How to run

1. Open PowerShell **as Administrator**.
2. If needed: `Set-ExecutionPolicy Bypass -Scope Process`
3. Run: `.\WE_IR.ps1` (or `.\WE_IR.ps1 -OutputRoot E:\Evidence` to write to external media)
4. Transfer the resulting `.zip` off the host and verify the printed SHA-256.

See [WALKTHROUGH.md](WALKTHROUGH.md) for every script's options and outputs.

## Building the launcher

```powershell
dotnet publish IRTriageLauncher.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish
.\publish\IR_Triage_Tool.exe --mode full
```

CI (`.github/workflows/dotnet-desktop.yml`) parses and lints every script with PSScriptAnalyzer, builds the launcher, and uploads the exe as an artifact.

## Testing

Use a disposable Windows 10/11 or Server VM, log in as a local administrator, open PowerShell as Administrator and run the scripts. Do not test memory dumps or packet captures on production systems without authorization.
