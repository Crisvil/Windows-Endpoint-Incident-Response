<#
.SYNOPSIS
    Very fast first-look triage (processes, connections, users, sessions).
.DESCRIPTION
    Runs in seconds and writes CSVs you can open immediately. Use WE_IR.ps1
    for a full collection.
.PARAMETER OutputRoot
    Folder under which the timestamped collection folder is created.
#>
[CmdletBinding()]
param(
    [string]$OutputRoot = (Join-Path $PSScriptRoot 'IR_Collection')
)

$timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$outputPath = Join-Path $OutputRoot "Quick_$($env:COMPUTERNAME)_$timestamp"
New-Item -ItemType Directory -Path $outputPath -Force | Out-Null

Write-Host '[*] Collecting quick triage data...' -ForegroundColor Cyan

$procs = Get-CimInstance Win32_Process
$names = @{}
foreach ($p in $procs) { $names[[int]$p.ProcessId] = $p.Name }

$procs | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate |
    Export-Csv (Join-Path $outputPath 'Processes.csv') -NoTypeInformation -Encoding UTF8

Get-NetTCPConnection -State Established, Listen -ErrorAction SilentlyContinue |
    Select-Object State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess,
        @{n = 'ProcessName'; e = { $names[[int]$_.OwningProcess] } } |
    Export-Csv (Join-Path $outputPath 'TCP_Connections.csv') -NoTypeInformation -Encoding UTF8

Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet |
    Export-Csv (Join-Path $outputPath 'LocalUsers.csv') -NoTypeInformation -Encoding UTF8

query user 2>&1 | Out-File (Join-Path $outputPath 'LoggedOnSessions.txt') -Encoding UTF8

Write-Host "[+] Quick triage complete. Output: $outputPath" -ForegroundColor Green
