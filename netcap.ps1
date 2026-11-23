<#
.SYNOPSIS
    Captures network traffic with the built-in netsh trace facility.
.DESCRIPTION
    Starts a packet capture for the given duration and always stops it,
    even if the script is interrupted with Ctrl+C. Output is an .etl file;
    convert it to .pcapng with Microsoft's etl2pcapng for Wireshark.
    Requires Administrator.
.PARAMETER Duration
    Capture length in seconds. Default 60.
.PARAMETER MaxSizeMB
    Maximum size of the trace file in MB. Default 512.
.PARAMETER OutputRoot
    Folder under which the timestamped collection folder is created.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 86400)]
    [int]$Duration = 60,
    [ValidateRange(16, 65536)]
    [int]$MaxSizeMB = 512,
    [string]$OutputRoot = (Join-Path $PSScriptRoot 'IR_Collection')
)

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'netsh trace requires an elevated (Administrator) PowerShell session.' }

$timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$outputPath = Join-Path $OutputRoot "NetCap_$($env:COMPUTERNAME)_$timestamp"
New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
# netsh needs an absolute path.
$traceFile = Join-Path (Resolve-Path -LiteralPath $outputPath).ProviderPath 'netcap.etl'

Write-Host "[*] Starting network capture for $Duration seconds..." -ForegroundColor Cyan
netsh trace start capture=yes report=no overwrite=yes maxsize=$MaxSizeMB tracefile="$traceFile"
if ($LASTEXITCODE -ne 0) { throw "netsh trace start failed (exit $LASTEXITCODE). Is another trace already running? Try: netsh trace stop" }

try {
    Start-Sleep -Seconds $Duration
} finally {
    Write-Host '[*] Stopping capture (this can take a minute)...' -ForegroundColor Cyan
    netsh trace stop | Out-Null
}

if (Test-Path -LiteralPath $traceFile) {
    $hash = (Get-FileHash -LiteralPath $traceFile -Algorithm SHA256).Hash
    Write-Host "[+] Network capture saved to $traceFile" -ForegroundColor Green
    Write-Host "[+] SHA256: $hash" -ForegroundColor Green
} else {
    Write-Host "[!] Trace file not found at $traceFile" -ForegroundColor Red
}
