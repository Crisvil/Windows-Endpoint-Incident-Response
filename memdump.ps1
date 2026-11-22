<#
.SYNOPSIS
    Captures a full process memory dump with Sysinternals ProcDump.
.DESCRIPTION
    Dumps the memory of one process (LSASS by default) for offline forensic
    analysis. ProcDump (procdump64.exe or procdump.exe) must be placed in the
    Tools folder. This is a process dump, not a full physical-memory image;
    use a dedicated acquisition tool (e.g. WinPmem, Magnet RAM Capture) for that.

    NOTE: LSASS dumps contain credential material. Handle and store the output
    as highly sensitive evidence. EDR/AV products may block or alert on this.
    Requires Administrator.
.PARAMETER ProcessName
    Name of the process to dump (without .exe). Default 'lsass'.
.PARAMETER ProcessId
    PID of the process to dump. Overrides ProcessName.
.PARAMETER ToolsPath
    Folder containing ProcDump. Defaults to .\Tools next to this script.
.PARAMETER OutputRoot
    Folder under which the timestamped collection folder is created.
#>
[CmdletBinding(DefaultParameterSetName = 'ByName')]
param(
    [Parameter(ParameterSetName = 'ByName')]
    [string]$ProcessName = 'lsass',
    [Parameter(ParameterSetName = 'ById', Mandatory)]
    [int]$ProcessId,
    [string]$ToolsPath  = (Join-Path $PSScriptRoot 'Tools'),
    [string]$OutputRoot = (Join-Path $PSScriptRoot 'IR_Collection')
)

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Memory dumps require an elevated (Administrator) PowerShell session.' }

$procdump = @('procdump64.exe', 'procdump.exe') |
    ForEach-Object { Join-Path $ToolsPath $_ } |
    Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $procdump) {
    Write-Host "ProcDump not found in $ToolsPath. Download it from https://learn.microsoft.com/sysinternals/downloads/procdump" -ForegroundColor Yellow
    Write-Host 'Alternative: Task Manager > Details > right-click process > Create memory dump file.' -ForegroundColor Yellow
    return
}

$target = if ($PSCmdlet.ParameterSetName -eq 'ById') {
    Get-Process -Id $ProcessId -ErrorAction Stop
} else {
    Get-Process -Name $ProcessName -ErrorAction Stop | Select-Object -First 1
}

$timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$outputPath = Join-Path $OutputRoot "MemDump_$($env:COMPUTERNAME)_$timestamp"
New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
$dumpFile = Join-Path $outputPath ("{0}_{1}.dmp" -f $target.ProcessName, $target.Id)

Write-Host "[*] Dumping $($target.ProcessName) (PID $($target.Id)) with ProcDump..." -ForegroundColor Cyan
& $procdump -accepteula -nobanner -ma $target.Id $dumpFile
if ($LASTEXITCODE -lt 0 -or -not (Test-Path -LiteralPath $dumpFile)) {
    Write-Host '[!] Dump failed. LSASS may be protected (RunAsPPL) or blocked by EDR.' -ForegroundColor Red
    return
}

$hash = (Get-FileHash -LiteralPath $dumpFile -Algorithm SHA256).Hash
"$hash  $(Split-Path $dumpFile -Leaf)" | Out-File (Join-Path $outputPath 'SHA256.txt') -Encoding ASCII
Write-Host "[+] Memory dump saved to $dumpFile" -ForegroundColor Green
Write-Host "[+] SHA256: $hash" -ForegroundColor Green
