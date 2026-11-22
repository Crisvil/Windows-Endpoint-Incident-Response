<#
.SYNOPSIS
    Basic Windows Endpoint Triage Collection for Incident Response.
.DESCRIPTION
    Collects key volatile and semi-volatile artifacts into a timestamped folder,
    highlights potentially suspicious processes, exports event logs, writes a
    SHA-256 manifest of every collected file and (optionally) zips the result.
    Each section runs independently, so one failure does not stop the collection.
    Run as Administrator for best results.
.PARAMETER OutputRoot
    Folder under which the timestamped collection folder is created.
    Defaults to <SystemDrive>\IR_Collection.
.PARAMETER MaxEvents
    Number of most recent events to export from each event log. Default 5000.
.PARAMETER NoZip
    Skip creating a .zip of the collection folder.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\WE_IR.ps1
.EXAMPLE
    .\WE_IR.ps1 -OutputRoot D:\Cases -MaxEvents 20000
#>
[CmdletBinding()]
param(
    [string]$OutputRoot = (Join-Path $env:SystemDrive 'IR_Collection'),
    [ValidateRange(1, 1000000)]
    [int]$MaxEvents = 5000,
    [switch]$NoZip
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$outputPath = Join-Path $OutputRoot "$($env:COMPUTERNAME)_$timestamp"
New-Item -ItemType Directory -Path $outputPath -Force | Out-Null

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning 'Not running as Administrator: some artifacts (process owners, Security log) will be incomplete.'
}

Start-Transcript -Path (Join-Path $outputPath 'transcript.txt') -Force | Out-Null
Write-Host "[*] Collecting data to: $outputPath" -ForegroundColor Green

function Invoke-Section {
    param([string]$Name, [scriptblock]$Action)
    Write-Host "[*] $Name" -ForegroundColor Cyan
    try { & $Action }
    catch {
        Write-Host "[!] $Name failed: $_" -ForegroundColor Red
        "[$(Get-Date -Format o)] $Name : $_" | Out-File (Join-Path $outputPath 'Errors.txt') -Append -Encoding UTF8
    }
}

function Out-Artifact {
    param([Parameter(ValueFromPipeline)]$InputObject, [string]$Name)
    begin   { $items = New-Object System.Collections.Generic.List[object] }
    process { if ($null -ne $InputObject) { $items.Add($InputObject) } }
    end {
        $path = Join-Path $outputPath $Name
        if ($Name -like '*.csv') { $items | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8 }
        else { $items | Format-List * | Out-File -FilePath $path -Encoding UTF8 -Width 4096 }
    }
}

Invoke-Section 'System information' {
    Get-CimInstance Win32_OperatingSystem |
        Select-Object CSName, Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime, LocalDateTime |
        Out-Artifact -Name 'SystemInfo.txt'
    Get-CimInstance Win32_ComputerSystem |
        Select-Object Name, Domain, Manufacturer, Model, UserName, TotalPhysicalMemory |
        Out-Artifact -Name 'ComputerSystem.txt'
    Get-TimeZone | Out-Artifact -Name 'TimeZone.txt'
}

Invoke-Section 'Hotfixes' {
    Get-HotFix | Select-Object HotFixID, Description, InstalledBy, InstalledOn |
        Sort-Object InstalledOn -Descending | Out-Artifact -Name 'Hotfixes.csv'
}

Invoke-Section 'Local users, groups and administrators' {
    Get-LocalUser | Select-Object Name, Enabled, Description, LastLogon, PasswordLastSet, SID |
        Out-Artifact -Name 'LocalUsers.csv'
    Get-LocalGroup | Select-Object Name, Description, SID | Out-Artifact -Name 'LocalGroups.csv'
    # Get-LocalGroupMember throws on orphaned SIDs; fall back to net.exe output.
    try {
        Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop |
            Select-Object Name, ObjectClass, PrincipalSource, SID | Out-Artifact -Name 'LocalAdministrators.csv'
    } catch {
        net localgroup Administrators | Out-File (Join-Path $outputPath 'LocalAdministrators.txt') -Encoding UTF8
    }
    query user 2>&1 | Out-File (Join-Path $outputPath 'LoggedOnSessions.txt') -Encoding UTF8
}

$processes = @()
Invoke-Section 'Processes' {
    $script:processes = @(Get-CimInstance Win32_Process | ForEach-Object {
        $p = $_
        $owner = 'N/A'
        try {
            $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
            if ($o.User) { $owner = if ($o.Domain) { "$($o.Domain)\$($o.User)" } else { $o.User } }
        } catch {}
        $hash = $null
        if ($p.ExecutablePath -and (Test-Path -LiteralPath $p.ExecutablePath)) {
            try { $hash = (Get-FileHash -LiteralPath $p.ExecutablePath -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}
        }
        [PSCustomObject]@{
            ProcessId       = $p.ProcessId
            ParentProcessId = $p.ParentProcessId
            Name            = $p.Name
            ExecutablePath  = $p.ExecutablePath
            CommandLine     = $p.CommandLine
            Owner           = $owner
            CreationDate    = $p.CreationDate
            SHA256          = $hash
        }
    })
    $script:processes | Out-Artifact -Name 'Processes_Full.csv'

    $suspiciousPaths = '\\Temp\\|\\AppData\\|\\Downloads\\|\\Users\\Public\\|\\PerfLogs\\|\\ProgramData\\[^\\]+\.exe$|\\Windows\\Tasks\\|\$Recycle\.Bin'
    $lolbins = '^(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|wmic)\.exe$'
    $suspicious = $script:processes | Where-Object {
        ($null -eq $_.ExecutablePath -and $_.ProcessId -notin 0, 4) -or
        ($_.ExecutablePath -match $suspiciousPaths) -or
        ($_.Name -match $lolbins -and $_.CommandLine -match '-enc|-encodedcommand|frombase64string|downloadstring|iex|invoke-expression|http[s]?://|/i:http|scrobj\.dll|urlcache')
    }
    if ($suspicious) {
        $suspicious | Out-Artifact -Name 'Suspicious_Processes.csv'
        Write-Host "[!] $(@($suspicious).Count) suspicious process(es) flagged. See Suspicious_Processes.csv" -ForegroundColor Yellow
    }
}

Invoke-Section 'Network connections' {
    $procNames = @{}
    foreach ($p in $script:processes) { $procNames[[int]$p.ProcessId] = $p.Name }
    Get-NetTCPConnection |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess,
            @{n = 'ProcessName'; e = { $procNames[[int]$_.OwningProcess] } }, CreationTime |
        Out-Artifact -Name 'TCP_Connections.csv'
    Get-NetUDPEndpoint |
        Select-Object LocalAddress, LocalPort, OwningProcess,
            @{n = 'ProcessName'; e = { $procNames[[int]$_.OwningProcess] } }, CreationTime |
        Out-Artifact -Name 'UDP_Endpoints.csv'
    Get-NetIPConfiguration -Detailed | Out-Artifact -Name 'IPConfiguration.txt'
    Get-NetNeighbor -ErrorAction SilentlyContinue |
        Select-Object InterfaceAlias, IPAddress, LinkLayerAddress, State | Out-Artifact -Name 'ARPCache.csv'
    Get-SmbSession -ErrorAction SilentlyContinue | Out-Artifact -Name 'SMBSessions.csv'
    Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name, Path, Description | Out-Artifact -Name 'SMBShares.csv'
    Get-Content -Path (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') -ErrorAction SilentlyContinue |
        Out-File (Join-Path $outputPath 'HostsFile.txt') -Encoding UTF8
}

Invoke-Section 'DNS cache' {
    if (Get-Command Get-DnsClientCache -ErrorAction SilentlyContinue) {
        Get-DnsClientCache | Select-Object Entry, RecordName, Type, Status, TimeToLive, Data |
            Out-Artifact -Name 'DNSCache.csv'
    }
    ipconfig /displaydns | Out-File (Join-Path $outputPath 'DNSCache.txt') -Encoding UTF8
}

Invoke-Section 'Services' {
    Get-CimInstance Win32_Service |
        Select-Object Name, DisplayName, State, StartMode, StartName, PathName, ProcessId |
        Out-Artifact -Name 'Services.csv'
}

Invoke-Section 'Scheduled tasks' {
    Get-ScheduledTask | Where-Object State -ne 'Disabled' |
        Select-Object TaskName, TaskPath, State, Author,
            @{n = 'Actions';  e = { ($_.Actions  | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join '; ' } },
            @{n = 'Triggers'; e = { ($_.Triggers | ForEach-Object { $_.CimClass.CimClassName -replace '^MSFT_Task', '' }) -join '; ' } },
            @{n = 'RunAs';    e = { $_.Principal.UserId } } |
        Out-Artifact -Name 'ScheduledTasks.csv'
}

Invoke-Section 'Registry Run keys' {
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    )
    $entries = foreach ($key in $runKeys) {
        if (Test-Path $key) {
            $props = Get-ItemProperty -Path $key
            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Name -notlike 'PS*') {
                    [PSCustomObject]@{ Key = $key; Name = $prop.Name; Value = $prop.Value }
                }
            }
        }
    }
    $entries | Out-Artifact -Name 'RunKeys.csv'
}

Invoke-Section 'Startup folders' {
    $startupFolders = @(Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup')
    # Every user profile, not just the account running the script.
    Get-ChildItem -Path (Join-Path $env:SystemDrive 'Users') -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $startupFolders += Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
    }
    $startupFolders | Where-Object { Test-Path -LiteralPath $_ } | ForEach-Object {
        Get-ChildItem -LiteralPath $_ -Force | Select-Object Name, FullName, CreationTimeUtc, LastWriteTimeUtc, Length
    } | Out-Artifact -Name 'StartupItems.csv'
}

Invoke-Section 'Defender status' {
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        Get-MpComputerStatus | Out-Artifact -Name 'DefenderStatus.txt'
        Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess, ExclusionExtension, DisableRealtimeMonitoring |
            Out-Artifact -Name 'DefenderExclusions.txt'
        Get-MpThreatDetection -ErrorAction SilentlyContinue | Out-Artifact -Name 'DefenderDetections.csv'
    }
}

Invoke-Section 'Event logs' {
    foreach ($log in 'Security', 'System', 'Application', 'Microsoft-Windows-PowerShell/Operational',
                     'Microsoft-Windows-Windows Defender/Operational', 'Microsoft-Windows-TaskScheduler/Operational') {
        $file = Join-Path $outputPath (($log -replace '[\\/ ]', '_') + '_Events.csv')
        try {
            Get-WinEvent -LogName $log -MaxEvents $MaxEvents -ErrorAction Stop |
                Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, MachineName, Message |
                Export-Csv -Path $file -NoTypeInformation -Encoding UTF8
            Write-Host "    [+] $log exported" -ForegroundColor Green
        } catch {
            Write-Host "    [-] $log skipped: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

Stop-Transcript | Out-Null

# Hash manifest for chain of custody.
Get-ChildItem -LiteralPath $outputPath -File | Get-FileHash -Algorithm SHA256 |
    Select-Object @{n = 'File'; e = { Split-Path $_.Path -Leaf } }, Hash |
    Export-Csv -Path (Join-Path $outputPath 'SHA256_Manifest.csv') -NoTypeInformation -Encoding UTF8

if (-not $NoZip) {
    $zip = "$outputPath.zip"
    try {
        Compress-Archive -Path (Join-Path $outputPath '*') -DestinationPath $zip -Force
        $zipHash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
        Write-Host "[+] Archive: $zip" -ForegroundColor Green
        Write-Host "[+] Archive SHA256: $zipHash" -ForegroundColor Green
    } catch {
        Write-Host "[!] Failed to create archive: $_" -ForegroundColor Red
    }
}

Write-Host "[+] Collection complete: $outputPath" -ForegroundColor Green
