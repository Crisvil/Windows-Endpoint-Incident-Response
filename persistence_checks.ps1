<#
.SYNOPSIS
    Enumerates common Windows persistence mechanisms.
.DESCRIPTION
    Collects scheduled tasks, services, WMI event subscriptions, registry
    autostart locations (Run/RunOnce, Winlogon, IFEO debuggers, AppInit_DLLs,
    Active Setup, LSA packages) and startup folders. If Sysinternals
    autorunsc.exe / autorunsc64.exe is present in the Tools folder, a full
    Autoruns CSV (with hashes and signature checks) is also produced.
.PARAMETER OutputRoot
    Folder under which the timestamped collection folder is created.
.PARAMETER ToolsPath
    Folder containing Sysinternals tools. Defaults to .\Tools next to this script.
#>
[CmdletBinding()]
param(
    [string]$OutputRoot = (Join-Path $PSScriptRoot 'IR_Collection'),
    [string]$ToolsPath  = (Join-Path $PSScriptRoot 'Tools')
)

$timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$outputPath = Join-Path $OutputRoot "Persistence_$($env:COMPUTERNAME)_$timestamp"
New-Item -ItemType Directory -Path $outputPath -Force | Out-Null

function Save-Csv {
    param([Parameter(ValueFromPipeline)]$InputObject, [string]$Name)
    begin   { $items = New-Object System.Collections.Generic.List[object] }
    process { if ($null -ne $InputObject) { $items.Add($InputObject) } }
    end     { $items | Export-Csv -Path (Join-Path $outputPath $Name) -NoTypeInformation -Encoding UTF8 }
}

Write-Host '[*] Enumerating scheduled tasks...' -ForegroundColor Cyan
try {
    Get-ScheduledTask |
        Select-Object TaskName, TaskPath, State, Author,
            @{n = 'Actions';  e = { ($_.Actions  | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join '; ' } },
            @{n = 'Triggers'; e = { ($_.Triggers | ForEach-Object { $_.CimClass.CimClassName -replace '^MSFT_Task', '' }) -join '; ' } },
            @{n = 'RunAs';    e = { $_.Principal.UserId } } |
        Save-Csv -Name 'ScheduledTasks.csv'
} catch { Write-Host "[!] Scheduled tasks: $_" -ForegroundColor Red }

Write-Host '[*] Enumerating services...' -ForegroundColor Cyan
try {
    Get-CimInstance -ClassName Win32_Service |
        Select-Object Name, DisplayName, State, StartMode, StartName, PathName |
        Save-Csv -Name 'Services.csv'
} catch { Write-Host "[!] Services: $_" -ForegroundColor Red }

Write-Host '[*] Enumerating WMI event subscriptions...' -ForegroundColor Cyan
try {
    $ns = 'root\subscription'
    Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction Stop |
        Select-Object Name, Query, QueryLanguage, EventNamespace | Save-Csv -Name 'WMI_EventFilters.csv'
    Get-CimInstance -Namespace $ns -ClassName __EventConsumer -ErrorAction Stop |
        Select-Object @{n = 'Class'; e = { $_.CimClass.CimClassName } }, Name, CommandLineTemplate, ExecutablePath, ScriptText, ScriptingEngine |
        Save-Csv -Name 'WMI_EventConsumers.csv'
    Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction Stop |
        Select-Object @{n = 'Filter'; e = { $_.Filter.Name } }, @{n = 'Consumer'; e = { $_.Consumer.Name } } |
        Save-Csv -Name 'WMI_Bindings.csv'
} catch { Write-Host "[!] WMI subscriptions: $_" -ForegroundColor Red }

Write-Host '[*] Enumerating registry autostart locations...' -ForegroundColor Cyan
$valueKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows',
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa',
    'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
)
$interesting = '^(Shell|Userinit|AppInit_DLLs|LoadAppInit_DLLs|Authentication Packages|Security Packages|Notification Packages|BootExecute)$'
$rows = @(foreach ($key in $valueKeys) {
    if (-not (Test-Path $key)) { continue }
    $isRunKey = $key -match '\\Run(Once)?$'
    $props = Get-ItemProperty -Path $key
    foreach ($p in $props.PSObject.Properties) {
        if ($p.Name -like 'PS*') { continue }
        if ($isRunKey -or $p.Name -match $interesting) {
            [PSCustomObject]@{ Key = $key; Name = $p.Name; Value = ($p.Value -join ' ') }
        }
    }
})
# Image File Execution Options debuggers / SilentProcessExit monitors.
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
if (Test-Path $ifeo) {
    $rows += Get-ChildItem $ifeo | ForEach-Object {
        $d = Get-ItemProperty -Path $_.PSPath -Name Debugger -ErrorAction SilentlyContinue
        if ($d) { [PSCustomObject]@{ Key = $_.Name; Name = 'Debugger'; Value = $d.Debugger } }
    }
}
# Active Setup StubPath entries.
$activeSetup = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components'
if (Test-Path $activeSetup) {
    $rows += Get-ChildItem $activeSetup | ForEach-Object {
        $s = Get-ItemProperty -Path $_.PSPath -Name StubPath -ErrorAction SilentlyContinue
        if ($s) { [PSCustomObject]@{ Key = $_.Name; Name = 'StubPath'; Value = $s.StubPath } }
    }
}
$rows | Save-Csv -Name 'Registry_Autostarts.csv'

Write-Host '[*] Enumerating startup folders...' -ForegroundColor Cyan
$startupFolders = @(Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup')
Get-ChildItem -Path (Join-Path $env:SystemDrive 'Users') -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $startupFolders += Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
}
$startupFolders | Where-Object { Test-Path -LiteralPath $_ } | ForEach-Object {
    Get-ChildItem -LiteralPath $_ -Force | Select-Object Name, FullName, CreationTimeUtc, LastWriteTimeUtc, Length
} | Save-Csv -Name 'StartupItems.csv'

$autoruns = @('autorunsc64.exe', 'autorunsc.exe') |
    ForEach-Object { Join-Path $ToolsPath $_ } |
    Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if ($autoruns) {
    Write-Host "[*] Running $autoruns ..." -ForegroundColor Cyan
    # -a * : all entry types, -c : CSV, -h : hashes, -s : verify signatures, -nobanner
    & $autoruns -accepteula -nobanner -a * -c -h -s '*' |
        Out-File -FilePath (Join-Path $outputPath 'Autoruns.csv') -Encoding UTF8
    Write-Host '[+] Autoruns exported.' -ForegroundColor Green
} else {
    Write-Host "[-] autorunsc not found in $ToolsPath; skipped full Autoruns export." -ForegroundColor Yellow
}

Write-Host "[+] Persistence checks complete: $outputPath" -ForegroundColor Green
