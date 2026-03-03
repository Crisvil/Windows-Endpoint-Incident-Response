using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Principal;
using System.Text;

namespace IRTriageLauncher
{
    class Program
    {
        // =========================
        // POWERSELL SCRIPTS (FIXED)
        // =========================

        private static readonly string BasicTriageScript = @"
# ======================
# Basic Windows Endpoint Triage Collection for Incident Response
# ======================

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$outputRoot = Join-Path $env:SystemDrive 'IR_Collection'
$outputPath = Join-Path $outputRoot $timestamp
if (-not (Test-Path $outputPath)) { New-Item -ItemType Directory -Path $outputPath -Force | Out-Null }

Start-Transcript -Path (Join-Path $outputPath 'transcript.txt') -Force | Out-Null

Write-Host '[*] IR Triage Collection Started' -ForegroundColor Cyan
Write-Host ('[*] Output: {0}' -f $outputPath) -ForegroundColor Green

try {
    # System Information
    Get-ComputerInfo |
        Select-Object WindowsProductName, WindowsVersion, OsArchitecture, TotalPhysicalMemory, CsName, CsDomain, BiosBIOSVersion, BiosManufacturer, OsLastBootUpTime |
        Out-File (Join-Path $outputPath 'SystemInfo.txt') -Encoding UTF8

    # Hotfixes
    Get-HotFix |
        Select-Object HotFixID, Description, InstalledBy, InstalledOn |
        Sort-Object InstalledOn -Descending |
        Out-File (Join-Path $outputPath 'Hotfixes.txt') -Encoding UTF8

    # Local Users & Groups
    Get-LocalUser |
        Select-Object Name, Enabled, Description, LastLogon, PasswordLastSet, SID |
        Export-Csv (Join-Path $outputPath 'LocalUsers.csv') -NoTypeInformation -Encoding UTF8

    Get-LocalGroup |
        Select-Object Name, Description, SID |
        Export-Csv (Join-Path $outputPath 'LocalGroups.csv') -NoTypeInformation -Encoding UTF8
}
catch {
    Write-Host ('[!] System/Accounts section error: {0}' -f $_) -ForegroundColor Red
}

# Process Analysis
try {
    $processes = Get-CimInstance Win32_Process | ForEach-Object {
        $p = $_
        $owner = 'N/A'
        try { $owner = (Invoke-CimMethod -InputObject $p -MethodName GetOwner).User } catch {}
        [PSCustomObject]@{
            ProcessId      = $p.ProcessId
            ParentProcessId= $p.ParentProcessId
            Name           = $p.Name
            ExecutablePath = $p.ExecutablePath
            CommandLine    = $p.CommandLine
            Owner          = $owner
            CreationDate   = $p.CreationDate
        }
    }

    $processes | Export-Csv (Join-Path $outputPath 'Processes_Full.csv') -NoTypeInformation -Encoding UTF8

    # Suspicious Process Heuristics
    $suspicious = $processes | Where-Object {
        ($_.ExecutablePath -eq $null) -or
        ($_.ExecutablePath -like '*\Temp\*') -or
        ($_.ExecutablePath -like '*\AppData\*') -or
        ($_.ExecutablePath -like '*\Downloads\*') -or
        ($_.ExecutablePath -like '*\Public\*') -or
        ($_.ExecutablePath -like '*\PerfLogs\*')
    }

    if ($suspicious) {
        $suspicious |
            Sort-Object Name, ProcessId |
            Format-Table ProcessId, Name, ExecutablePath, Owner, CommandLine -Wrap |
            Out-File (Join-Path $outputPath 'Suspicious_Processes.txt') -Encoding UTF8
        Write-Host '[!] Suspicious processes detected!' -ForegroundColor Red
    }
}
catch {
    Write-Host ('[!] Process analysis error: {0}' -f $_) -ForegroundColor Red
}

# Network
try {
    Get-NetTCPConnection | Where-Object State -eq 'Established' |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, State |
        Export-Csv (Join-Path $outputPath 'TCP_Connections.csv') -NoTypeInformation -Encoding UTF8

    Get-NetUDPEndpoint |
        Select-Object LocalAddress, LocalPort, OwningProcess |
        Export-Csv (Join-Path $outputPath 'UDP_Endpoints.csv') -NoTypeInformation -Encoding UTF8
}
catch {
    Write-Host ('[!] Network query error: {0}' -f $_) -ForegroundColor Red
}

# Services & Tasks
try {
    Get-CimInstance Win32_Service |
        Select-Object Name, DisplayName, State, StartMode, PathName |
        Export-Csv (Join-Path $outputPath 'Services.csv') -NoTypeInformation -Encoding UTF8

    Get-ScheduledTask | Where-Object State -ne 'Disabled' |
        Select-Object TaskName, TaskPath, State, Author,
                      @{n='Actions';e={$_.Actions | ForEach-Object {$_.Execute + ' ' + $_.Arguments} -join '; '}},
                      @{n='Triggers';e={$_.Triggers | ForEach-Object { $_.ToString() } -join '; '}} |
        Export-Csv (Join-Path $outputPath 'ScheduledTasks.csv') -NoTypeInformation -Encoding UTF8
}
catch {
    Write-Host ('[!] Services/Tasks error: {0}' -f $_) -ForegroundColor Red
}

# Registry Run Keys
try {
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    )

    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            $safeName = ($key -replace '[:\\]', '_')
            Get-ItemProperty $key |
                Out-File (Join-Path $outputPath ('RunKey_{0}.txt' -f $safeName)) -Encoding UTF8
        }
    }
}
catch {
    Write-Host ('[!] Run keys error: {0}' -f $_) -ForegroundColor Red
}

# Startup Folders
try {
    $startupFolders = @(
        (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'),
        (Join-Path $env:PROGRAMDATA 'Microsoft\Windows\Start Menu\Programs\Startup')
    )

    $startupItemsFile = Join-Path $outputPath 'StartupItems.txt'
    'Startup Folder Items:' | Out-File $startupItemsFile -Encoding UTF8
    foreach ($folder in $startupFolders) {
        if (Test-Path $folder) {
            ('{0}' -f $folder) | Out-File $startupItemsFile -Append -Encoding UTF8
            Get-ChildItem $folder |
                Select-Object Name, FullName, CreationTimeUtc, LastWriteTimeUtc |
                Format-Table -AutoSize | Out-File $startupItemsFile -Append -Encoding UTF8
        }
    }
}
catch {
    Write-Host ('[!] Startup items error: {0}' -f $_) -ForegroundColor Red
}

# DNS Cache
try {
    ipconfig /displaydns | Out-File (Join-Path $outputPath 'DNSCache.txt') -Encoding UTF8
}
catch {
    Write-Host ('[!] DNS cache export error: {0}' -f $_) -ForegroundColor Red
}

# Event Logs (top 5000)
try {
    $logs = @('Security', 'System', 'Application')
    foreach ($log in $logs) {
        $file = Join-Path $outputPath ('{0}_Events.csv' -f $log)
        try {
            Get-WinEvent -LogName $log -MaxEvents 5000 -ErrorAction Stop |
              Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
              Export-Csv $file -NoTypeInformation -Encoding UTF8
            Write-Host ('[+] {0} events exported' -f $log) -ForegroundColor Green
        }
        catch {
            Write-Host ('[-] Failed to export {0} events: {1}' -f $log, $_) -ForegroundColor Yellow
        }
    }
}
catch {
    Write-Host ('[!] Event logs section error: {0}' -f $_) -ForegroundColor Red
}

Write-Host ('[+] Collection complete: {0}' -f $outputPath) -ForegroundColor Green
Stop-Transcript | Out-Null
";

        private static readonly string AdvancedMemoryScript = @"
# ======================
# Advanced Memory Analysis Module
# ======================

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$outputRoot = Join-Path $env:SystemDrive 'AdvancedIR_Memory'
$outputPath = Join-Path $outputRoot $timestamp
New-Item -ItemType Directory -Path $outputPath -Force | Out-Null

Start-Transcript -Path (Join-Path $outputPath 'transcript.txt') -Force | Out-Null
Write-Host '[*] Advanced Memory Analysis Started' -ForegroundColor Cyan

# Process Analysis with Anomaly Heuristics
try {
    $processes = Get-CimInstance Win32_Process | ForEach-Object {
        $proc = $_
        $isDotNet = $false
        $isHollowed = $false
        $owner = 'N/A'

        try {
            $procId = $proc.ProcessId
            if ($procId -gt 0 -and $procId -ne 4) {
                $procDetails = Get-Process -Id $procId -ErrorAction SilentlyContinue
                if ($procDetails) {
                    try {
                        $modules = $procDetails.Modules | Where-Object { $_.ModuleName -match 'clr.dll|mscoree.dll' }
                        $isDotNet = [bool]$modules
                    } catch {}
                    $imagePath = $proc.ExecutablePath
                    if ($imagePath) {
                        $expectedName = [System.IO.Path]::GetFileNameWithoutExtension($imagePath)
                        $actualName = $proc.Name -replace '\.exe$', ''
                        if ($expectedName -and $expectedName -ne $actualName) { $isHollowed = $true }
                    }
                }
            }
        } catch {}

        try { $owner = (Invoke-CimMethod -InputObject $proc -MethodName GetOwner).User } catch {}

        [PSCustomObject]@{
            ProcessId             = $proc.ProcessId
            ParentProcessId       = $proc.ParentProcessId
            Name                  = $proc.Name
            ExecutablePath        = $proc.ExecutablePath
            CommandLine           = $proc.CommandLine
            Owner                 = $owner
            CreationDate          = $proc.CreationDate
            IsDotNet              = $isDotNet
            IsPotentiallyHollowed = $isHollowed
            ThreadCount           = $proc.ThreadCount
            HandleCount           = $proc.HandleCount
            WorkingSetSize        = $proc.WorkingSetSize
        }
    }

    $processes | Export-Csv (Join-Path $outputPath 'Advanced_Process_Analysis.csv') -NoTypeInformation -Encoding UTF8

    $injectionIndicators = $processes | Where-Object {
        ($_.ExecutablePath -eq $null -and $_.ProcessId -ne 0) -or
        ($_.IsDotNet -and ($_.ParentProcessId -in @(1, 4, 0))) -or
        ($_.IsPotentiallyHollowed) -or
        ($_.HandleCount -gt 1000 -and $_.ThreadCount -lt 5)
    }

    if ($injectionIndicators) {
        $injectionIndicators | Export-Csv (Join-Path $outputPath 'Injection_Indicators.csv') -NoTypeInformation -Encoding UTF8
        Write-Host '[!] Potential injection artifacts detected!' -ForegroundColor Red
    }
}
catch {
    Write-Host ('[!] Process anomaly section error: {0}' -f $_) -ForegroundColor Red
}

# ETW Sessions
try {
    $etwSessions = logman query -ets |
        Select-String '^\s+(\S+)\s+(\S+)\s+(\S+)' |
        ForEach-Object {
            $m = $_.Matches[0].Groups
            [PSCustomObject]@{ SessionName = $m[1].Value; Type = $m[2].Value; Status = $m[3].Value }
        }
    $etwSessions | Export-Csv (Join-Path $outputPath 'ETW_Sessions.csv') -NoTypeInformation -Encoding UTF8
}
catch {
    Write-Host ('[!] ETW enumeration error: {0}' -f $_) -ForegroundColor Yellow
}

# AMSI-related PowerShell events (last 24h)
try {
    $amsiEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-PowerShell/Operational'
        ID        = 4104
        StartTime = (Get-Date).AddHours(-24)
    } -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -match 'amsiInitFailed|AmsiScanBuffer|System.Management.Automation.AmsiUtils'
    } | Select-Object TimeCreated, Id, Message

    if ($amsiEvents) {
        $amsiEvents | Export-Csv (Join-Path $outputPath 'AMSI_Bypass_Indicators.csv') -NoTypeInformation -Encoding UTF8
        Write-Host '[!] AMSI bypass attempts detected!' -ForegroundColor Red
    }
}
catch {
    Write-Host ('[!] AMSI event parsing error: {0}' -f $_) -ForegroundColor Yellow
}

# Credential Protection (LSA PPL & Credential Guard)
try {
    $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -ErrorAction SilentlyContinue
    $lsaStatus = if ($null -ne $lsa -and ($lsa.RunAsPPL -eq 1 -or $lsa.RunAsPPL -eq 2)) { 'Enabled' } else { 'Disabled' }

    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction SilentlyContinue
    $cgStatus = 'Unknown'
    if ($dg -and $dg.SecurityServicesRunning) {
        $cgStatus = if ($dg.SecurityServicesRunning -contains 1) { 'Running' } else { 'Not Running' }
    }

    [PSCustomObject]@{
        LSAProtection   = $lsaStatus
        CredentialGuard = $cgStatus
    } | Export-Csv (Join-Path $outputPath 'Credential_Protection_Status.csv') -NoTypeInformation -Encoding UTF8
}
catch {
    Write-Host ('[!] Credential protection query error: {0}' -f $_) -ForegroundColor Yellow
}

Write-Host ('[+] Memory Analysis Complete: {0}' -f $outputPath) -ForegroundColor Green
Stop-Transcript | Out-Null
";

        // =========================
        // PROGRAM ENTRY
        // =========================

        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.Title = "Windows IR Triage Collection Tool";

            string version = "2.1.0";
            try
            {
                Assembly asm = Assembly.GetExecutingAssembly();
                Version ver = asm != null ? asm.GetName().Version : null;
                if (ver != null) version = ver.ToString();
            }
            catch { }

            Console.WriteLine(string.Format(@"
╔══════════════════════════════════════════════════════════════╗
║     Windows Incident Response Triage Collection Tool         ║
║                    Version {0}                               ║
╚══════════════════════════════════════════════════════════════╝
", version));

            // Self-elevate if not admin
            if (!IsAdministrator())
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[!] Administrator privileges required. Elevating...");
                Console.ResetColor();

                try
                {
                    string exe = null;

                    try
                    {
                        Process current = Process.GetCurrentProcess();
                        if (current != null && current.MainModule != null)
                            exe = current.MainModule.FileName;
                    }
                    catch { }

                    if (string.IsNullOrEmpty(exe))
                    {
                        try { exe = Assembly.GetExecutingAssembly().Location; } catch { }
                    }

                    if (string.IsNullOrEmpty(exe))
                        throw new Exception("Unable to determine executable path.");

                    ProcessStartInfo psiElevate = new ProcessStartInfo(exe);
                    psiElevate.UseShellExecute = true;
                    psiElevate.Verb = "runas";
                    psiElevate.Arguments = args != null ? string.Join(" ", args) : "";

                    Process.Start(psiElevate);
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[!] Elevation failed: " + ex.Message);
                    Console.ResetColor();
                }
                return;
            }

            Console.WriteLine("Select operation mode:");
            Console.WriteLine("1. Basic Triage Collection (Standard artifacts)");
            Console.WriteLine("2. Advanced Memory Analysis (Process injection, ETW, AMSI)");
            Console.WriteLine("3. Full Collection (Both modules)");
            Console.WriteLine("4. Exit");
            Console.Write("\nSelection [1-4]: ");

            string choice = Console.ReadLine();
            string scriptToRun = null;

            switch (choice)
            {
                case "1":
                    scriptToRun = BasicTriageScript;
                    break;
                case "2":
                    scriptToRun = AdvancedMemoryScript;
                    break;
                case "3":
                    scriptToRun = BasicTriageScript + Environment.NewLine + AdvancedMemoryScript;
                    break;
                case "4":
                    scriptToRun = null;
                    break;
                default:
                    scriptToRun = BasicTriageScript;
                    break;
            }

            if (scriptToRun == null) return;

            Console.WriteLine("\n[*] Starting collection...");
            Console.WriteLine("[*] Do not close this window until completion.\n");

            try
            {
                ExecutePowerShellScript(scriptToRun);

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("\n[+] Collection completed successfully!");
                Console.WriteLine("[+] Check C:\\IR_Collection\\<timestamp> and C:\\AdvancedIR_Memory\\<timestamp> for results.");
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n[!] Error during execution: " + ex.Message);
                Console.ResetColor();
            }

            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey(true);
        }

        // =========================
        // HELPERS
        // =========================

        static bool IsAdministrator()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                if (identity == null) return false;
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        static string ResolvePowerShellPath()
        {
            string windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            bool is64OS = Environment.Is64BitOperatingSystem;
            bool is64Proc = Environment.Is64BitProcess;

            if (is64OS && !is64Proc)
            {
                // 32-bit process on 64-bit OS → use Sysnative to reach 64-bit PowerShell
                return Path.Combine(windir, "Sysnative", "WindowsPowerShell", "v1.0", "powershell.exe");
            }
            return Path.Combine(windir, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
        }

        static void ExecutePowerShellScript(string script)
        {
            // PowerShell -EncodedCommand expects UTF-16LE (Unicode)
            string encodedScript = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));

            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = ResolvePowerShellPath();
            psi.Arguments = "-ExecutionPolicy Bypass -NoProfile -EncodedCommand " + encodedScript;
            psi.UseShellExecute = false;             // capture output
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.CreateNoWindow = false;
            psi.WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

            using (Process process = new Process())
            {
                process.StartInfo = psi;

                process.OutputDataReceived += (sender, e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data))
                        Console.WriteLine(e.Data);
                };

                process.ErrorDataReceived += (sender, e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data))
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("[ERROR] " + e.Data);
                        Console.ResetColor();
                    }
                };

                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                process.WaitForExit();

                if (process.ExitCode != 0)
                    throw new Exception("PowerShell exited with code " + process.ExitCode);
            }
        }
    }
}
