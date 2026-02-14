using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using System.Security.Principal;

namespace IRTriageLauncher
{
    class Program
    {
        // Embedded PowerShell scripts - Base64 encoded to avoid string escaping issues
        private static readonly string BasicTriageScript = @"
# Basic Windows Endpoint Triage Collection for Incident Response
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$outputPath = 'C:\IR_Collection_$timestamp'

if (-not (Test-Path $outputPath)) {
    New-Item -ItemType Directory -Path $outputPath | Out-Null
}

Write-Host '[*] IR Triage Collection Started' -ForegroundColor Cyan
Write-Host '[*] Output: $outputPath' -ForegroundColor Green

# System Information
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsArchitecture, 
    TotalPhysicalMemory, CsName, CsDomain, BiosBIOSVersion, BiosManufacturer, 
    OsLastBootUpTime | Out-File '$outputPath\SystemInfo.txt'

# Hotfixes
Get-HotFix | Select-Object HotFixID, Description, InstalledBy, InstalledOn | 
    Sort-Object InstalledOn -Descending | Out-File '$outputPath\Hotfixes.txt'

# Local Users and Groups
Get-LocalUser | Select-Object Name, Enabled, Description, LastLogon, PasswordLastSet, SID | 
    Export-Csv '$outputPath\LocalUsers.csv' -NoTypeInformation

Get-LocalGroup | Select-Object Name, Description, SID | 
    Export-Csv '$outputPath\LocalGroups.csv' -NoTypeInformation

# Process Analysis
$processes = Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, 
    Name, ExecutablePath, CommandLine,
    @{Name='Owner'; Expression={ try { (Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User } catch { 'N/A' }}},
    CreationDate

$processes | Export-Csv '$outputPath\Processes_Full.csv' -NoTypeInformation

# Suspicious Process Detection
$suspicious = $processes | Where-Object {
    ($_.ExecutablePath -eq $null) -or
    ($_.ExecutablePath -like '*\Temp\*') -or
    ($_.ExecutablePath -like '*\AppData\*') -or
    ($_.ExecutablePath -like '*\Downloads\*') -or
    ($_.ExecutablePath -like '*\Public\*') -or
    ($_.ExecutablePath -like '*\PerfLogs\*')
}

if ($suspicious) {
    $suspicious | Format-Table ProcessId, Name, ExecutablePath, Owner, CommandLine -Wrap | 
        Out-File '$outputPath\Suspicious_Processes.txt'
    Write-Host '[!] Suspicious processes detected!' -ForegroundColor Red
}

# Network Connections
Get-NetTCPConnection | Where-Object State -eq 'Established' | 
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, CreationTime | 
    Export-Csv '$outputPath\TCP_Connections.csv' -NoTypeInformation

Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess | 
    Export-Csv '$outputPath\UDP_Endpoints.csv' -NoTypeInformation

# Services and Scheduled Tasks
Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName | 
    Export-Csv '$outputPath\Services.csv' -NoTypeInformation

Get-ScheduledTask | Where-Object State -ne 'Disabled' | 
    Select-Object TaskName, TaskPath, State, Author, Actions, Triggers | 
    Export-Csv '$outputPath\ScheduledTasks.csv' -NoTypeInformation

# Registry Run Keys
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
        Get-ItemProperty $key | Out-File '$outputPath\RunKey_$safeName.txt'
    }
}

# Startup Folders
$startupFolders = @(
    '$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup',
    '$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\Startup'
)

'Startup Folder Items:' | Out-File '$outputPath\StartupItems.txt'
foreach ($folder in $startupFolders) {
    if (Test-Path $folder) {
        '$folder' | Out-File '$outputPath\StartupItems.txt' -Append
        Get-ChildItem $folder | Select-Object Name, FullName, CreationTimeUtc, LastWriteTimeUtc | 
            Out-File '$outputPath\StartupItems.txt' -Append
    }
}

# DNS Cache
ipconfig /displaydns | Out-File '$outputPath\DNSCache.txt'

# Event Logs
$logs = @('Security', 'System', 'Application')
foreach ($log in $logs) {
    $file = '$outputPath\$log`Events.csv'
    try {
        Get-WinEvent -LogName $log -MaxEvents 5000 -ErrorAction Stop | 
            Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message | 
            Export-Csv $file -NoTypeInformation
        Write-Host '[+] $log events exported' -ForegroundColor Green
    } catch {
        Write-Host '[-] Failed to export $log events' -ForegroundColor Red
    }
}

Write-Host '[+] Collection complete: $outputPath' -ForegroundColor Green
";

        private static readonly string AdvancedMemoryScript = @"
# Advanced Memory Analysis Module
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$outputPath = 'C:\AdvancedIR_Memory_$timestamp'
New-Item -ItemType Directory -Path $outputPath -Force | Out-Null

Write-Host '[*] Advanced Memory Analysis Started' -ForegroundColor Cyan

# Process Analysis with Anomaly Detection
$processes = Get-CimInstance Win32_Process | ForEach-Object {
    $proc = $_
    $isDotNet = $false
    $isHollowed = $false
    
    try {
        $procId = $proc.ProcessId
        if ($procId -gt 0 -and $procId -ne 4) {
            $procDetails = Get-Process -Id $procId -ErrorAction SilentlyContinue
            if ($procDetails) {
                $modules = $procDetails.Modules | Where-Object { $_.ModuleName -match 'clr.dll|mscoree.dll' }
                $isDotNet = [bool]$modules
                
                $imagePath = $proc.ExecutablePath
                if ($imagePath) {
                    $expectedName = [System.IO.Path]::GetFileNameWithoutExtension($imagePath)
                    $actualName = $proc.Name -replace '\.exe$', ''
                    if ($expectedName -and $expectedName -ne $actualName) {
                        $isHollowed = $true
                    }
                }
            }
        }
    } catch { }
    
    [PSCustomObject]@{
        ProcessId = $proc.ProcessId
        ParentProcessId = $proc.ParentProcessId
        Name = $proc.Name
        ExecutablePath = $proc.ExecutablePath
        CommandLine = $proc.CommandLine
        Owner = try { (Invoke-CimMethod -InputObject $proc -MethodName GetOwner).User } catch { 'N/A' }
        CreationDate = $proc.CreationDate
        IsDotNet = $isDotNet
        IsPotentiallyHollowed = $isHollowed
        ThreadCount = $proc.ThreadCount
        HandleCount = $proc.HandleCount
        WorkingSetSize = $proc.WorkingSetSize
    }
}

$processes | Export-Csv '$outputPath\Advanced_Process_Analysis.csv' -NoTypeInformation

# Injection Indicators
$injectionIndicators = $processes | Where-Object {
    ($_.ExecutablePath -eq $null -and $_.ProcessId -ne 0) -or
    ($_.IsDotNet -and $_.ParentProcessId -in @(1, 4, 0)) -or
    ($_.IsPotentiallyHollowed) -or
    ($_.HandleCount -gt 1000 -and $_.ThreadCount -lt 5)
}

if ($injectionIndicators) {
    $injectionIndicators | Export-Csv '$outputPath\Injection_Indicators.csv' -NoTypeInformation
    Write-Host '[!] Potential injection artifacts detected!' -ForegroundColor Red
}

# ETW Session Check
$etwSessions = logman query -ets | Select-String '^\s+(\S+)\s+(\S+)\s+(\S+)' | ForEach-Object {
    $matches = $_.Matches[0].Groups
    [PSCustomObject]@{
        SessionName = $matches[1].Value
        Type = $matches[2].Value
        Status = $matches[3].Value
    }
}
$etwSessions | Export-Csv '$outputPath\ETW_Sessions.csv' -NoTypeInformation

# AMSI Check via Event Logs
$amsiEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    ID = 4104
    StartTime = (Get-Date).AddHours(-24)
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -match 'amsiInitFailed|AmsiScanBuffer|System.Management.Automation.AmsiUtils'
} | Select-Object TimeCreated, Id, Message

if ($amsiEvents) {
    $amsiEvents | Export-Csv '$outputPath\AMSI_Bypass_Indicators.csv' -NoTypeInformation
    Write-Host '[!] AMSI bypass attempts detected!' -ForegroundColor Red
}

# Credential Protection Check
$lsaProtection = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -ErrorAction SilentlyContinue
try {
    $credentialGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction SilentlyContinue
    $cgStatus = if ($credentialGuard.SecurityServicesRunning -band 0x01) { 'Running' } else { 'Not Running' }
} catch {
    $cgStatus = 'Unknown'
}

[PSCustomObject]@{
    LSAProtection = if ($lsaProtection.RunAsPPL -eq 1) { 'Enabled' } else { 'Disabled' }
    CredentialGuard = $cgStatus
} | Export-Csv '$outputPath\Credential_Protection_Status.csv' -NoTypeInformation

Write-Host '[+] Memory Analysis Complete: $outputPath' -ForegroundColor Green
";

        static void Main(string[] args)
        {
            Console.WriteLine(@"
╔══════════════════════════════════════════════════════════════╗
║     Windows Incident Response Triage Collection Tool         ║
║                    Version 2.0                               ║
╚══════════════════════════════════════════════════════════════╝
");

            // Check for Administrator privileges
            if (!IsAdministrator())
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[!] ERROR: This tool requires Administrator privileges.");
                Console.WriteLine("[!] Please run as Administrator.");
                Console.ResetColor();
                Console.WriteLine("\nPress any key to exit...");
                Console.ReadKey();
                return;
            }

            // Display menu
            Console.WriteLine("Select operation mode:");
            Console.WriteLine("1. Basic Triage Collection (Standard artifacts)");
            Console.WriteLine("2. Advanced Memory Analysis (Process injection, ETW, AMSI)");
            Console.WriteLine("3. Full Collection (Both modules)");
            Console.WriteLine("4. Exit");
            Console.Write("\nSelection [1-4]: ");

            string choice = Console.ReadLine();

            string scriptToRun = choice switch
            {
                "1" => BasicTriageScript,
                "2" => AdvancedMemoryScript,
                "3" => BasicTriageScript + "\n" + AdvancedMemoryScript,
                "4" => null,
                _ => BasicTriageScript
            };

            if (scriptToRun == null) return;

            Console.WriteLine("\n[*] Starting collection...");
            Console.WriteLine("[*] Do not close this window until completion.\n");

            try
            {
                ExecutePowerShellScript(scriptToRun);
                
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("\n[+] Collection completed successfully!");
                Console.WriteLine("[+] Check C:\\IR_Collection_* or C:\\AdvancedIR_* folders for results.");
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"\n[!] Error during execution: {ex.Message}");
                Console.ResetColor();
            }

            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }

        static bool IsAdministrator()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        static void ExecutePowerShellScript(string script)
        {
            // Encode script to Base64 to avoid command line escaping issues
            string encodedScript = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
            
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-ExecutionPolicy Bypass -NoProfile -EncodedCommand {encodedScript}",
                Verb = "runas", // Ensure admin rights
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = false,
                WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows)
            };

            using (Process process = new Process { StartInfo = psi })
            {
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
                        Console.WriteLine($"[ERROR] {e.Data}");
                        Console.ResetColor();
                    }
                };

                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                process.WaitForExit();

                if (process.ExitCode != 0)
                {
                    throw new Exception($"PowerShell exited with code {process.ExitCode}");
                }
            }
        }
    }
}
