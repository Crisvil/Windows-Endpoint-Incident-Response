
# Persistence Checks Script (persistence_checks.ps1)
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputPath = "./IR_Collection_$timestamp"
if (-not (Test-Path $outputPath)) { New-Item -ItemType Directory -Path $outputPath | Out-Null }

Write-Host "Enumerating scheduled tasks, WMI, services, and autoruns..." -ForegroundColor Cyan
Get-ScheduledTask | Select-Object TaskName, TaskPath, State, Author, Actions, Triggers | Out-File "$outputPath/ScheduledTasks.txt"
Get-WmiObject -Class Win32_Service | Select-Object Name, State, StartMode, PathName | Out-File "$outputPath/Services.txt"

$autoruns = "./Tools/autorunsc.exe"
if (Test-Path $autoruns) {
    & $autoruns -accepteula -a * -c > "$outputPath/Autoruns.csv"
    Write-Host "Autoruns exported to $outputPath/Autoruns.csv" -ForegroundColor Green
} else {
    Write-Host "Autoruns not found. Checking registry Run keys only." -ForegroundColor Yellow
    $runKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            Get-ItemProperty $key | Out-File "$outputPath/RunKey_$($key -replace '[:\\]', '_').txt"
        }
    }
}
