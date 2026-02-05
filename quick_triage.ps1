
# Quick Triage Script (quick_triage.ps1)
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputPath = "./IR_Collection_$timestamp"
if (-not (Test-Path $outputPath)) { New-Item -ItemType Directory -Path $outputPath | Out-Null }

Write-Host "Collecting quick triage data..." -ForegroundColor Cyan
Get-Process | Select-Object Id, ProcessName, Path, StartTime | Out-File "$outputPath/quick_triage.txt"
Get-NetTCPConnection | Where-Object State -eq "Established" | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess | Out-File "$outputPath/quick_triage.txt" -Append
Get-LocalUser | Select-Object Name, Enabled | Out-File "$outputPath/quick_triage.txt" -Append
Write-Host "Quick triage complete. Output: $outputPath/quick_triage.txt" -ForegroundColor Green
