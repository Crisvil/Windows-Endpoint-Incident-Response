
# Network Capture Script (netcap.ps1)
param(
    [int]$Duration = 60
)
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputPath = "./IR_Collection_$timestamp"
if (-not (Test-Path $outputPath)) { New-Item -ItemType Directory -Path $outputPath | Out-Null }

Write-Host "Starting network capture for $Duration seconds..." -ForegroundColor Cyan
Start-Process -NoNewWindow -FilePath "netsh" -ArgumentList "trace start capture=yes tracefile=$outputPath/netcap.etl" -Wait
Start-Sleep -Seconds $Duration
Start-Process -NoNewWindow -FilePath "netsh" -ArgumentList "trace stop" -Wait
Write-Host "Network capture saved to $outputPath/netcap.etl" -ForegroundColor Green
