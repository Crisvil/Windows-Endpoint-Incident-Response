
# Memory Dump Collection Script (memdump.ps1)

# Requires: Sysinternals ProcDump (recommended), or fallback to built-in tools
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputPath = "./IR_Collection_$timestamp"
if (-not (Test-Path $outputPath)) { New-Item -ItemType Directory -Path $outputPath | Out-Null }

$procdump = "./Tools/procdump64.exe"
if (Test-Path $procdump) {
    Write-Host "Using ProcDump to capture memory..." -ForegroundColor Cyan
    & $procdump -ma (Get-Process -Name lsass).Id "$outputPath/memdump.dmp"
    Write-Host "Memory dump saved to $outputPath/memdump.dmp" -ForegroundColor Green
} else {
    Write-Host "ProcDump not found. Please download from Sysinternals or use Task Manager (Create Dump File on lsass.exe)." -ForegroundColor Yellow
}
