# Compilation Instructions
Option 1: Using Visual Studio (Recommended)
Open Visual Studio 2022
Create new Console App (.NET Framework) - choose .NET Framework 4.7.2 or higher
Replace Program.cs with the code above
Build → Build Solution (Ctrl+Shift+B)
Output: bin\Release\IRTriageLauncher.exe
Option 2: Using Command Line (No Visual Studio Required)
Create a batch file compile.bat:

batch
Copy
@echo off
echo Compiling IR Triage Launcher...

:: Find MSBuild (adjust path if needed)
set MSBUILD="C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
if not exist %MSBUILD% set MSBUILD="C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe"

:: Create temporary project file
mkdir IR_Triage_Build 2>nul
cd IR_Triage_Build

(
echo ^<Project Sdk="Microsoft.NET.Sdk"^>
echo   ^<PropertyGroup^>
echo     ^<OutputType^>Exe^</OutputType^>
echo     ^<TargetFramework^>net472^</TargetFramework^>
echo     ^<AssemblyName^>IR_Triage_Tool^</AssemblyName^>
echo     ^<RootNamespace^>IRTriageLauncher^</RootNamespace^>
echo   ^</PropertyGroup^>
echo ^</Project^>
) > IR_Triage_Tool.csproj

:: Create Program.cs
(
paste the C# code here
) > Program.cs

:: Compile
dotnet build -c Release

echo.
echo Build complete: bin\Release\IR_Triage_Tool.exe
pause
Option 3: Using csc.exe (Single File, No Dependencies)
batch
Copy
@echo off
:: This creates a single EXE with no external dependencies
csc.exe -target:exe -out:IR_Triage_Tool.exe -platform:anycpu Program.cs
Key Features of This Executable
Table
Copy
Feature	Implementation
Admin Check	Validates WindowsPrincipal for Administrator role before execution
Execution Policy Bypass	Uses -ExecutionPolicy Bypass flag (legitimate IR use case)
Script Encoding	Base64 encodes embedded PowerShell to prevent command injection
No Temporary Files	Scripts execute in memory, no PS1 files written to disk
Real-time Output	Streams PowerShell output to console in real-time
Error Handling	Captures stderr and displays in red
Modular Design	Menu system allows selective execution
Security Considerations
⚠️ Important: This tool is designed for authorized incident response and cybersecurity professionals. The execution policy bypass is a legitimate administrative technique when:
You own the system or have explicit authorization
Standard PowerShell execution is blocked by GPO but IR is required
You're conducting authorized penetration testing with written permission
Defensive Detections (for blue teams):
Monitor for powershell.exe -EncodedCommand with long base64 strings
Alert on IR_Triage_Tool.exe or similar process names
Monitor for rapid sequential access to Security event logs, registry run keys, and process memory
Alternative: Single-File .NET 6/7/8 Version
If you prefer a modern, single-file publish that doesn't require .NET Framework:
xml
Copy
<!-- Add to .csproj for .NET 6+ -->
<PropertyGroup>
    <PublishSingleFile>true</PublishSingleFile>
    <SelfContained>true</SelfContained>
    <RuntimeIdentifier>win-x64</RuntimeIdentifier>
    <PublishTrimmed>true</PublishTrimmed>
</PropertyGroup>
Build with:
bash
Copy
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
