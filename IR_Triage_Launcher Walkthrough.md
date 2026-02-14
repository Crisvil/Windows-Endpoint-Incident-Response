## IR_Triage_Launcher – Build & Compilation Guide

This guide provides step-by-step instructions for compiling and building the IR_Triage_Launcher tool on Windows.

Multiple build methods are supported:

✅ Visual Studio (Recommended)

✅ Command Line (.NET SDK)

✅ csc.exe (Single-file legacy method)

✅ Modern .NET 6/7/8 Single-File Publish

## Option 1: Build Using Visual Studio (Recommended)
1️⃣ Open Visual Studio 2022

Install Visual Studio 2022 with .NET desktop development workload.

2️⃣ Create a New Project

Select Console App (.NET Framework)

Choose .NET Framework 4.7.2 or higher

Name the project: IRTriageLauncher

3️⃣ Add Source Code

Replace the contents of:

Program.cs


With your full C# source code.

4️⃣ Build the Solution

Navigate to:

Build → Build Solution


Or press:

Ctrl + Shift + B

5️⃣ Output Location
bin\Release\IRTriageLauncher.exe

## Option 2: Command Line Build (No Visual Studio UI Required)

This method requires the .NET SDK.

Step 1: Create compile.bat

Save the following as:

compile.bat

@echo off
echo Compiling IR Triage Launcher...

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

(
REM Paste your full C# source code here
) > Program.cs

dotnet build -c Release

echo.
echo Build complete: bin\Release\IR_Triage_Tool.exe
pause

Step 2: Paste Your C# Code

Insert your complete source code where indicated.

Step 3: Run the Batch File

Double-click compile.bat
OR run from Command Prompt:

compile.bat

Output Location
IR_Triage_Build\bin\Release\IR_Triage_Tool.exe

## Option 3: Compile with csc.exe (Single File)

This method uses the legacy C# compiler included with the .NET Framework SDK.

Step 1: Save Source Code

Save your file as:

Program.cs

Step 2: Compile
csc.exe -target:exe -out:IR_Triage_Tool.exe -platform:anycpu Program.cs


⚠ Ensure csc.exe is in your system PATH.

Output
IR_Triage_Tool.exe


Located in the current directory.

## Option 4: Modern .NET 6/7/8 Single-File Publish (Recommended for Production)

This creates a fully self-contained single executable.

Update Your .csproj File

Add:

<PropertyGroup>
    <PublishSingleFile>true</PublishSingleFile>
    <SelfContained>true</SelfContained>
    <RuntimeIdentifier>win-x64</RuntimeIdentifier>
    <PublishTrimmed>true</PublishTrimmed>
</PropertyGroup>

Publish Command
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true

Output Location
bin\Release\net6.0\win-x64\publish\


You will get:

IR_Triage_Tool.exe


Single file. No .NET installation required on target system.

Key Features
Feature	Implementation
Admin Check	Validates WindowsPrincipal for Administrator role
Execution Policy Bypass	Uses -ExecutionPolicy Bypass (legitimate IR use case)
Script Encoding	Base64 encodes embedded PowerShell
No Temporary Files	Executes PowerShell in memory
Real-Time Output	Streams console output live
Error Handling	Captures stderr and displays in red
Modular Menu	Selective execution framework
Security Considerations

⚠ This tool is intended only for authorized incident response and cybersecurity operations.

Legitimate use cases include:

System owner authorization

IR during restricted PowerShell environments (GPO blocks)

Authorized penetration testing with written permission

Blue Team Detection Notes

Defensive teams should monitor:

powershell.exe -EncodedCommand with long Base64 strings

Suspicious execution of IR_Triage_Tool.exe

Rapid sequential access to:

Security event logs

Registry run keys

Process memory

Troubleshooting
Issue	Solution
dotnet not found	Install latest .NET SDK
csc.exe missing	Install .NET Framework SDK
Build errors	Ensure correct TargetFramework
Single-file fails	Verify RuntimeIdentifier matches OS
License

Include your license and usage terms here.

Repository Notes

For issues or improvements:

Open an issue in your GitHub repository.

If you’d like, I can also generate:

✅ A professional README.md

✅ A LICENSE template (MIT / Apache / Custom)

✅ A GitHub release checklist

✅ A digitally signed build checklist for enterprise IR tools
