# PSNIT  ![version](https://img.shields.io/badge/version-0.1.0-blue.svg)
PowerShell Network Information Tool

## What does PSNIT do?
PSNIT uses native powershell cmdlets to gather information from your current network configuration. It's purpose is to assist users in troubleshooting, auditing, and securing their Windows network setup. In addition to network diagnostics, PSNIT also serves as a lightweight launcher for commonly used built-in Windows security tools, such as firewall settings, local security policy, credential manager among others.

## Work in progress
🐞 Port Hardening sweep crashes the program.
🐞 Setting static IP is not persistent after reboot.
🐞 Basic networking knowledge required beforehand.

## How to get started
Clone the PSNIT repository to your machine using PowerShell.
```git
git clone https://github.com/jsalmensuo/PSNIT.git
```
Move into the location.
```git
cd PSNIT
```

### Permission
Confirm the execution policy of your current PowerShell session.
```powershell 
Get-ExecutionPolicy
```

Allow the current session of Powershell to run locally created scripts, this opens a new terminal with temporary privileges.
```powershell 
pwsh.exe -ExecutionPolicy RemoteSigned
```

If instead you want your execution policy for locally created scripts to be persistent use these.
 ```powershell 
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

#If you want to remove said persistence.
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Undefined
```
### Run the launcher
```powershell
.\PSNIT.ps1
```