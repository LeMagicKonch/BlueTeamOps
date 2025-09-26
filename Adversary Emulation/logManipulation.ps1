# Corrupt PowerShell ConsoleHistory Text
# Permissions Required: Normal
echo "" > C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Disable Script Block Logging
# PErmissions Required: Admin
# Method 1: Registry
Set-ItemProperty -Path HKLM:SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -Value 0

# Method 2: wevutil
wevtutil sl Microsoft-Windows-PowerShell/Operational /e:false

# Delete EVTX Logs
# Permissions Required: Admin
wevtutil cl Security
wevtutil cl "Windows PowerShell"
wevtutil cl Microsoft-Windows-PowerShell/Operational
wevtutil cl System
