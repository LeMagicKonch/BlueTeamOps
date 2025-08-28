schtasks /CREATE /SC MINUTE /TN updater /TR "powershell.exe -w hidden -c calc.exe; schtasks /DELETE /TN updater /F"

timeout /t 240

schtasks /DELETE /TN updater /F



