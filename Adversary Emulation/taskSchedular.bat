schtasks /CREATE /SC MINUTE /TN updater /TR "powershell.exe -c calc.exe"

timeout /t 240

schtasks /DELETE /TN updater /F


