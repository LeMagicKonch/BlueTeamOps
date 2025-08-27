schtasks /CREATE /SC MINUTE /TN updater /TR "powershell.exe -c calc.exe"

timeout /t 180

schtasks /DELETE /TN updater /F

