schtasks /CREATE /SC MINUTES 3 /ONCE /TN updater /TR "powershell.exe -c calc.exe"

schtasks /DELETE /TN updater /F