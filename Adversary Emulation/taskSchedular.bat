schtasks /CREATE /SC MINUTES 3 /ONCE /TN updater /TR "powershell.exe -c calc.exe"

timeout /t 180

schtasks /DELETE /TN updater /F
