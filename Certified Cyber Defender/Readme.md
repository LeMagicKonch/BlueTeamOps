# **CCD Notes**

## Table Of Contents:
<!--ts-->
  * [Suricata](#suricata)
  * [Rita](#rita)
  * [Sysmon](#sysmon)
  * [Velociraptor](#velociraptor)
  * [Email Security](#email-security)
    * [GoPhish](#gophish)
    * [Honey Token](#honey-token)
  * [Network Forensics](#network-forensics)
    * [Preparing Network Captures for Analysis](#preparing-network-captures-for-analysis)
    * [WireShark](#wireshark)
    * [Zui](#zui)
    * [HTTP Analysis](#http-analysis)
    * [SMB Analysis](#smb-analysis)
    * [DNS Analysis](#dns-analysis)
    * [Digital Forensics: Network Lab 2](#Digital-Forensics:-Network-Lab-2)
 * [Digital Forensics](#digital-forensics)
   * [Memory Collection](#memory-collection)
   * [Disk Images](#disk-images)
 * [Disk Forensics](#disk-forensics)
   * [Windows](#windows)
     * [Lab](#lab)
<!--te-->

## **Suricata**

### **Configurations**

Below are some key files to review for Suricata configurations:

```
/etc/suricata/suricata.yaml

/opt/lib/suricata/suricata.rules
```

### **Log Files**

```
/var/log/suricata
```

Types of Log Files:
1. suricata.log
   operational logs
3. fast.log
   alerts for detected threats
5. eve.json
   Rich JSON-formatted logs for granular analysis
7. stats.log
   performance metrics

### **Analyzing PCAPs with Suricata**

```
sudo suricata -r <file-path>.pcap
```

### **Writing Custom Suricata Detections**

**Example Detection:**

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"ET TROJAN Possible Malware Download"; flow:established,to_server; content:"GET /malware.exe"; http_method; nocase; sid:1000001; rev:1;)
```

Step 1: Create Rule File

Create a new .rules file and add your detection to the file.

```
sudo vim /var/lib/suricata/local.rules
```

Step 2: Update suricata.yaml

Add the following line in the */etc/suricata/suricata.yaml* file under the *default-rule-path: /var/lib/suricata/rules* line:

```
rule-files:
  - suricata.rules
  - local.rules
```

Step 3: Reload Suricata

```
sudo kill -USR2 $(pidof suricata)
```

Step 4: Test Rule

## **Rita**

### **Importing Logs Into Rita**

First, convert pcap into a file for Rita:

```
zeek -r <file-path>.pcap local
```

then, import into Rita:

```
sudo rita import <file-paths> <name-of-DB>
```

### **Analyzing Suspicious DNS Activity/Tunneling**

Step 1: Import Logs

See above example command

Step 2: Identify Beaconing Domains

```
sudo rita show-beacons-fqdn <DB-name> -H
```

Step 3: Explode DNS Traffic

```
sudo rita show-exploded-dns <DB-path> -H | more
```

Step 4: Isolate the Malicious Domain

```
sudo rita show-exploded-dns <DB-path> | grep <domain>
```

### **Generate Report with Findings**

Generate an HTML formated report

```
rita html-report octopus
```

## **Sysmon**

Resources:

https://github.com/trustedsec/SysmonCommunityGuide

### **Creating Custom Detection Rule**

Step 1: Config File Format

![image](https://github.com/user-attachments/assets/ddb8a5b9-b6d0-43a6-a116-9802c8e57e1f)

Step 2: Place Config File in Sysmon Directory

Remember that the file name should be like : *processcreate.rule*

Step 3: Open PowerShell as Admin

Step 4: Update Sysmon Config

```
.\Sysmon64.exe -c <file-path>.rule
```

### **Create Custom Block Executable Rule**

#### Example Rule

![image](https://github.com/user-attachments/assets/9d03a00b-f4e2-4352-9e33-b10e5e912744)

Then follow the same steps to update Sysmon config

## **Velociraptor**

References:
https://docs.velociraptor.app/docs/deployment/

### **Accessing Velociraptor**

On the Velociraptor server, open a web browser and go to: *https://127.0.0.1:8889*

### **Starting Hunts**

Step 1: Go To *Hunt Manager*

Step 2: Select *New Hunt*

Step 3: Give Name to Hunt (be descriptive)

Step 4: Select Artifacts to Hunt

Step 5: Select *Launch*

Step 6: Select Hunt you want to run and then click *Run Hunt*

### **Top Useful Artifacts To Hunt**

File Downloads --> *Windows.Analysis.EvidenceOfDownload*

Process List --> *Windows.System.Pslist*

Process Tree --> *Generic.System.Pstree*

Network Connections (netstat) --> *Windows.Network.Netstat*

Windows Services --> *Windows.System.Services*

## **Email Security**

Sandboxes:
- https://www.hybrid-analysis.com/
- https://www.vmray.com/
- https://www.joesandbox.com/#windows
- https://any.run/

Activity: Analyze Exposed Email Headers
- https://download.cyberdefenders.org/BlueDemy/CCD/Evaluate_your_organization's_exposed_internal_mail_headers.pdf?_gl=1*j0zqhl*_gcl_au*MTA5MDAzMTQ5LjE3NDgxMDg2NTQuOTk0Njg4NDEzLjE3NDgxMDg2NjEuMTc0ODEwODY2MQ..*_ga*NzY1NzY5NzA2LjE3NDgxMDg2NTQ.*_ga_S3NEJKDDX5*czE3NDgxMDg2NTQkbzEkZzEkdDE3NDgxMDg3MTAkajQkbDAkaDY3NjY5NDAyMCRkaUtKR3pQbEpaRzdHTmdOOG1OOXVncy1VVnhkSjFGSGdoUQ..

Cuckoo Setup:
- https://download.cyberdefenders.org/BlueDemy/CCD/Cuckoo.pdf?_gl=1*az31uv*_gcl_au*MjE0NzA5ODM3My4xNzQ4MDI4OTU4Ljk2ODk2NjEwMC4xNzQ4MDQ2MzA3LjE3NDgwNDczNDU.*_ga*MTMzOTk3NTY2NC4xNzQ4MDI4OTU4*_ga_S3NEJKDDX5*czE3NDgwNDU5MzMkbzQkZzEkdDE3NDgwNDc4MDMkajU5JGwwJGgxNDY3MjY1MTU4JGRHd3dFZ0lfNUJDVFJrM3JmN1ZWeWlJeFdZY2hTNndMMUNR
- https://www.youtube.com/watch?v=T11ebEozlYk

### Email Attack Response Plan

![image](https://github.com/user-attachments/assets/69195efb-213f-48dc-afc8-4a32c935cd8c)


### **SPF**

Popular SPF Mechanisms:

![image](https://github.com/user-attachments/assets/95112bc9-eb79-4b55-8f91-eda1d7f7f237)


### **Enumerate SPF Records**

![image](https://github.com/user-attachments/assets/fe852192-192f-4c35-8a4a-4438516b8fc3)



### **DMARC**

Check DMARC Record for Domain:

```
┌──(lemagickonch㉿kali)-[~]
└─$ dig +short TXT _dmarc.alkosto.com.co
"v=DMARC1; p=quarantine; pct=100; rua=mailto:raphael.lopez@alkosto.com,mailto:boletin@alkosto.com; ruf=mailto:raphael.lopez@alkosto.com; sp=reject; ri=84600;fo=1;"
```

In the above output, emails for failed DMARC will be sent to : *raphael.lopez@alkosto.co*

### **DKIM**

DKIM Status':

![image](https://github.com/user-attachments/assets/560a74bb-6617-4f11-8872-0660eade1870)


## **GoPhish**

Reference:
1. https://www.youtube.com/watch?v=lVp0MHvRHIo&feature=youtu.be
2. Email Harvester --> https://github.com/maldevel/EmailHarvester

### Finding Version of GoPhish

```
systemctl list-unites --type=service

ps aux | grep gophish

cat /home/ubuntu/Desktop/CCD/gophish/VERSION
```



## **Honey Token**

Reference:
1. https://www.youtube.com/watch?v=jzUwVr0Sz-s


## **Network Forensics**

### **Preparing Network Captures for Analysis**

#### **NetFlow Records**

```
nfpcapd -r infile.pcap -z -w /output/Directory -t interval
```

##### Analyzing NetFlow Records

```
nfdump -R path/to/netflowRecords/ -n 10 -s scrip/packets
```

#### **Zeek**

```
zeek -r infile.pcap Log::default_logdir=./output/Directory
```

##### Types of Zeek Logs

1. conn.log --> TCP/UDP/ICMP connections
2. dns.log --> DNS logs
3. http.log --> HTTP Traffic

##### Analyzing Zeek Log Files

1. zeek-cut
2. awk

Example - AWK:

```
awk '/#fields/ {for (i=2; i<=NF; i++) print $i}' http.log
```

Example - Zeek-Cut:

```
cat http.log | zeek-cut id.orig_h id.resp_h uri
```

### **Wireshark**

#### **Find Downloaded Files**

Downloading files will most likely use GET requests. The below WireShark filter will find all GET requests:

```
http.request.method == "GET"
```

#### **Extract Files from PCAP**

File --> Export Objects --> HTTP

To get the file hash of the exported file on linux:

```
sha256sum <file-path>
```

#### **Search For Strings In Packet Data**

Sometimes you want to look for specific data in the packets so we want to search the packet contents for a specific string.

Do This:

1. Click *Find*
2. Change data type to *string*
3. Change search location to *Packet Details*

Example:

![image](https://github.com/user-attachments/assets/89604e9a-0618-452e-a4a0-96152bdd43c6)

### **Zui**

#### **Find All Alerts**

```
event_type == 'alert'
```

#### **Filter by Source IP**

```
id.orig_h == '<ip address'
```

### **HTTP Analysis**

#### Analyze HTTP Methods

```
cat access.log | awk '{print $1 $6}' | sort | uniq -c | sort
```

#### Analyze HTTP Return Codes

```
cat access.log | awk '{print $1 $9}' | sort | uniq -c | sort
```

#### Analyze User Agenets

```
cat access.log | awk -F '"' '{print $1 $6}' | cut -d " " -f1,7- | sort | uniq -
```

### **SMB Analysis**

In Zui we can use the following queries:

Check All Notices and look for *lateral movement*:

```
_path == 'notice' | sort ts
```

Files accessed or shared via SMB:

```
_path == 'smb_files' | sort ts
```

Find accessed shares and their mapping:

```
_path == 'smb_mapping' | sort ts
```

Check *Distributed Computing Environment / Remote Call Procedures* which can be associated with SMB:

```
_path == 'dce_rpc'
```

## **DNS Analysis**

Use *passivedns* to quickly parse through large PCAP files for DNS logs:

```
sudo passivedns -r <file_path>.pcap -l ./passivedns.log
```

Find top DNS queries:

```
cat passivedns.log | awk -F '|' '{print $9}' | sort | uniq -c | sort
```

Find large number of DNS responses:

```
cat passivedns.log | awk '{print $7, $9}' | sort | uniq -c
```

### **Extracting Objects*

```
#Check for embedded files
binwalk.exe contact.php

#Extract embedded files
binwalk.exe -e contact.php
```

### **Digital Forensics: Network Lab 2**

#### **Creating Zeek Logs**

```
mkdir zeek

zeek -r <file>.pcap Log::default_logdir=./zeek
```

#### **Finding Malicious Payloads**

##### WireShark

We can look for the *DOS* string in network traffic to identify *Portable Executables*:

```
frame contains "This program cannot be run in DOS mode"
```

We can also look for HTTP methods that are commonly used to send data to web servers:

```
http.request.method == "POST"
```

##### Extract Malicious Upload

First, go to the packet of the POST HTTP method that uploaded the malicious ISO file.

Then extract the payload from the pcap file:

![image](https://github.com/user-attachments/assets/474c7cd1-89ef-413a-8254-04b72e12f5f8)

Lastly, use *binwalk* to check for embedded executables and extract them from the ISO file.

![image](https://github.com/user-attachments/assets/65dfe4eb-e71f-4036-8e0e-fcabfda2b06d)

NOTE:
- In this example, the ISO file contained *ADOBE.exe* and *DOCUMENT.lnk*

##### Cobalt Strike Config Parser

Since we saw Cobalt Strike alerts in *Zui* we can use the *Cobalt Strike Config Parser* to see if there is a config built into the *adobe.exe* file we found:

![image](https://github.com/user-attachments/assets/673ec2e6-5d26-4700-90dc-ff62f209cbb9)

##### Analyzing *document.lnk*

![image](https://github.com/user-attachments/assets/7ae802bf-0666-43c6-a57c-5658c22520e7)

##### Finding Command Execution

First, I ran *strings* against the given pcap file looking for IOCs of command execution:

![image](https://github.com/user-attachments/assets/d4208eaf-4778-4a95-bff1-ac53d80919b9)

Seeing a couple instances of *PowerShell* I moved back to *WireShark* to get more info.

I used the search functionality and queried for the string *PowerShell* in the *bytes of packets*

![image](https://github.com/user-attachments/assets/5cdce877-2a6e-4fb0-a20d-9c1b8818cc6b)

I came across this packet that showed some tampering with AV...

## **Digital Forensics**

### **Evidence Aquisition**

Process:

![image](https://github.com/user-attachments/assets/49ae61d7-24b9-467e-aaa9-c1f27f3decf8)

![image](https://github.com/user-attachments/assets/d2ab5a86-7701-485d-b209-af1507987861)


Tool Overview:

![image](https://github.com/user-attachments/assets/f6d6983e-cbeb-4bcb-9ce7-d9a6c85803ce)

### **Memory Collection**

### **Live Windows Collection**

First, we need to check for Disk Encryption. This is crucial because if the device uses disk encryption we need to conduct live collection becuase if the device loses power or shuts down the data will be encrypted.

We can use *Encrypted Disk Detector* to check for disk encryption:

```
.\EDD.exe
```

Run *dumpit.exe* to collect raw image:

```
dumpit.exe /T raw
```

Next we need to ensure the capture was not corupted:

```
volatility -f <file_path>.raw imageinfo
```

### **Dead Windows Collection**

This will cover how to collect from a powered off Windows Device.

#### Hybernation File

```
C:\hyberfil.sys
```

Contains replica of memory of when device was put into hybernation

#### Paging File

```
C:\pagefile.sys
```

#### Crash Dump

```
C:\Windows\memory.dmp
```

### **Linux Memory Collection**

References:
- https://github.com/orlikoski/CyLR

```
uname -a

sudo insmod lime-<OS-Version>-generic.ko "path=<path-to-save>.mem format=lime timeout=0"

sudo ./CyLR
```

## **Disk Images**

### **Windows Disk Collection**

References:
- Write Block Device --> https://www.youtube.com/watch?v=7eT8KSHMGFw&themeRefresh=1

#### **FTK Imager**

Steps:
1. Create Disk Image
2. Choose Physical Drive
3. Click Add
4. Select Output Type (See Below for More Details)
5. Enter Evidence Info
6. Finish

FTK Imager Output Types:
- RAW
  - Bit-by-bit copy 
- SMART
  - not commonly used
- E01
  - Most Commonly Used (Use this one)
  - Also stores metadata
- AFF

### **Linux Disk Collection**

Exmaple:

![image](https://github.com/user-attachments/assets/59967c9d-de74-4178-9b78-364f8057c97e)


## **Disk Forensics**

### **Windows**

#### Registry Hives

Resources:
- https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives

![image](https://github.com/user-attachments/assets/760c7383-6a09-4acb-936c-6ed5e4245f9f)

![image](https://github.com/user-attachments/assets/4a71941b-5915-4f53-a0fd-12f97dd15967)

Transaction Logs:

![image](https://github.com/user-attachments/assets/63f493e4-8288-41f9-a344-819629680ebd)

Remote Registry Analysis:

- Open Regedit
- Select *Connect Network Registry*
- Enter IP address of desired device
- select OK and authenticate

#### Profiling Windows Systems

**Windows Version and Install Date**

```
SOFTWARE\Microsoft\Windows NT\CurrentVersion
```

![image](https://github.com/user-attachments/assets/21ef28b8-d888-4f51-a190-d45ddd572d92)

NOTE:
- in the above picture if we wanted to convert the times, right-click the time and select *Data Interpreter*

**Computer Name**

```
System\ControlSet001\Control\ComputerName\ComputerName
```

**Timezone**

```
SYSTEM\ControlSet001\Control\TimeZoneInformation
```

**StartUp and Shutdown Time**

Tool:
- https://www.nirsoft.net/utils/computer_turned_on_times.html

```
System\ControlSet001\Control\Windows
```

#### **Network Connections/Devices**

Tool:
- https://www.nirsoft.net/utils/wifi_history_view.html

**Network Interfaces and Configs**

```
SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards

SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces
```

![image](https://github.com/user-attachments/assets/d28d4b93-e034-4e99-b812-33506b98fdf1)

**Connection History**

```
SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged

SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles
```

![image](https://github.com/user-attachments/assets/c6e9a243-fba3-4391-aca3-85196be1ff66)

![image](https://github.com/user-attachments/assets/78e3f2c5-3051-4487-b641-8e34eaf347f9)

**Network Shares**

```
SYSTEM\ControlSet001\Services\LanmanServer\Shares
```

#### **User Information**

**Security Account Manager (SAM)**

```
# SAM File Location
C:\Windows\System32\config\SAM

# Backup SAM File Location
C:\Windows\Repair\SAM
```

We can use *RegRipper* to analyze the SAM file!

**Tracking User Activity with Security.evtx**

![image](https://github.com/user-attachments/assets/84834f88-98ec-47b0-82af-9e6cd4e8d63e)

#### **File and Folder Activity**

**$MFT**

Tools:
- RStudio --> https://www.r-studio.com/
- MFTEcmd / MFTEexplorer --> https://github.com/EricZimmerman/MFTECmd

Stored in the root of NTFS partition which we can find in FTK Imager.

**$UsnJrnl**

Provides high-level monitoring of file and folder changes (creation, deletion, renaming)

Located at *$Extend\$USJrnl*

Contains two other data streams: 
- $J where most important data resides
- $Max

Example:

![image](https://github.com/user-attachments/assets/e83f0449-7410-4a13-936d-22bf597de7cd)

**$LogFile**

Tool:
- https://sites.google.com/site/forensicnote/ntfs-log-tracker

Monitors changes to file/folders, but unlike $Usnjrnl, it stores detailed low-level changes to provide more resilience to the file system

Located in the volume root.

Example:

![image](https://github.com/user-attachments/assets/630287c7-48dc-499b-b604-9b48016761d6)

**$I30 INDX**

Tool:
- https://github.com/harelsegev/INDXRipper

Tracks which files are in which directories.

May keep track of deleted files even if securely wiped so this is very useful in proving the existance of a particular file even if it doesn't exist anymore.

Example:

![image](https://github.com/user-attachments/assets/26740e65-91b1-4498-91c2-13ad3211f136)

**Windows Search Database**

Tool:
- https://github.com/strozfriedberg/sidr

#### **Linking User Actions to Files/Folders**

**Security.evtx**

Enabling monitoring:

![image](https://github.com/user-attachments/assets/21812a4a-495a-4b38-921a-0083f942abdd)

Primary Event Codes:

![image](https://github.com/user-attachments/assets/4f22acd7-80cd-41ce-a147-472ef9d2f38f)

**MRULists**

Useful data in MRULists:
- list of files and commands each user accessed
- shows order

NTUSER.DAT Registry Hive:

```
C:\users\<user>\NTUSER.DAT
```

Common MRU Keys:

![image](https://github.com/user-attachments/assets/a78d4f4a-d9bc-457a-9d4c-7494d381ee57)

**Shellbags**

Tool:
- https://ericzimmerman.github.io/#!index.md

Shellbags are two registry sub-keys: *BagMRU* and *Bags*

Stores details about folders the user viewed using *File Explorer*

Location of Shellbag registry hives:
- c:\users\<user>\NTUSER.dat
- c:\users\<user>\AppData\Local\Microsoft\Windows\USRCLASS.dat

Shellbag Key Locations:

![image](https://github.com/user-attachments/assets/3641a8fd-ecbb-4111-8d47-240e63956479)

Why use shellbags?

Determine what folders any user viewed and what the contents of each folder was, even if it does not exist anymore

**LNK FIles**

Tool:
- Eric Zimmerman *LECmd*

LNK files are pointers to open a file or folder.

Valuable Info:
- original nfile
- creation date
- size

Example:

![image](https://github.com/user-attachments/assets/818c7f19-c5cb-4302-ba2c-aa84039ca124)

**JumpLists**

Tool:
- https://ericzimmerman.github.io/#!index.md

Jumplist Data Stored Locations:

![image](https://github.com/user-attachments/assets/21789cf0-a5ed-4c96-bc22-ceb6c07c4345)

#### **USB Devices**

**Registry**

SYSTEM Hive Keys to Investigate:

![image](https://github.com/user-attachments/assets/539dd3cc-a374-4765-b25d-4bac2914e965)

*USB* Key contains info about all USB devices connected to the system 

*USBSTOR* key stores info about USB data drives.

**setupapi.dev.log**

This is a plaintext log file located at *c:\windows\inf\setupapi.dev.log*

Contains information about Plug and Pay devices and driver installation.

Using this log we can identify *the first time a device was connected*.

**Event Logs**

![image](https://github.com/user-attachments/assets/f7b2dcf7-533c-425b-ad71-60d7c8039f7b)

**Determing Users Involved**

We will use the device GUID to determine who accessed USB.

To get the device GUIDs go to:

```
HKEY_CURRENT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
```

We can also use the below location for user specific objects:

```
HKEY_CURRENT\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeInfoCache
```

**Automation**

Tools:
- https://github.com/woanware/usbdeviceforensics
- https://usbdetective.com/
- USB Forensic Tacker tool

### **Analyzing Installed Applications**

**AppRepository**

Location:

```
c:\programdata\microsoft\windows\apprepository
```

We can analyze the *StateRepository-Machine.srd* database file using *DB Browser for SQLite*

**Registry**

Registry Locations:

![image](https://github.com/user-attachments/assets/9513392a-1d98-4ee0-aa9e-7af54a92b20b)

**EventLogs**

Event Codes of Interest:

![image](https://github.com/user-attachments/assets/3ffcb046-9fbf-48e5-87ea-388884878783)

### **Analyzing Execution Activities**

**Services**

Config of Windows services stored at: *c:\windows\system32\config\SYSTEM* under the *CurrentControlSet\Services* key

NOTE:
- there might be multiple variations of *ControlSet* like *ControlSet002* and *ControlSet003*
- This is because one acts as the active ControlSet while the others act as backups for a last known good state to revert to
- To determine which ControlSet is active or backups:
  - Check the *HKLM\SYSTEM\Select* key and you will see the loaded ControlSet under the key value *current*

Key Event Codes to help create a timeline for services:

![image](https://github.com/user-attachments/assets/be2fbf76-43fc-48ed-89fb-f98649639302)

**Windows Timeline**

Tool:
- Eric Zimmerman *WxTCMD*

Timeline data stored at:

```
c:\users\<user>\appdata\local\connecteddevicesplatform\L.<user>\activitiescache.db
```

**Autorun Applications**

Stored Registry Locations:

![image](https://github.com/user-attachments/assets/fc2d8346-bf71-4fd9-88e0-68061141063a)

**UserAssist Registry Key**

Tool:
- UserAssist Tool

This key stores info about programs that are frequently run by a specific user, last time programs were executed and how many times.

This key is stored in *NTUSER.dat* registry hive.

```
# Key location within NTUSER.dat
SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
```

NOTE:
- UserAssist only records GUI-based applications

**ShimCache aka AppCompatCache**

Tool:
- Eric Zimmerman AppCompatCacheParser

ShimCache is a feature that allows older apps to run on newer systems.

Find if an application uses ShimCache:
- right0click file
- select properties
- select Compatability Mode
- Look for following string "Run this program in compatability mode for:"

Registry Location:

```
HKLM\SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache
```

Example:

![image](https://github.com/user-attachments/assets/6dcc230f-ad49-43a3-b891-2056eba92d58)


**AmCache.hve Registry Hive**

Tools:
- Eric Zimmerman AmcacheParser

Stores info about the files that are installed ona system

File Location:

```
c:\windows\AppCompat\Programs\Amcache.hve
```

When using *AmcacheParser* tool, one of the most useful files is the *UnassociatedFileEntries*.

This contains a list of installed applications.

**DAM & DAM Registry Key**

BAM is a Windows service that controls the activity of background applications.

Location:

```
SYSTEM\ControlSet001\Services\bam\State\UserSettings
```

**Prefetch & SuperFetch**

Prefetch is a component of the Memory Manager that can improve the performance of Windows boot process and reduce time it takes for programs to start.

These files can provide info about programs that were frequently ran on the system.

File Path:

```
c:\windows\Prefetch
```

**SRUM (System Resource Usage Monitor)**

Tools:
- https://ericzimmerman.github.io/#!index.md

Tracks system resource usage

File Path Location:

```
c:\windows\system32\sru
```

Before anlaysis we need to check if the *SRUDB.dat* file needs to be repaired:

![image](https://github.com/user-attachments/assets/88ae2847-cee2-4ffc-9874-9f60cee999e2)

Example:

![image](https://github.com/user-attachments/assets/64f86b19-0ab0-416b-a334-3d2514da631c)

**Microsoft Office Alerts**

Event Log File:

```
OAlerts.evtx
```

contains text displayed to users in dialogs by Microsoft Office Suite apps

**Scheduled Tasks**

![image](https://github.com/user-attachments/assets/9dcfdb44-2dc3-4644-b5f3-6298c5f1d331)









## **Lab**

### **Profiling System**

Finding the Build Version:

- Open *Registry Explorer*
- Import Hive *C:\Windows\System32\Config\Software*
- since this is a *dirty hive* we have to load the associated LOG files when prompted
- Navigate to *SOFTWARE\Microsoft\Windows NT\CurrentVersion*

Finding the Computer Name:
- do the same steps above but for the SYSTEM Hive
- Navigate to *SYSTEM\ControlSet001\Control\ComputerName\ComputerName*

Finding System Timezone:
- Navigate to *SYSTEM\ControlSet001\Control\TimeZoneInformation*

Finding Last Shutdown Time:
- Navigate to *SYSTEM\ControlSet001\Control\Windows*
- Right Click the shutdown time
- select *Data Interpreter*

Finding IP Address of System:
- Navigate to *SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces*

### **Network Traffic**

Finding MAC Address of Last Connection:
- Navigate to *SOFTWARE\Micorsoft\Widnows NT\CurrentVersion\NetworkList\Profiles*
- find the record with the latest modify timestamp
- note the domain and find the MAC address in the below location
- Navigate to *SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged*

### **Program Execution**

Finding how long *telegram.exe* ran:
- Navigate to *C:\Users\Administrator\NTUSER.dat*
- Open the *UserAssist* tool and upload the NTUSER.dat file
  - We chose the NTUSER.dat file in the *Administrator* user because we saw this was the user file location that telgram.exe was running from in the *sysmon logs*
 
### **Finding Created User**
- Open RegRipper (rr.exe)
- Upload the SAM Registry Hive (*c:\windows\system32\SAM*)
- Look for last created user account

### **Finding Malicious Service Creation**

- Open *Registry Explorer* and add the following Hive to analyze: *c:\windows\system32\config\SYSTEM*
- Navigate to *SYSTEM\ControlSet001\Services*
- Export the table of services
- Look for Suspicious Service Binary Paths

### **Finding Original FileName**

- Open *NTFS Log Tracker* tool
- Add $LogFile Path --> *c\$LogFile*
- Add $UsnJrnl:$J Path --> *c\$Extend\$J*
- Add $MFT Path --> *c\$MFT*
- Click *Parse*
- Open output .db file in *DB Browser for SQLite* tool
- Go to "Browse Data" --> UsnJrnl
- Filters:
  - FullPath --> *Administrator\\Downloads*
  - Event --> *Renamed*
