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

Tool Overview:

![image](https://github.com/user-attachments/assets/f6d6983e-cbeb-4bcb-9ce7-d9a6c85803ce)


