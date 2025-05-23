# **CCD Notes**

## Table Of Contents:
<!--ts-->
  * [Suricata](#suricata)
  * [Rita](#rita)
  * [Sysmon](#sysmon)
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
