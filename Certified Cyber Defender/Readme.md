# **CCD Notes**

## Table Of Contents:
<!--ts-->
  * [Suricata](#suricata)
  * [Rita](#rita)
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
