# **CCD Notes**

## Table Of Contents:
<!--ts-->
  * [Suricata](#suricata)
  * [Rita](#rita)
<!--te-->
# **Given Creden

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
