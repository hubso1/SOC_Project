# SOC Project 🛡️
> **Open-source SOC** lab environment using tools like **Wazuh, Suricata, TheHive, Cortex, Shuffle and more.** Built for learning, threat detection, log analysis, and incident response.

## 📚 Table of Contents
1. [Project Description](#project-description)
2. [SOC security system architecture diagram](#soc-security-system-architecture-diagram)
3. [System Components Overview](#system-components-overview)
4. [Deployment Overview 🚀](#deployment-overview)
5. [Incident Response 🚨](#incident-response)
6. [Conclusions and Further Development Possibilities](#conclusions-and-further-development-possibilities)

## Project Description

This project aims to build a complete Security Operations Center (SOC) environment using open-source tools, designed to support learning and understanding of key IT security principles. Its main goals are to:

    Demonstrate how to collect and analyze logs from Linux and Windows systems using Wazuh agents

    Enable detection of network threats and anomalies with the Suricata IDS

    Showcase incident management using TheHive and Cortex

    Implement security process automation via Shuffle (SOAR)

    Integrate with external services like VirusTotal and Slack

    Visualize data flow and interaction between components in a modern SOC setup

This project serves an educational purpose, helping users explore the architecture, integration, and operation of tools commonly used in real-world SOC environments. It can be extended further and used as a base for experiments, development, and hands-on practice in threat detection and incident response.

## SOC security system architecture diagram

The following diagram presents the general architecture of a **Security Operations Center (SOC)** environment, encompassing components such as **SIEM, SOAR, DNS, and detection and response systems (IDS/IPS).** The system is built around a central Wazuh server, integrated with automation tools (Shuffle), threat intelligence and analysis (Cortex, VirusTotal), incident management (TheHive), and team communication (Slack). Endpoints (Linux, Windows) and the network are monitored and protected by Wazuh agents and the Suricata IDS. DNS traffic is filtered through a local Technitium DNS server.

<img width="512" height="362" alt="unnamed" src="https://github.com/user-attachments/assets/0b07ca1d-1ecb-4a23-a504-32bba53d4048" />

---

## System Components Overview

### [**Wazuh Server**](https://wazuh.com/)
Central server managing all agents. Responsible for collecting, analyzing, and forwarding logs from endpoints, as well as managing security policies and active responses.

### [**Wazuh Indexer**](https://wazuh.com/) 
Log storage and search component based on OpenSearch. Stores security logs for fast querying and visualization.

### [**Wazuh Dashboard**](https://wazuh.com/)
Web-based visual interface. Allows alert inspection, rule creation, dashboards, and visual analysis.

### [**Wazuh Agent**](https://wazuh.com/)
Lightweight agents installed on endpoints (Linux/Windows) that collect logs, monitor systems, and react to events.

### [**Wazuh Active Response**](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html)
Incident response mechanism capable of blocking IPs during brute-force attacks, stopping malicious processes, restarting services, etc. Can function as a basic EDR with proper configuration.

### [**Shuffle – SOAR**](https://github.com/frikky/Shuffle)
Automation tool that reacts to detected threats (e.g., querying VirusTotal, creating incidents in TheHive, sending alerts to Slack). Uses "workflows" triggered by specific security events.

### [**TheHive**](https://thehive-project.org/)
Security Incident Response Platform (SIRP) for managing, tracking, and analyzing incidents.

### [**Cortex**](https://github.com/TheHive-Project/Cortex)
Analysis engine integrated with TheHive and Shuffle. Provides a wide range of analyzers (e.g., VirusTotal, AbuseIPDB, DNS lookup) for automatic data enrichment.

### [**Suricata**](https://suricata.io/)
Network IDS/IPS monitoring tool that detects port scanning, exploits, and network anomalies. Operates at the packet level.

### [**VirusTotal**](https://www.virustotal.com/)
Online service that scans files and URLs using multiple antivirus engines. Integrated with Cortex and Shuffle for threat analysis.

### [**Slack**](https://slack.com/)
Communication platform used by the security team. Integrated with Shuffle for real-time alerting and notifications.

### [**Technitium DNS Server**](https://technitium.com/dns/)
Internal DNS server deployed to monitor DNS queries. Enables DNS traffic visibility and is integrated with Wazuh for identifying suspicious domain requests.

---

## Deployment Overview

### 1. Installing Wazuh

In this setup, both the Wazuh Server and the Indexer component are installed on the same host. This simplifies configuration and is commonly used in test or small-scale environments.

For larger and production-grade deployments, it is possible to deploy multiple Indexer instances distributed across different hosts. This architecture allows for system scaling, improved performance, and high availability. Such an approach enables efficient management of large volumes of data and better support for distributed environments.

📄 **Installation guide:** [Wazuh Installation Documentation](https://documentation.wazuh.com/current/installation-guide/index.html)

⚠️ If you experience issues accessing the Wazuh Dashboard, ensure that **port 443** is open on your local firewall.
<img width="512" height="97" alt="unnamed" src="https://github.com/user-attachments/assets/c7126730-f275-426a-b43f-edae7e40e668" />

### 2. Installing Wazuh Agents
<img width="512" height="157" alt="unnamed" src="https://github.com/user-attachments/assets/61a8b2b9-9571-423f-92c4-9effb71a5271" />

If any issues occur during agent installation, it's recommended to check the log file: _`/var/ossec/etc/ossec.log`_
<img width="512" height="96" alt="unnamed" src="https://github.com/user-attachments/assets/c53a5e6b-41a1-4700-98b1-9b02b3696558" />

#### 🛠️ Common Issue: Duplicate Hostname

Agent installation may fail if the agent's hostname is identical to the Wazuh manager's hostname. In the Wazuh system, **each agent must have a unique name** to ensure proper registration and communication.

If a name conflict occurs, the system will reject the agent. To resolve this, make sure the agent’s hostname differs from the manager’s hostname.

### 🔌 Agentless Monitoring

Wazuh also supports **agentless monitoring**, which can be useful for devices where installing an agent is not feasible (e.g., firewalls, routers, or remote Linux systems).

Example configuration:
```xml
<agentless>
  <type>ssh_integrity_check_linux</type>
  <frequency>300</frequency>
  <host>root@IP</host>
  <state>periodic_diff</state>
  <arguments>/etc /usr/bin /usr/sbin</arguments>
</agentless>
```
To use agentless monitoring, Wazuh requires an SSH connection from the Wazuh manager to the target endpoint. This method enables log collection and integrity checks without installing a local agent.

### 3. Adding SOCFortress Rules to Wazuh

[SOCFortress](https://github.com/socfortress/Wazuh-Rules) is a community-driven platform offering pre-built and regularly updated security rules and detection scenarios. Integrating SOCFortress rules into Wazuh significantly enhances threat detection capabilities, allowing for:

- Faster identification of advanced attack techniques  
- Broader detection coverage across various systems  
- Improved efficiency of the security operations team  
- Use of tested, community-backed threat signatures

By adding these rules to Wazuh, you extend your environment’s visibility and response capabilities with minimal configuration overhead.
<img width="512" height="206" alt="unnamed" src="https://github.com/user-attachments/assets/31ca5faf-a5de-495a-8cd8-be90d293d13f" />

### 4. Installing Shuffle (SOAR) | Integration with Wazuh

Shuffle is a SOAR (Security Orchestration, Automation, and Response) platform that enables automation and orchestration of security processes. Integrating Shuffle with Wazuh allows for:

- Automatic alert processing  
- Quick remediation actions  
- Coordination of various security tools and systems in one place  

This helps security teams increase incident response efficiency, minimize reaction time, and reduce the risk of human error.

### 🧩 Wazuh Integration with Shuffle

To integrate Wazuh with Shuffle, insert the following snippet into your `/var/ossec/etc/ossec.conf` file:

```xml
<integration>
  <name>shuffle</name>
  <hook_url>API</hook_url>
  <level>6</level>
  <alert_format>json</alert_format>
</integration>
```
🚀 Creating the First Webhook

<img width="512" height="200" alt="unnamed" src="https://github.com/user-attachments/assets/f3b4cdcc-c73f-4e9a-81e7-100b2ff05ef1" />

A webhook is a basic mechanism for receiving data in Shuffle. In the context of Wazuh, it enables:

    Real-time reception of alerts immediately after they are generated

    Triggering Shuffle workflows, such as alert classification or escalation

📚 Source: (https://github.com/Shuffle/Shuffle)

❗ Troubleshooting SSL Certificate Errors

If SSL-related errors occur, you may temporarily disable SSL verification, though this is not recommended for production environments due to the associated security risks.
Example error messages:
Check for SSL-related log entries using:
tail `/var/ossec/etc/ossec.conf | grep SSL`
```syslog
2025/07/04 03:51:21 wazuh-integratord: ERROR: While running shuffle -> integrations. Output: requests.exceptions.SSLError: HTTPSConnectionPool(host='IP', port=3001): Max retries exceeded with url: /api/v1/hooks/API (Caused by SSLError(SSLError(1, '[SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1007)')))
2025/07/04 03:53:08 wazuh-integratord: ERROR: While running shuffle -> integrations. Output: requests.exceptions.SSLError: HTTPSConnectionPool(host='IP', port=3443): Max retries exceeded with url: /api/v1/hooks/<API> (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate (_ssl.c:1007)')))
```

🔧 Disabling SSL Verification in `shuffle.py` (Temporary Workaround)

In the integration script located at `/var/ossec/integrations/shuffle.py`, locate the requests.post function. You can set the verify flag to **False** to bypass SSL verification (not recommended for production).
Example code adjustment:
```python
def send_msg(msg: str, url: str) -> None:
    """Send the message to the API"""
    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
    res = requests.post(url, data=msg, headers=headers, timeout=10, verify=False)
```
⚠️ Warning: This method is not guaranteed to work with all servers, as some enforce strict SSL policies and may reject unsecured connections

### 5. 🗂️ Adding FIM (File Integrity Monitoring) Rules

FIM (File Integrity Monitoring) rules allow you to monitor changes to critical system directories in real time. This helps detect unauthorized modifications to configuration files or binaries, which may indicate a security breach or unwanted activity.

It is recommended to monitor key system paths such as:

- `/etc`
- `/root`
- `/bin`
- `/sbin`

These directories contain sensitive configuration files, user data, and critical system binaries.

To enable file integrity monitoring in Wazuh, add the following entries to the Wazuh Manager configuration file:

**File path:** `/var/ossec/etc/ossec.conf`

```xml
<directories check_all="yes" report_changes="yes" realtime="yes">/etc</directories>
<directories check_all="yes" report_changes="yes" realtime="yes">/root</directories>
<directories check_all="yes" report_changes="yes" realtime="yes">/bin</directories>
<directories check_all="yes" report_changes="yes" realtime="yes">/sbin</directories>
```
These settings activate FIM for the listed directories. The parameters:

    check_all="yes" – inspects all files

    report_changes="yes" – logs content modifications

    realtime="yes" – enables real-time monitoring

With this configuration, Wazuh will immediately detect and report any changes made to the specified directories, helping you quickly identify unauthorized or suspicious activity.

📚 Source: [Wazuh FIM Documentation](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

### 6. 🛡️ Advanced FIM (File Integrity Monitoring) Configuration

To expand the precision and scope of file integrity monitoring, the configuration of the **FIM module** in Wazuh can be extended via the `agent.conf` file. This allows for:

- Monitoring additional critical system files and directories (both Linux and Windows)
- Enabling **real-time monitoring** of changes
- Storing diffs of modified files with `report_changes`
- Using `whodata` to identify the user responsible for a change (requires Auditd or Windows Event Log)

### 🧩 Sample agent.conf Configuration

**File path:** `/var/ossec/etc/shared/default/agent.conf`

```xml
<agent_config>
  <syscheck>
    <disabled>no</disabled>
    <!-- Frequency: every 12 hours -->
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>

    <!-- Linux directories -->
    <directories>/etc,/usr/bin,/usr/sbin</directories>
    <directories>/bin,/sbin,/boot</directories>
    <directories check_all="yes" report_changes="yes" realtime="yes">/bin,/sbin,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes" report_changes="yes" realtime="yes" whodata="yes">/etc/passwd</directories>
    <directories check_all="yes" report_changes="yes" realtime="yes" whodata="yes">/etc/shadow</directories>
    <directories check_all="yes" report_changes="yes" realtime="yes">/etc/resolv.conf</directories>
    <directories check_all="yes" report_changes="yes" realtime="yes">/etc/sudoers</directories>
    <directories check_all="yes" report_changes="yes" realtime="yes">/root/.bash_history</directories>
    <directories check_all="yes" report_changes="yes" realtime="yes">/etc/ssh/</directories>

    <!-- Windows directories -->
    <directories check_all="yes" report_changes="yes" realtime="yes">C:\Windows\Tasks</directories>
    <directories check_all="yes" report_changes="yes" realtime="yes">C:\Windows\System32\drivers\etc\hosts</directories>
    <directories check_all="yes" report_changes="yes" realtime="yes" whodata="yes">C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell</directories>
    <directories check_all="yes" report_changes="yes" realtime="yes">C:\Windows\System32\sysWOW64</directories>
    <directories check_all="yes" report_changes="yes" realtime="yes">C:\Windows\System32\config</directories>
    <directories check_all="yes" report_changes="yes" realtime="yes">C:\Program Files (x86)</directories>
    <directories check_all="yes" report_changes="yes" realtime="yes">C:\ProgramData</directories>

    <!-- Ignored paths -->
    <ignore>c:\program files (x86)\ossec-agent</ignore>
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>

    <!-- Ignore file types -->
    <ignore type="sregex">.log$|.swp$</ignore>

    <!-- Check but do not store diff -->
    <nodiff>/etc/ssl/private.key</nodiff>

    <!-- Skip virtual filesystems -->
    <skip_nfs>yes</skip_nfs>
    <skip_dev>yes</skip_dev>
    <skip_proc>yes</skip_proc>
    <skip_sys>yes</skip_sys>

    <!-- Tuning -->
    <process_priority>10</process_priority>
    <max_eps>50</max_eps>

    <!-- Database synchronization -->
    <synchronization>
      <enabled>yes</enabled>
      <interval>5m</interval>
      <max_eps>10</max_eps>
    </synchronization>
  </syscheck>
</agent_config>
```
This configuration is applied on the Wazuh Manager and is automatically distributed to all agents. It significantly simplifies large-scale FIM deployment across many endpoints.

⚠️ Detecting Execution Permissions on Shell Scripts

Giving execution permission to a script can pose a serious threat if the script contains malicious code (e.g., deleting or modifying critical files). Therefore, this action should be tightly controlled and monitored.

Wazuh has built-in rules to detect permission changes, but you can also create custom FIM rules to fine-tune detection — for example, when execute permission (+x) is added to shell scripts.

🔧 Custom Rule to Detect Execute Bit on Scripts

File path: `/var/ossec/etc/rules/fim_special.xml`

```xml
<group name="syscheck">
  <rule id="100022" level="8">
    <if_sid>550</if_sid>
    <field name="file">.sh$</field>
    <field name="changed_fields">^permission$</field>
    <field name="perm" type="pcre2">\w\wx</field>
    <description>Execute permission added to shell script.</description>
    <mitre>
      <id>T1222.002</id>
    </mitre>
  </rule>
</group>
```

This rule will generate an alert when a .sh file receives execution permission.

Example command to trigger the rule:

```bash
chmod +x script.sh
```

After running this command, the alert will be visible in the Wazuh dashboard.
<img width="512" height="147" alt="unnamed" src="https://github.com/user-attachments/assets/26237bf8-e8c1-4e59-a2af-873914c16f03" />

📚 Source: [Wazuh FIM Documentation](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)

### 7.🧰 Installing and Configuring Suricata IDS/IPS on an Endpoint | Integration with Wazuh

**Suricata** is an open-source IDS/IPS engine capable of real-time traffic analysis and packet inspection. When deployed on an endpoint (Wazuh agent), it acts as a local network monitor for threats. Integration with **Wazuh** enables:

- Centralized collection of Suricata alerts
- Correlation with other security events
- Improved incident visibility and faster response

### ⚙️ Suricata Installation and Basic Setup

After installing Suricata on the endpoint, configure its main YAML configuration file:

**File path:** `/etc/suricata/suricata.yaml`

Be sure to:

- Set the correct **network interface** for packet capture
- Define **home networks** accurately (including internal ranges), but **do not blindly trust internal IPs** — attacks may originate from compromised internal devices

<img width="512" height="263" alt="unnamed" src="https://github.com/user-attachments/assets/5cbcc22a-3f32-4389-b945-0da88dd665d6" />
<img width="512" height="52" alt="unnamed" src="https://github.com/user-attachments/assets/86fb8ff9-d3b0-4193-aa33-47c029dcccd3" />

### 📦 Installing Emerging Threats Ruleset

The [Emerging Threats](https://rules.emergingthreats.net/) ruleset provides Suricata with up-to-date, community-maintained signatures. It enhances detection for:

- Malware communication
- Exploits and known vulnerabilities
- Suspicious or abnormal network behavior

Once installed, ensure your `suricata.yaml` file includes these rules by referencing the correct rule paths and categories.

<img width="512" height="174" alt="unnamed" src="https://github.com/user-attachments/assets/74060f67-12f1-459a-b19c-5ac1116dd8cc" />
<img width="512" height="171" alt="unnamed" src="https://github.com/user-attachments/assets/38bbedd1-72b9-4e48-aea1-946f5d8e0af2" />


### 📡 Integrating Suricata with Wazuh

To forward Suricata alerts to the Wazuh manager, configure the agent to monitor the Suricata JSON log file:

**File path:** `/var/ossec/etc/shared/Suricata/agent.conf`

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

📚 Sources:
    [Wazuh + Suricata Integration Guide](https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html)

### 8. 🦠 Integration with VirusTotal | Automated Malware Detection and Removal | Active Response

Wazuh includes an **Active Response** module that automates reactions to detected security incidents. Although Active Response is not a full EDR/XDR system, it serves as an automatic mechanism enabling security teams to quickly and effectively respond to specific events, simplifying incident management.

### 🔗 VirusTotal Engine Integration with Wazuh

Add the following integration block in the Wazuh manager configuration to connect VirusTotal API:

**File path:** `/var/ossec/etc/ossec.conf`

```xml
<integration>
  <name>virustotal</name>
  <api_key>API_VT</api_key>
  <rule_id>100200,100201</rule_id>
  <alert_format>json</alert_format>
</integration>
```

🛠️ Creating Active Response Script for Automated Malware Removal

Create a script remove-threat.sh to automatically remove malicious files detected on endpoints:

**File path:**  `/var/ossec/active-response/bin/remove-threat.sh`

```bash
#!/bin/bash

LOCAL=`dirname $0`;
cd $LOCAL
cd ../

PWD=`pwd`

read INPUT_JSON
FILENAME=$(echo $INPUT_JSON | jq -r .parameters.alert.data.virustotal.source.file)
COMMAND=$(echo $INPUT_JSON | jq -r .command)
LOG_FILE="${PWD}/../logs/active-responses.log"

#------------------------ Analyze command -------------------------#
if [ ${COMMAND} = "add" ]
then
 # Send control message to execd
 printf '{"version":1,"origin":{"name":"remove-threat","module":"active-response"},"command":"check_keys", "parameters":{"keys":[]}}\n'

 read RESPONSE
 COMMAND2=$(echo $RESPONSE | jq -r .command)
 if [ ${COMMAND2} != "continue" ]
 then
  echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Remove threat active response aborted" >> ${LOG_FILE}
  exit 0;
 fi
fi

# Removing file
rm -f $FILENAME
if [ $? -eq 0 ]; then
 echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Successfully removed threat" >> ${LOG_FILE}
else
 echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Error removing threat" >> ${LOG_FILE}
fi

exit 0;
```

The script reads JSON data containing threat information, including the path to the malicious file. It verifies action permissions via communication with the Wazuh execd daemon, then attempts to delete the specified file and logs success or failure. This ensures a fast and effective automated incident response.

📋 Local Rules for Alerting and Automated File Removal
Configure local rules to detect suspicious changes in critical directories and trigger automatic malware removal alerts:
**File path:**  `var/ossec/etc/rules/local_rules.xml`

```xml
<group name="syscheck,pci_dss_11.5,nist_800_53_SI.7,">
    <!-- Rules for Linux systems -->
    <rule id="100200" level="7">
        <if_sid>550</if_sid>
        <field name="file">/root</field>
        <description>File modified in /root directory.</description>
    </rule>
    <rule id="100201" level="7">
        <if_sid>554</if_sid>
        <field name="file">/root</field>
        <description>File added to /root directory.</description>
    </rule>
</group>

<group name="virustotal,">
  <rule id="100092" level="12">
    <if_sid>657</if_sid>
    <match>Successfully removed threat</match>
    <description>$(parameters.program) removed threat located at $(parameters.alert.data.virustotal.source.file)</description>
  </rule>

  <rule id="100093" level="12">
    <if_sid>657</if_sid>
    <match>Error removing threat</match>
    <description>Error removing threat located at $(parameters.alert.data.virustotal.source.file)</description>
  </rule>
</group>
```

Thanks to these local rules, the Wazuh system can detect suspicious changes in critical directories and also automatically respond to detected threats, informing the administrator about the success or issues encountered during the malware removal process.

The following configuration enables the Active Response mechanism on the Wazuh server. It defines the remove-threat command, which executes the **remove-threat.sh** script in response to the detection of a specific event (rule with ID 87105):
**File path:**  `var/ossec/etc/ossec.conf`

```xml
  <command>
    <name>remove-threat</name>
    <executable>remove-threat.sh</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <active-response>
    <disabled>no</disabled>
    <command>remove-threat</command>
    <location>local</location>
    <rules_id>87105</rules_id>
  </active-response>
```
#### Operation of Active Response and automatic malicious file removal:
  
  Downloading the malicious file:

<img width="512" height="59" alt="unnamed" src="https://github.com/user-attachments/assets/96ed418e-3239-4623-b031-b36ce3811ce7" />

<img width="1056" height="138" alt="obraz" src="https://github.com/user-attachments/assets/6d30f5f6-408e-4203-8653-93c674e37e36" />

<img width="512" height="91" alt="unnamed" src="https://github.com/user-attachments/assets/290a31d6-64fb-4b72-878a-0375df9a2ed0" />

### 9. 🔥 Active Response — Blocking Malicious Hosts via Firewall

Wazuh includes a set of built-in scripts used for Active Response. These scripts are located in the following directory on Linux/Unix endpoints:
**File path:** `/var/ossec/active-response/bin/`

The firewall-drop active response script is available by default on Linux/Unix systems. It uses iptables to block malicious IP addresses.

To enable automatic IP blocking, add the following configuration to the Wazuh manager:

**File path:** `/var/ossec/etc/ossec.conf`

```xml
<command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>
  
  <active-response>
    <disabled>no</disabled>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>5763,100004,100299</rules_id>
    <timeout>60</timeout>
  </active-response>
```
📌 The configuration above means that when one of the specified rules (e.g., 100299) is triggered, the system will locally block the source IP for 60 seconds on the machine where the alert originated.

🚫 Operation of firewall-drop (Active Response)

Example use case: Blocking a host for 60 seconds when port scanning is detected.
🛡️ Custom Active Response Rule Based on Suricata Alert

Create a custom rule that triggers the firewall block based on Suricata detection:

**File path:** `/var/ossec/etc/rules/local_rules.xml`

```xml
<group name="custom_active_response_rules,">
  <rule id="100299" level="12" ignore="10" frequency="2" timeframe="20">
    <if_sid>100003</if_sid>
    <description>PORT Scanning detected!</description>
    <mitre>
      <id>T1595</id>
    </mitre>
  </rule>
</group>
```
🔍 This rule detects repeated events (frequency="2" within 20 seconds) originating from rule 100003 (e.g., a Suricata port scanning alert) and raises the alert level to 12. Once the condition is met, the appropriate response action is triggered.

📉 Outcome

<img width="512" height="150" alt="unnamed" src="https://github.com/user-attachments/assets/56400781-2848-4137-a2a5-1f9be1f1b62f" />

<img width="791" height="100" alt="obraz" src="https://github.com/user-attachments/assets/ac8a90a2-0380-4461-b4a1-21f2588e30c1" />

When the scan is initiated from a malicious host and the rule is triggered:

    The attacker’s IP address is blocked using iptables for 60 seconds.

    Communication between the attacker and the target system is interrupted.

    A corresponding alert appears in the Wazuh dashboard.

    Logs confirm execution of the firewall-drop Active Response.

📴 No network connectivity remains between the source and destination host during the blocking period.

<img width="512" height="130" alt="unnamed" src="https://github.com/user-attachments/assets/76c6c030-5fd2-461e-b5ad-610d84bb52b9" />


### 10. 📢 Integration of Wazuh with Slack for Real-Time Alerting

Slack has been integrated as a communication channel for the security team to ensure real-time delivery of critical security notifications. Using the SOAR platform Shuffle, it is possible to automatically forward alerts from Wazuh directly to a designated Slack channel.

    💬 Slack is a modern communication platform that enables teams to exchange information in real time, integrate with external tools, and respond to incidents quickly and efficiently.

🔗 Slack Integration with Wazuh

To enable Slack alerting, add the following integration block to the Wazuh manager configuration:

File path: `/var/ossec/etc/ossec.conf`

```xml
<integration>
  <name>slack</name>
  <hook_url>https://hooks.slack.com/services/API</hook_url>
  <rule_id>100092,5763,100210,100299</rule_id>
  <alert_format>json</alert_format>
</integration>
```

This configuration allows Wazuh to send JSON-formatted alerts to the specified Slack webhook URL whenever any of the listed rules (e.g., 100092, 100299) are triggered.
Example Alerts on Slack Channel

<img width="512" height="127" alt="unnamed" src="https://github.com/user-attachments/assets/1283a503-10ac-4547-ba66-fc117938fe18" />
<img width="512" height="182" alt="unnamed" src="https://github.com/user-attachments/assets/c12b6220-d546-436a-8af1-8217599897ee" />

🔗 Source:
[Wazuh Documentation — Integration with External APIs](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)

### 11. Installation and Configuration of TheHive and Cortex | Integration with Shuffle for Alert Management

**Installation Guide:**  
https://github.com/StrangeBeeCorp/docker

#### 🐝 TheHive – Incident Response Platform (IRP)

TheHive is a powerful IRP designed for managing cybersecurity incidents. It allows you to:

- Collect alerts from multiple sources (e.g., Wazuh via Shuffle),
- Automatically create and classify incidents (alerts and cases),
- Manage incident lifecycle following SOC procedures.

**In this project:**

- Only `High` and `Medium` severity alerts are forwarded to TheHive (e.g., malware detection, port scans, suspicious logins).
- Only `High` severity alerts are automatically escalated to full **cases**, requiring manual analysis by SOC analysts.
- This setup enables initial classification and helps reduce **false positives**, improving alert triage efficiency.

<img width="512" height="338" alt="unnamed" src="https://github.com/user-attachments/assets/e5d4cacb-097e-4102-844e-27e150074d0e" />

#### Example JSON Alert Payload (advanced setup)

Due to an initial issue with incorrect JSON formatting, manual construction of the alert payload according to TheHive API documentation was required. This resolved alert creation issues.

<img width="512" height="299" alt="unnamed" src="https://github.com/user-attachments/assets/12be63c0-14de-4790-bd66-75e29eaf28fd" />

<img width="512" height="153" alt="unnamed" src="https://github.com/user-attachments/assets/641f6c25-7c3d-4733-88f5-be08186dd2f8" />

```json
{
  "description": " $exec.title |  
Agent: $exec.all_fields.agent.ip, $exec.all_fields.agent.id, $exec.all_fields.agent.name
MITRE: $exec.all_fields.data.parameters.alert.rule.mitre.id | $exec.all_fields.data.parameters.alert.rule.mitre.tactic |  $exec.all_fields.data.parameters.alert.rule.mitre.technique",
  "externallink": "",
  "pap": 2,
  "severity": $exec.severity,
  "source": "Wazuh",
  "sourceRef": "Rule: $exec.all_fields.rule.id ",
  "status": "New",
  "summary": " $exec.all_fields.rule.description TIME:  $exec.timestamp  ",
  "tags": ["  $exec.id,$exec.all_fields.agent.ip "],
  "title": " $exec.title ",
  "tlp": 2,
  "type": "Internal"
}
```
Example Alert Visualization in TheHive

    High severity alerts, escalated as cases, are visible within the TheHive dashboard for review and tracking.

<img width="512" height="63" alt="unnamed" src="https://github.com/user-attachments/assets/2fe50a63-c740-4951-b5ad-ba1a403c1566" />

<img width="512" height="185" alt="unnamed" src="https://github.com/user-attachments/assets/9c09e53d-271e-40a1-aaab-0a51511d9f0e" />

<img width="512" height="71" alt="unnamed" src="https://github.com/user-attachments/assets/b849f33b-5f82-4191-b50d-fe480ce4a4cc" />

<img width="512" height="95" alt="unnamed" src="https://github.com/user-attachments/assets/d939da2e-3897-4501-a4f5-f1d9f451da49" />

<img width="512" height="92" alt="unnamed" src="https://github.com/user-attachments/assets/c71481e6-b3b5-4724-b315-38a6fafe4eac" />


#### 🧠 Cortex – Threat Analysis Engine

Cortex is an analytical engine that integrates seamlessly with TheHive and Shuffle. It provides automatic enrichment of incident data using analyzers.

In this project:

    Cortex uses analyzers such as VirusTotal to scan IPs, file hashes, and URLs received from TheHive or Shuffle.

    It accelerates threat enrichment and supports decision-making for alert escalation.

<img width="512" height="200" alt="unnamed" src="https://github.com/user-attachments/assets/e3b31623-7ec2-4165-812e-0c4081263212" />


Created Cortex Analyzers (used in this project):

    VirusTotal – IP Scan

    VirusTotal – File Hash Lookup

    VirusTotal – URL Scan

<img width="512" height="303" alt="unnamed" src="https://github.com/user-attachments/assets/ac32b77f-7e37-45b3-b216-9dd3333f1ad9" />

These analyzers help provide real-time risk context for each indicator involved in an alert.
Automated Workflow with Shuffle

Thanks to the advanced workflow design in Shuffle, high-severity alerts automatically trigger:

    IP, file, and URL analysis via Cortex analyzers (e.g., VirusTotal),

    Retrieval of scan results,

    Push-back of enriched data into TheHive.

<img width="274" height="512" alt="unnamed" src="https://github.com/user-attachments/assets/7ce37d6b-f29d-489a-bbe2-500b98a38c29" />


<img width="512" height="142" alt="unnamed" src="https://github.com/user-attachments/assets/d57c7a2a-b7ac-404e-b973-7c887078e582" />


This results in:

    Faster analyst decision-making,

    Improved visibility into potential threats,

    Efficient SOC operations.

⚠️ Important:

If Docker containers for TheHive or Cortex fail to start, ensure correct permissions are applied to volumes and configuration files.
<img width="512" height="153" alt="unnamed" src="https://github.com/user-attachments/assets/573d81db-ddfb-4022-866c-f129cf5ede2d" />
```bash
sudo chown -R 1000:1000 docker/.../elasticsearch/
```

### 12. 🔁  Workflow Enhancement in Shuffle

As part of the **Shuffle Workflow** development, several advanced conditions were implemented to control the flow of information during the automation process. These conditions are based on:

- Regular Expression (Regex) matching  
- Analysis of detection rules generated by **Wazuh**

This makes it possible to dynamically route alerts, filter events, and take different actions based on the content of the alert, its origin, or threat level. Such an approach enables **precise automation** and better adaptation of response actions to the nature of the incident.

#### 🧩 Workflow Overview

<img width="512" height="219" alt="unnamed" src="https://github.com/user-attachments/assets/9e14e93d-5c64-4814-ab96-7285e4dde87d" />


One important element of the automation is the branch responsible for handling **FIM (File Integrity Monitoring)** alerts generated by Wazuh. To reduce noise, a Regex-based condition is used:

```regex
^(553|554|550|100200|100201)$
```

<img width="512" height="174" alt="unnamed" src="https://github.com/user-attachments/assets/bed29a62-58aa-4640-9b75-670f8e3e61cd" />

This condition filters alerts based on the `rule.id` field. Only alerts matching the listed IDs (related to critical file modifications) are passed to **TheHive** for alert creation.

##### Benefits:
- 🎯 Accurate filtering of FIM events (e.g., `/etc`, `/bin`)
- ⚠️ Reduced number of false positives
- 🚀 Better scalability and responsiveness of the Shuffle platform


#### 🟠 Severity-Based Alert Handling in Shuffle

<img width="337" height="395" alt="unnamed" src="https://github.com/user-attachments/assets/7ce52f27-ae72-4e4b-8bec-0b17ea965fb3" />


Alerts are routed and handled differently depending on their severity level:

| Severity Level     | Action                                                                 |
|--------------------|------------------------------------------------------------------------|
| 🔴 **High (≥12)**     | Automatically forwarded to TheHive as **Cases**. Email notifications are sent to the SOC team. |
| 🟡 **Medium (7–11)**  | Sent to TheHive as **Alerts**, but not escalated to Cases automatically. |
| ⚪ **Low (<7)**        | Not sent to Shuffle. Handled locally via the **Wazuh Dashboard** to avoid log flooding. |


#### 🛡️ File Integrity Monitoring (FIM) Alerts

These alerts form a separate branch in the Shuffle workflow. They are treated as **medium severity** and are used to report changes in critical directories on monitored agents — e.g., `/etc`, `/bin`.

Example alert:

<img width="512" height="222" alt="unnamed" src="https://github.com/user-attachments/assets/2f0d9750-fee8-41b6-be83-000ff1b74676" />

These alerts are forwarded to **TheHive** for review and correlation.

#### ✉️ Automatic Email Notifications for High Alerts

When a **High severity** alert (severity ≥ 12) is detected, Shuffle performs the following actions:

- Sends the alert to **TheHive** where a new **Case** is automatically created
- Sends an email notification to the designated SOC team or analyst

This process increases awareness and allows the team to act quickly.

<img width="512" height="443" alt="unnamed" src="https://github.com/user-attachments/assets/fed00b6b-0d73-4e48-b9c8-b34c22c40705" />

```
Thanks to this automation design, high-level alerts are not only visible in dashboards, but also actively escalated through:

    🛡️ Wazuh

    🔁 Shuffle

    🧠 Cortex

    🐝 TheHive

    📬 Email notifications to the SOC team

This ensures faster response, better alert triage, and higher efficiency in incident handling.
```

### 13. Installation and Configuration of Local DNS Server | Integration with Wazuh

#### Technitium DNS Server – Overview and Use Case

[Technitium DNS Server](https://technitium.com/dns/) is an open-source DNS server that can function both as a **recursive** and **authoritative** DNS resolver. It is easy to set up, works out of the box, and provides a user-friendly web interface.

By default, most systems use DNS provided by ISPs, which allows them to:

- Track visited domains
- Manipulate traffic (e.g., blocking, redirecting, or injecting content)

Technitium DNS mitigates these issues by supporting encrypted DNS protocols like **DNS-over-TLS** and **DNS-over-HTTPS**, enhancing both privacy and control.


#### 🔒 Why deploy a local DNS server and integrate it with Wazuh?

- **Privacy & Security**: Avoids external DNS control (e.g., ISP), ensuring local management of DNS traffic.
- **DNS visibility and analysis**: Integration with Wazuh enables real-time monitoring and anomaly detection.
- **Early threat detection**: Malware often relies on DNS (e.g., beaconing, phishing), and DNS logs help identify such behaviors.
- **Centralized logging and inspection**: DNS logs are forwarded to Wazuh for correlation with other sources (agents, Suricata, EDR).


#### 🛠️ DNS Server Installation

Installation guide:  
👉 [https://technitium.com/dns/](https://technitium.com/dns/)

#### 🔗 Integration with Wazuh

##### Add custom rules to `local_rules.xml`:

```xml
<group name="technitium_dns, dns, custom">
    <rule id="100301" level="3">
        <decoded_as>json</decoded_as>
        <field name="dns.type">dns</field>
        <description>Technitium DNS logs grouped.</description>
    </rule>

    <rule id="100302" level="3">
        <if_sid>100301</if_sid>
        <field name="dns.responseType" negate="yes">Blocked</field>
        <description>Technitium DNS: Allowed</description>
    </rule>

    <rule id="100303" level="3">
        <if_sid>100301</if_sid>
        <field name="dns.responseType">Blocked</field>
        <description>Technitium DNS: Blocked</description>
    </rule>

    <rule id="100304" level="12" frequency="10" timeframe="30">
        <if_matched_sid>100303</if_matched_sid>
        <same_srcip/>
        <description>Technitium DNS: Multiple DNS requests blocked from same IP.</description>
    </rule>
    
    <rule id="100305" level="12" frequency="5" timeframe="120">
        <if_matched_sid>100302</if_matched_sid>
        <same_srcip/>
        <field name="dns.question.questionName" type="pcre2">[\w\.]{30,}</field>
        <description>Technitium DNS: Possible exfil (multiple long queries)</description>
    </rule>

    <rule id="100306" level="12" frequency="5" timeframe="120">
        <if_matched_sid>100302</if_matched_sid>
        <same_srcip/>
        <field name="dns.question.questionName" type="pcre2">^(?:[A-Za-z0-9+]{4})+(?:[A-Za-z0-9+]{2}==|[A-Za-z0-9+]{3}=)?$</field>
        <description>Technitium DNS: Possible exfil (base64 encoded query)</description>
    </rule>

    <rule id="100307" level="12" frequency="5" timeframe="120">
        <if_matched_sid>100302</if_matched_sid>
        <same_srcip/>
        <field name="dns.question.questionName" type="pcre2">^(?:[A-Z2-7]{8})+(?:[A-Z2-7]{2}======|[A-Z2-7]{4}====|[A-Z2-7]{5}===|[A-Z2-7]{7}=)?$</field>
        <description>Technitium DNS: Possible exfil (base32 encoded query)</description>
    </rule>

    <rule id="100308" level="15" frequency="5" timeframe="150" ignore="60">
        <if_matched_sid>100304</if_matched_sid>
        <same_srcip/>
        <description>Technitium DNS: Multiple DNS requests blocked from same IP.</description>
        <description>The events are too high, therefore to be ignored 60 seconds to prevent issues</description>
    </rule>

    <rule id="100309" level="12">
        <if_sid>100302</if_sid>
        <list field="dns.question.questionName" lookup="match_key">etc/lists/warning_list</list>
        <description>Technitium DNS: Malicious domain is allowed. Check blocking configuration.</description>
    </rule>
</group>
```

Config file path: `/var/ossec/etc/rules/local_rules.xml`

🧾 Log export in JSON format

Example configuration for the built-in Log Exporter in Technitium:

```json
{
  "maxQueueSize": 1000000,
  "file": {
    "path": "/var/log/dns/dns_logs.json",
    "enabled": true
  }
}
```

#### 🧩 Wazuh Agent: Enable DNS log collection

Ensure the same path as used in the Log Exporter is referenced in `ossec.conf`:

```xml
<localfile>
   <log_format>json</log_format>
   <only-future-events>no</only-future-events>
   <location>/var/log/dns/dns_logs.json</location>
   <out_format>{"dns": $(log) }</out_format>
   <label key="type">dns</label> 
</localfile>
```

File path: `/var/ossec/etc/ossec.conf`

Blocking Suspicious and Malicious Domains:

<img width="512" height="202" alt="unnamed" src="https://github.com/user-attachments/assets/0ddc7790-a2c7-4244-8886-27b25a9a3599" />

Technitium DNS enables fast blocking of known malicious domains via various public and custom blacklists.

Result:

<img width="512" height="184" alt="unnamed" src="https://github.com/user-attachments/assets/1ef548fa-cb95-4360-8b17-9f1a3c41b7bc" />

<img width="512" height="124" alt="unnamed" src="https://github.com/user-attachments/assets/ab4361cf-ba9a-4deb-8f74-f63df4c37238" />

<img width="512" height="504" alt="unnamed" src="https://github.com/user-attachments/assets/ec48540b-f3e0-4aed-a202-5d29add86636" />


To apply the DNS server system-wide, configure it in: `/etc/resolv.conf`

```bash
nameserver <DNS_IP-ADDRESS>
```

📊 Creating DNS Dashboard in Wazuh

Thanks to this integration, a custom Local DNS Dashboard can be built in Wazuh to visualize and analyze DNS activity across the network.

<img width="512" height="283" alt="unnamed" src="https://github.com/user-attachments/assets/176f92d1-5ff2-489b-bc0d-a6ab48ca7f3e" />


📌 Reference:
https://zaferbalkan.com/technitium/

✅ Final Result

A configured local DNS server:

    Blocks access to blacklisted domains

    Exports enriched DNS logs

    Sends data to Wazuh for advanced correlation and alerting

### Incident Detection with Auditd and Wazuh

**Auditd** is a native Linux auditing tool used to track system activity and user behavior. In this use case, we leverage Auditd on an Ubuntu endpoint to monitor and alert on the execution of suspicious commands by privileged users.

🎯 Objective

Track and respond to malicious command execution on Linux endpoints. This includes logging all executed commands by privileged users (e.g., sudo, root) and triggering alerts for high-risk actions using custom rules and Wazuh’s lookup capabilities.

🧩 Step-by-step Setup

Add audit rules to track command execution path: `/etc/audit/audit.rules`:

```bash
echo "-a exit,always -F auid=1000 -F egid!=994 -F auid!=-1 -F arch=b32 -S execve -k audit-wazuh-c" >> /etc/audit/audit.rules
echo "-a exit,always -F auid=1000 -F egid!=994 -F auid!=-1 -F arch=b64 -S execve -k audit-wazuh-c" >> /etc/audit/audit.rules
```
Configure the Wazuh agent to read Auditd logs:

File path: `/var/ossec/etc/ossec.conf`

```xml
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

Create a CDB list `/var/ossec/etc/lists/suspicious-programs` with potentially dangerous commands:

```bash
ncat:yellow
nc:red
tcpdump:orange
```

Add the list to the Wazuh manager configuration (`/var/ossec/etc/ossec.conf`):

```xml
<list>etc/lists/suspicious-programs</list>
```

Then define a custom rule in `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="audit">
  <rule id="100210" level="12">
    <if_sid>80792</if_sid>
    <list field="audit.command" lookup="match_key_value" check_value="red">etc/lists/suspicious-programs</list>
    <description>Audit: Highly Suspicious Command executed: $(audit.exe)</description>
    <group>audit_command,</group>
  </rule>
</group>
```

🔍 Monitoring File Downloads via wget + Incident Enrichment Pipeline

To improve detection capabilities for suspicious file downloads, a custom Wazuh rule was created to monitor the use of the wget command. This rule helps identify when users attempt to download files or connect to external domains directly from the command line.

Custom rule defined in `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="audit">
  <rule id="100010" level="8">
    <if_sid>80700</if_sid>
    <match>wget</match>
    <description>Command WGET executed by user! - $(audit.exe) - $(audit.execve.a1)</description>
    <group>wget_usage</group>
  </rule>
</group>
```

🔁 Automation and Threat Enrichment Workflow

When the above rule is triggered (e.g., wget is used to fetch a file), Wazuh generates an alert. This alert is forwarded to Shuffle (SOAR) where an automated workflow processes the incident:

    URL & Domain Extraction: The command line argument (audit.execve.a1) is parsed to extract the download URL or domain.

    Threat Intelligence Lookup: The extracted indicators are automatically sent to Cortex for enrichment using analyzers like:

        VirusTotal

        URLScan

    Case Creation in TheHive: The enriched alert is converted into a case in TheHive, including:

        Original command and user details

        Threat intelligence results

        Severity based on the reputation of the downloaded content

This setup enables near real-time response and deeper context for analysts, all built using open-source tooling.

🧪 Attack Emulation

To test detection:

<img width="647" height="82" alt="obraz" src="https://github.com/user-attachments/assets/5e0c1181-629b-4e78-80fe-134b910acceb" />

<img width="1086" height="146" alt="obraz" src="https://github.com/user-attachments/assets/07a5ba31-c1b2-4535-8db5-fa07e4a44090" />


This should trigger a high-severity alert due to the presence of nc in the suspicious-programs list with severity level "red".

---

## Incident Response

This section demonstrates how the SOC environment responds to real-world security incidents by leveraging the full integration between Wazuh, Suricata, TheHive, Cortex, and Shuffle.

Incident response workflows are triggered automatically based on alert severity, rule matching, or correlation logic. Each response may include:

- Alert enrichment using Cortex analyzers (e.g. VirusTotal, AbuseIPDB)
- Case creation in TheHive with detailed observable data
- Automatic tagging and classification (e.g. MITRE ATT&CK mapping)
- Active Response actions (e.g. blocking IP, isolating host)
- Email/Slack notifications for critical incidents
- Timeline tracking and analyst collaboration

### 🔍 Example Scenarios:

#### Use Case #2 – Suspicious File Download

**🎯 Objective:**  
Evaluate the SIEM system's capability to detect and respond to suspicious file downloads. The goal is to determine whether the environment can successfully identify potential threats from unknown or malicious sources.

**🧪 Environment Setup:**
- **Endpoint Agent:** Ubuntu Server 24.04
- **SIEM:** Wazuh
- **Wazuh Rules:** `10092` (Level 12), `87105` (Level 12)

### 🔁 Incident Flow:

<img width="512" height="78" alt="unnamed" src="https://github.com/user-attachments/assets/fa04ba88-d79e-4cc9-a0ce-3b17e133f8ad" />

1. A user downloads a suspicious file using the `curl` command.
2. The download starts immediately, and the file is saved in the current working directory.
3. Once the download is complete, Wazuh detects the activity via local rules.
4. Alerts are generated with `rule.id: 87105` and `rule.id: 10092`.
5. Wazuh triggers **Active Response**, invoking a script to delete the file.
6. The incident is enriched with VirusTotal data and logged.


### ⚠️ Detection Mechanism

Wazuh generated:
- `rule.id: 87105` – triggered on suspicious download behavior.

<img width="512" height="96" alt="unnamed" src="https://github.com/user-attachments/assets/97c55ec0-1586-497d-a909-4cdee278be05" />


- `rule.id: 10092` – triggered by VirusTotal detection indicating a malicious file.

Wazuh's integration with VirusTotal enables automated analysis of downloaded files using multi-engine reputation scoring, enhancing detection accuracy.

<img width="512" height="62" alt="unnamed" src="https://github.com/user-attachments/assets/c9a85405-a4b0-4ce4-9677-452118fb453c" />

<img width="512" height="344" alt="unnamed" src="https://github.com/user-attachments/assets/89d6b5d8-2afb-435e-9bdf-4d32a3ae2157" />

### 🔐 Response Actions

**Local Rules (`local_rules.xml`):**  
Custom rules were created to automate the response process based on the above alert IDs. Once triggered, they invoke an **Active Response script** to handle the threat.

Active Response Script:
A script named `remove-threat.sh` is automatically executed when the alert is detected. It performs the following:

    Extracts the file hash and path.

    Queries VirusTotal for threat classification.

    If confirmed malicious → deletes the file.

📄 Path: `/var/ossec/active-response/bin/remove-threat.sh`
🚨 Alerting & Automation

    Alerts are pushed to Wazuh Dashboards for visibility.

    VirusTotal data is attached to the event.

    Slack or email notifications (optional) can be triggered.

    All actions are logged for audit and compliance.

<img width="512" height="84" alt="unnamed" src="https://github.com/user-attachments/assets/5ad74afd-44d7-485b-96a0-df58d9f1b4a6" />

<img width="512" height="169" alt="unnamed" src="https://github.com/user-attachments/assets/18d97d43-36bc-479f-b782-17bbd42c687e" />

<img width="512" height="297" alt="unnamed" src="https://github.com/user-attachments/assets/25b009fa-84f6-4f45-9f8a-5f63ea00daf4" />


- **Suspicious DNS Activity**  
  Technitium DNS logs show multiple blocked DNS queries to suspicious domains. Alerts are aggregated in Wazuh and correlated with known threat indicators. An incident is opened in TheHive and a case analyst is assigned automatically.

- **Port Scanning Detected by Suricata**  
  Suricata IDS detects Nmap-style scanning from a remote IP. The IP is added to a blocklist via Active Response and an alert is sent to Slack with details.

> Screenshots and workflow diagrams will be included below for each case.


---

## Conclusions and Further Development Possibilities

### ✅ Conclusions

The project of building a **Security Operations Center (SOC)** using open-source tools such as **Wazuh**, **Suricata**, **Shuffle**, **TheHive**, **Cortex**, **Technitium DNS**, and external services like **VirusTotal** or **Slack** demonstrates that it is possible to build a **fully functional detection, analysis, and response system** without the need for expensive, commercial solutions.

The implemented SOC environment is capable of:

- Collecting, correlating, and analyzing logs from Windows and Linux agents  
- Detecting anomalies and network attacks using **Suricata (IDS)**  
- Automatically responding to threats (e.g., blocking IPs via **Active Response**)  
- Managing and analyzing incidents using **TheHive** and **Cortex**  
- Automating actions via **SOAR platform (Shuffle)**  
- Integrating with **Threat Intelligence services** like VirusTotal, AbuseIPDB  
- Visualizing data based on **MITRE ATT&CK**  
- Providing ready-to-use dashboards for **PCI DSS**, **GDPR**, **HIPAA**, **NIST 800-53**  

This project shows that **open-source tools are fully functional and integrable** into a cohesive IT security environment.  
However, deploying such a system **requires time, technical knowledge**, and a clear understanding of architecture and data flow between components.

A central role in this setup is played by **Wazuh**, which acts as the core monitoring and response engine.  
It is a **flexible and powerful solution** that can be extended with custom integrations, rules, dashboards, and **Active Response** scenarios.  
Wazuh is well-suited to serve as a **central SIEM/EDR/Compliance platform** in environments of varying complexity.

---

### 🚀 Further Development Opportunities

#### 🔭 Expand Detection & Visibility

- Add more sensors like **Zeek**, **Sysmon**, or **OSQuery**  
- Increase endpoint telemetry and detection coverage  

#### 🧠 Threat Intelligence Integration

- Integrate **MISP** platform and connect to external **IOC feeds**  
- Automatically enrich alerts with external context (IP reputation, domains, malware hashes)  

#### 🧪 Simulation & Attack Testing

- Implement **attack simulations**, purple teaming, and detection validation via adversary emulation  

#### ⚙️ Advanced Automation

- Build complex workflows in **Shuffle** to automate escalation, tagging, response, and reporting  
- Integrate with **ITSM platforms**, email systems, **Active Directory**, or **SIEM** tools  

#### 📋 Audit & Compliance

- Create custom **audit dashboards** tailored to organizational requirements  
- Generate **scheduled reports** directly from dashboards or **Cortex**  

#### 🛡️ SOC Hardening

- Secure components and agents (TLS encryption, **RBAC roles**, access control, file integrity monitoring)  
- Implement **traffic segmentation**, honeypots, and isolate critical services  

---

