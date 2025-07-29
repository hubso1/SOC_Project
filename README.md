# SOC Project 🛡️
> **Open-source SOC** lab environment using tools like **Wazuh, Suricata, TheHive, Cortex, Shuffle and more.** Built for learning, threat detection, log analysis, and incident response.

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

The following diagram presents the general architecture of a Security Operations Center (SOC) environment, encompassing components such as SIEM, SOAR, DNS, and detection and response systems (IDS/IPS). The system is built around a central Wazuh server, integrated with automation tools (Shuffle), threat intelligence and analysis (Cortex, VirusTotal), incident management (TheHive), and team communication (Slack). Endpoints (Linux, Windows) and the network are monitored and protected by Wazuh agents and the Suricata IDS. DNS traffic is filtered through a local Technitium DNS server.

<img width="512" height="362" alt="unnamed" src="https://github.com/user-attachments/assets/0b07ca1d-1ecb-4a23-a504-32bba53d4048" />

---

## 📦 System Components Overview

### [**Wazuh Server**](https://wazuh.com/)
Central server managing all agents. Responsible for collecting, analyzing, and forwarding logs from endpoints, as well as managing security policies and active responses.

### [**Wazuh Indexer**](https://wazuh.com/)
Log storage and search component based on OpenSearch. Stores security logs for fast querying and visualization.

### [**Wazuh Dashboard**](https://wazuh.com/)
Web-based visual interface (Wazuh UI/Kibana). Allows alert inspection, rule creation, dashboards, and visual analysis.

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

## 🚀 Deployment Overview

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
tail `/var/ossec/etc/ossec.conf` | grep SSL
```syslog
2025/07/04 03:51:21 wazuh-integratord: ERROR: While running shuffle -> integrations. Output: requests.exceptions.SSLError: HTTPSConnectionPool(host='IP', port=3001): Max retries exceeded with url: /api/v1/hooks/API (Caused by SSLError(SSLError(1, '[SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1007)')))
2025/07/04 03:53:08 wazuh-integratord: ERROR: While running shuffle -> integrations. Output: requests.exceptions.SSLError: HTTPSConnectionPool(host='IP', port=3443): Max retries exceeded with url: /api/v1/hooks/<API> (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate (_ssl.c:1007)')))
```

🔧 Disabling SSL Verification in shuffle.py (Temporary Workaround)

In the integration script located at /var/ossec/integrations/shuffle.py, locate the requests.post function. You can set the verify flag to **False** to bypass SSL verification (not recommended for production).
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

File path: /var/ossec/etc/rules/fim_special.xml

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
### Operation of Active Response and automatic malicious file removal:
  
  Downloading the malicious file:

<img width="512" height="59" alt="unnamed" src="https://github.com/user-attachments/assets/96ed418e-3239-4623-b031-b36ce3811ce7" />
<img width="512" height="67" alt="unnamed" src="https://github.com/user-attachments/assets/1443fc0e-e18c-441b-8b05-d98145cb0d32" />
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
<img width="512" height="150" alt="unnamed" src="https://github.com/user-attachments/assets/fa64ffe4-520d-45cb-8074-f34d39ebd71d" />

When the scan is initiated from a malicious host and the rule is triggered:

    The attacker’s IP address is blocked using iptables for 60 seconds.

    Communication between the attacker and the target system is interrupted.

    A corresponding alert appears in the Wazuh dashboard.

    Logs confirm execution of the firewall-drop Active Response.

📴 No network connectivity remains between the source and destination host during the blocking period.

### 10. 📢 Integration of Wazuh with Slack for Real-Time Alerting

Slack has been integrated as a communication channel for the security team to ensure real-time delivery of critical security notifications. Using the SOAR platform Shuffle, it is possible to automatically forward alerts from Wazuh directly to a designated Slack channel.

    💬 Slack is a modern communication platform that enables teams to exchange information in real time, integrate with external tools, and respond to incidents quickly and efficiently.

🔗 Slack Integration with Wazuh

To enable Slack alerting, add the following integration block to the Wazuh manager configuration:

File path: /var/ossec/etc/ossec.conf

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

