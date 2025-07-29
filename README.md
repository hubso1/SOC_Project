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

In the integration script located at /var/ossec/integrations/shuffle.py, locate the requests.post function. You can set the verify flag to False to bypass SSL verification (not recommended for production).
Example code adjustment:
```python
def send_msg(msg: str, url: str) -> None:
    """Send the message to the API"""
    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
    res = requests.post(url, data=msg, headers=headers, timeout=10, verify=False)
```
⚠️ Warning: This method is not guaranteed to work with all servers, as some enforce strict SSL policies and may reject unsecured connections

