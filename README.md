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

### Wazuh & Shuffle integration:

```xml
<integration>
  <name>shuffle</name>
  <hook_url>API</hook_url>
  <level>6</level>
  <alert_format>json</alert_format>
</integration>
```

_Ścieżka pliku konfiguracyjnego: `/var/ossec/etc/ossec.conf`_

