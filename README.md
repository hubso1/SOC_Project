# SOC_Project
Open-source SOC lab environment using tools like Wazuh, Suricata, TheHive, Cortex, Shuffle and more. Built for learning, threat detection, log analysis, and incident response.

Project Description

This project aims to build a complete Security Operations Center (SOC) environment using open-source tools, designed to support learning and understanding of key IT security principles. Its main goals are to:

    Demonstrate how to collect and analyze logs from Linux and Windows systems using Wazuh agents

    Enable detection of network threats and anomalies with the Suricata IDS

    Showcase incident management using TheHive and Cortex

    Implement security process automation via Shuffle (SOAR)

    Integrate with external services like VirusTotal and Slack

    Visualize data flow and interaction between components in a modern SOC setup

This project serves an educational purpose, helping users explore the architecture, integration, and operation of tools commonly used in real-world SOC environments. It can be extended further and used as a base for experiments, development, and hands-on practice in threat detection and incident response.

 <integration>
    <name>shuffle</name>
    <hook_url>API</hook_url>                                                               
    <level>6</level>
    <alert_format>json</alert_format>
  </integration>

/var/ossec/etc/ossec.conf

