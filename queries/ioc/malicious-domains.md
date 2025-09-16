# Malicious Domains - Command and Control / Phishing Infrastructure

## Description
Detects outbound network sessions to known-bad domains, identifying potential signs of command and control (C2) callbacks, beaconing activity, or connections to phishing infrastructure. This query helps identify compromised hosts communicating with attacker-controlled domains.

## Logic Overview
This query analyzes network session data to identify suspicious domain communications:
- **Data Sources**: Network session logs (network.isession table)
- **Key Indicators**: Outbound connections to known malicious domains
- **Detection Logic**: Matches destination domains against a predefined list of known-bad domains
- **Time Window**: Last 7 days from current timestamp
- **Session Details**: Captures comprehensive connection metadata including IPs, ports, protocols, and traffic volumes

## SQL Query

```sql
SELECT timestamp, uid, id.orig_h as "id_orig_h", orig_hostname, id.resp_h as "id_resp_h", 
       resp_hostname, id.resp_p as "id_resp_p", proto_name, orig_ip_bytes, 
       resp_ip_bytes, duration, conn_state, sensor_uid
FROM network.isession
WHERE (resp_domain = 'baddomain1.com' OR resp_domain = 'baddomain2.com') 
  AND timestamp > date_add('day', -7, now())
ORDER BY timestamp DESC
LIMIT 100
```

## MITRE ATT&CK Mapping
- **Tactic**: Command and Control
- **Technique**: T1071 - Application Layer Protocol
- **Sub-technique**: T1071.001 - Web Protocols

## Hunting Value
This query provides critical value for threat hunting by:
- **C2 Communication Detection**: Identifies potential command and control channels used by malware
- **Beaconing Activity**: Catches periodic callbacks from infected hosts to attacker infrastructure
- **Phishing Infrastructure**: Detects user interactions with malicious domains used in phishing campaigns
- **Malware Family Identification**: Helps identify specific threat families
- **Threat Actor Tracking**: Enables tracking of infrastructure used by groups like Scattered Spider

## Tuning and Customization
Adapt the query for your environment with these considerations:
- **Domain List Maintenance**: Regular updates to the malicious domain list are critical for effectiveness
- **Time Window**: Adjust the 7-day window (`date_add('day', -7, now())`) based on retention and investigation needs
- **Result Limit**: Modify `LIMIT 100` based on expected volume and analysis capacity
- **False Positive Filtering**: Consider excluding legitimate domains that may be flagged incorrectly
- **Domain Matching**: Implement wildcard or substring matching for domain families or DGAs
- **Protocol Filtering**: Add protocol-specific filters if focusing on specific attack vectors

## Investigation Follow-up
When this query returns suspicious results, investigate further by:
- **Host Analysis**: Examine the originating host for signs of compromise or malware infection
- **Traffic Pattern Analysis**: Look for beaconing patterns, data exfiltration, or command execution
- **Timeline Correlation**: Check for related security events around the connection timeframes
- **Domain Reputation**: Research the reputation and history of the contacted domains
- **Network Forensics**: Analyze packet captures or network metadata for detailed communication content
- **Endpoint Investigation**: Deploy EDR tools to examine processes and files on affected systems
- **Additional Queries**: Run supplementary queries to check for:
  - DNS queries to the same malicious domains
  - Other hosts communicating with the same infrastructure
  - File downloads or uploads during the sessions
  - Process execution correlated with network activity
- **Containment Planning**: Prepare isolation procedures for confirmed compromised hosts

## Author Information
- **Author**: Vectra AI Team
- **Date Created**: 2024-09-15
- **Last Updated**: 2024-09-15
- **Version**: 1.0

## References
- [MITRE ATT&CK - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK - Phishing](https://attack.mitre.org/techniques/T1566/)