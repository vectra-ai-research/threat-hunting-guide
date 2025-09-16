# SMB v1 Protocol Usage Detection

## Description
This query identifies all instances of SMBv1 protocol usage across your network infrastructure, including client connections, server shares, and inter-system communications. It detects both active SMBv1 sessions and systems that have SMBv1 enabled but may not be actively using it, revealing legacy applications, older Windows systems, network-attached storage devices, and third-party software that still rely on this outdated and vulnerable protocol.

## Logic Overview
The query scans network SMB activity over the past 7 days to identify systems using the SMBv1 protocol. It correlates SMB connection logs with hostname resolution data to provide clear asset identification. The detection focuses on:
- Active SMBv1 protocol negotiations and sessions
- Distinct source hosts initiating SMBv1 connections
- Hostname resolution for better asset identification and remediation planning

SMBv1 detection is critical because this protocol lacks modern security features like encryption and proper authentication mechanisms, making it a significant attack vector for lateral movement and data exfiltration.

## SQL Query

```sql
-- Detect SMBv1 protocol usage across network infrastructure
-- Identifies both active sessions and systems with SMBv1 capability
-- Includes hostname resolution for asset identification

SELECT DISTINCT id.orig_h, orig_hostname.name
FROM network.smb_mapping._all
WHERE version = 'SMBv1' AND timestamp > date_add('day', -7, now())
```

## MITRE ATT&CK Mapping
- **Tactic**: Lateral Movement
- **Technique**: T1021.002 - Remote Services
- **Sub-technique**: SMB/Windows Admin Shares

## Hunting Value
This query provides critical security and compliance value by identifying:

**Security Risks**:
- **Lateral Movement Vulnerabilities**: SMBv1's lack of encryption and weak authentication makes it ideal for attackers to move laterally through networks
- **Attack Surface Reduction**: Identifies systems that can be exploited using known SMBv1 vulnerabilities
- **Data Exfiltration Paths**: SMBv1 connections can be leveraged for unauthorized data access and transfer

**Compliance Requirements**:
- **Regulatory Standards**: Many frameworks (PCI DSS, NIST, SOX) require disabling insecure protocols like SMBv1
- **Industry Guidelines**: Security frameworks mandate removal of legacy protocols to meet baseline security requirements
- **Audit Preparation**: Provides documentation for compliance audits and security assessments

## Tuning and Customization
**Time Window Adjustments**:
- Extend to 30 days for comprehensive legacy system discovery: `date_add('day', -30, now())`
- Reduce to 24 hours for active threat hunting: `date_add('hour', -24, now())`

**Environment-Specific Filters**:
- Exclude known legacy systems during planned migration periods
- Add network segment filter for prioritizing critical business areas

## Investigation Follow-up
When SMBv1 usage is detected:

1. **Asset Classification**:
   - Identify system purpose and business criticality
   - Determine if the system is managed or unmanaged
   - Check for asset inventory and ownership information
   - Assess network segmentation and access controls

2. **Technical Analysis**:
   - Verify current operating system and patch levels
   - Check for available SMBv2/v3 support
   - Identify applications or services requiring SMBv1
   - Review system configuration and group policies

3. **Risk Assessment**:
   - Evaluate exposure to external networks
   - Check for recent security incidents involving the system

## Author Information
- **Author**: Cyrille Franchet
- **Date Created**: 2025-09-15
- **Last Updated**: 2025-09-15
- **Version**: 1.0

## References
- [MITRE ATT&CK T1021.002](https://attack.mitre.org/techniques/T1021/002/)
- [Microsoft SMBv1 Deprecation Guide](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/smbv1-not-installed-by-default-in-windows)