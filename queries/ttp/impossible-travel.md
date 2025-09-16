# Multi-Country Sign-Ins (Impossible Travel)

## Description
Detects users who have signed in from multiple different countries within the last 24 hours, which may indicate compromised credentials. This query identifies potential impossible travel scenarios where users appear to be authenticating from geographically distant locations within a timeframe that would be physically impossible.

## Logic Overview
This query analyzes authentication data from Azure/Entra ID sign-in logs to identify anomalous sign-in patterns:
- **Data Sources**: Entra ID sign-in logs with location data
- **Key Indicators**: Multiple distinct countries for the same user within 24 hours
- **Detection Logic**: Groups successful sign-ins by user identity, counts unique countries, and identifies users with more than one country
- **Time Window**: Last 24 hours from current timestamp
- **Filtering**: Excludes entries without location data and focuses only on successful authentications

## SQL Query

```sql
SELECT DISTINCT(vectra.identity_principal), 
       COUNT(DISTINCT location.country_or_region) AS CountryCount, 
       MIN(timestamp) AS FirstLogin, 
       MAX(timestamp) AS LastLogin
FROM entra.signins._all
WHERE location.country_or_region IS NOT NULL
  AND timestamp > date_add('day', -1, now())
GROUP BY vectra.identity_principal
HAVING COUNT(DISTINCT location.country_or_region) > 1
ORDER BY CountryCount
LIMIT 100
```

## MITRE ATT&CK Mapping
- **Tactic**: Initial Access
- **Technique**: T1078 - Valid Accounts
- **Sub-technique**: T1078.004 - Cloud Accounts

## Hunting Value
This query provides significant value for threat hunting by:
- **Credential Compromise Detection**: Identifies potentially compromised accounts being used from multiple geographic locations
- **Account Takeover Indicators**: Reveals signs of unauthorized access to legitimate user accounts
- **Geographic Anomaly Detection**: Catches impossible travel patterns that human users cannot physically achieve
- **Investigation Prioritization**: Helps security teams focus on high-risk authentication events

## Tuning and Customization
Consider these adjustments for your environment:
- **Time Window**: Adjust the 24-hour window (`date_add('day', -1, now())`)
- **Country Threshold**: Modify the `> 1` condition if you want to detect travel across more countries instead
- **Result Limit**: Increase the `LIMIT 100` based on your user base size
- **VPN Considerations**: May need to filter out known VPN exit nodes or remote work locations

## Investigation Follow-up
When this query returns suspicious results, investigate further by:
- **Timeline Analysis**: Examine the exact timing between sign-ins from different countries
- **IP Address Investigation**: Research the source IP addresses for reputation and geolocation accuracy
- **User Behavior**: Check for other anomalous activities from the same user account during the timeframe
- **Authentication Methods**: Verify if multi-factor authentication was used for the sign-ins
- **Application Usage**: Investigate which applications or resources were accessed from each location
- **User Verification**: Contact the user to verify legitimate travel or remote access
- **Additional Queries**: Run follow-up queries to check for:
  - Failed authentication attempts from the same IPs
  - Other users authenticating from the same suspicious locations
  - Data exfiltration or unusual resource access patterns

## Author Information
- **Author**: Arpan Sarkar
- **Date Created**: 2025-09-15
- **Last Updated**: 2024-09-15
- **Version**: 1.0

## References
- [MITRE ATT&CK - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- [Azure AD Sign-in Logs Documentation](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins)