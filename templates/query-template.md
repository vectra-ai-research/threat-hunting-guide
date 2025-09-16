# Query Template

Use this template when contributing new threat hunting queries to ensure consistency and completeness.

---

# [Query Name]

## Description
Brief description of what this query detects or hunts for. Include the specific threat, behavior, or anomaly this query is designed to identify.

## Logic Overview
Explain the detection logic and approach used in the query. Describe:
- What data sources are being analyzed
- Key indicators or patterns being searched for
- Any statistical or threshold-based logic
- Correlation techniques used

## SQL Query

```sql
-- Replace this with your actual SQL query
-- Include clear comments explaining complex logic
-- Use descriptive table aliases and column names
-- Ensure proper formatting and indentation

SELECT 
    timestamp,
    source_ip,
    destination_ip,
    query_name
FROM dns_logs
WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
    AND query_name LIKE '%.suspicious-domain.com'
ORDER BY timestamp DESC;
```

## MITRE ATT&CK Mapping
If applicable, map this query to relevant MITRE ATT&CK techniques:
- **Tactic**: [e.g., Command and Control]
- **Technique**: [e.g., T1071.004 - Application Layer Protocol: DNS]
- **Sub-technique**: [if applicable]

## Hunting Value
Explain why this query is valuable for threat hunting:
- What types of threats it can detect
- How it fits into broader hunting workflows
- Potential for discovering unknown threats
- Context for investigation priorities

## Tuning and Customization
Provide guidance for adapting the query to different environments:
- Parameters that may need adjustment
- Common false positive sources
- Environment-specific modifications
- Performance considerations

## Investigation Follow-up
Suggest next steps when this query returns suspicious results:
- Additional queries to run
- Data points to investigate
- External sources to correlate with
- Escalation criteria

## Author Information
- **Author**: [Your Name]
- **Date Created**: [YYYY-MM-DD]
- **Last Updated**: [YYYY-MM-DD]
- **Version**: [1.0]

## References
- [Link to relevant documentation]
- [MITRE ATT&CK technique pages]
- [Security research or blog posts]
- [Vendor documentation]