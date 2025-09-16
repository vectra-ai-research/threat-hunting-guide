# Getting Started with Threat Hunting

This guide provides security analysts with information needed to effectively threat hunt in Vectra AI platform.

## Prerequisites

### Technical Requirements
- Access to the [Vectra AI](https://www.vectra.ai) RUX platform
- Access to Investigate search
- Basic understanding of SQL syntax and joins
- Familiarity with your organization's network and security architecture

### Recommended Skills
- Knowledge of common attack techniques and indicators
- Experience with log analysis and pattern recognition
- Understanding of network protocols and authentication systems
- Familiarity with MITRE ATT&CK framework

## Your First Threat Hunt

### Step 1: Choose a Starting Query
We recommend beginning with one of these queries:
- **[Failed Login Pattern Analysis](../queries/authentication/failed-login-patterns.md)** - Good for environments with centralized authentication
- **[Suspicious DNS Queries](../queries/network/suspicious-dns-queries.md)** - Effective for detecting C2 infrastructure

### Step 2: Adapt the Query
2. **Customize Field Names**: Update column names to match your desired result
3. **Adjust Thresholds**: Modify detection thresholds based on your environment size
4. **Add Filters**: Include any environment-specific exclusions

### Step 3: Test Execution
```sql
-- Start with a smaller time window for testing
WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 1 HOUR)  -- Instead of 24 hours
LIMIT 10;  -- Limit results during testing
```

### Step 4: Validate Results
- Compare results against known incidents or expected patterns
- Verify that legitimate activity is appropriately excluded
- Check that the query execution time is reasonable
- Document any necessary adjustments

## Common Customizations

### Time Windows
Most queries use relative time windows that you may need to adjust:
```sql
-- Original: 24-hour window
WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)

-- Customized: 4-hour window for faster iteration
WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 4 HOUR)
```

### Threshold Tuning
Adjust detection thresholds based on your environment:
```sql
-- Original: Generic threshold
HAVING total_failures >= 20

-- Customized: Environment-specific threshold
HAVING total_failures >= 50  -- For high-activity environments or data type
```

## Building a Hunting Program

### 1. Start Small
- Begin with 2-3 high-value queries
- Focus on data sources with good coverage
- Establish regular execution schedules
- Document findings and tuning decisions

### 2. Establish Processes
- Create investigation runbooks for each query
- Define escalation criteria and response procedures
- Implement case management for tracking findings
- Schedule regular review and tuning sessions

### 3. Expand Coverage
- Add new query categories based on threat landscape
- Integrate additional data sources
- Develop custom queries for environment-specific threats
- Implement automated execution and alerting

### 4. Measure Effectiveness
- Track true positive rates and investigation outcomes
- Monitor query performance and execution times
- Document lessons learned and process improvements
- Share findings with security community

## Resources and Support

- **[Vectra AI SQL Search](https://support.vectra.ai/vectra/article/KB-VS-1864)**
- **Issues**: Report problems or ask questions via GitHub issues