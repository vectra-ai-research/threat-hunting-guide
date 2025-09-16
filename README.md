# Vectra Threat Hunting Guide

A comprehensive collection of threat hunting queries designed to help security analysts detect, investigate, and respond to potential security threats across enterprise environments.

## Overview

This repository provides production-ready SQL queries for threat hunting activities. Each query includes detailed documentation explaining the detection logic, expected results, and hunting value to help security teams implement effective threat hunting programs.

## Repository Structure

```
threat-hunting-guide/
├── queries/                     # Core threat hunting queries
│   ├── compliance/              # Compliance-related detection queries
│   ├── ttp/                     # TTP-based hunting queries
│   ├── ioc/                     # IOC-based hunting queries
│   └── README.md                # Query categories and usage guide
├── templates/                   # Standardized query templates
│   └── query-template.md        # Template for new query contributions
└── docs/                        # Documentation and guides
    └── getting-started.md       # Quick start guide for analysts
```

## Query Categories

- **Compliance**: Regulatory and policy violation detection including SMB v1 usage, outdated protocols, and configuration compliance
- **TTP**: Tactics, Techniques, and Procedures detection including impossible travel, credential compromise, and behavioral anomalies
- **IOC**: Indicator of Compromise detection for known malicious artifacts, signatures, and threat intelligence matches

## Quick Start

1. Browse the [`queries/`](queries/) directory to find relevant threat hunting queries
2. Review the query documentation for context and expected results
3. Adapt the SQL queries to your specific data & environment
4. Run queries in your Vectra AI platform

## Usage Guidelines

- **Customize**: Modify time ranges, thresholds, and filters for your environment
- **Validate**: Confirm query results against known good/bad examples
- **Document**: Record findings and tune queries based on results

## Contributing

We welcome contributions of new threat hunting queries! Please use the provided [query template](templates/query-template.md) to ensure consistency and completeness.

## Support

For questions, suggestions, or issues, please open a GitHub issue with detailed information about your use case and environment.