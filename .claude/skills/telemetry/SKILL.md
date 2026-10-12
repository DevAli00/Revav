---
name: telemetry
description: Telemetry channel mapping — ETW providers, WMI subscriptions, cloud endpoints, logging
---

# Telemetry Channel Mapping

## Channel Types

1. **ETW Providers** — Event Tracing for Windows providers consumed by the product
2. **WMI Subscriptions** — WMI event subscriptions for process, file, registry monitoring
3. **Event Log Channels** — Windows Event Log channels consumed or generated
4. **Cloud Endpoints** — Cloud telemetry submission endpoints and data formats
5. **Local Logging** — On-disk log files, structured data stores
6. **Syslog/SIEM** — Syslog forwarding, SIEM integration channels

## Mapping Approach

1. List ETW providers registered by product components
2. Enumerate WMI event subscriptions owned by product services
3. Identify cloud telemetry endpoints and submission patterns
4. Locate local log storage and data retention policies
5. Map telemetry sources to ATT&CK technique visibility

## Telemetry vs. Detection

Telemetry provides visibility, not necessarily detection. A product may collect data about a technique without actively alerting. Telemetry-only coverage receives lower confidence scores.

## Tool Integration

Use `revav scan --agents telemetry` for telemetry mapping.
