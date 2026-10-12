---
name: behavioral
description: Behavioral detection profiling — process trees, file/registry monitoring, API sequences
---

# Behavioral Detection Profiling

## Detection Categories

1. **Process Tree Analysis** — Parent-child rules, suspicious ancestry chains
2. **File System Monitoring** — Monitored paths, file operation patterns
3. **Registry Monitoring** — Watched keys/values, persistence locations
4. **API Call Sequences** — Monitored call chains, behavioral signatures
5. **Network Behavior** — DNS monitoring, connection patterns
6. **Memory Operations** — Allocation patterns, injection detection

## Profiling Approach

1. Enumerate monitored resources (paths, keys, APIs)
2. Map trigger conditions (single action vs. sequence)
3. Assess sensitivity thresholds and scoring weights
4. Identify unmonitored categories as coverage gaps

## Confidence

- Multi-stage behavioral rules: high confidence
- Single-action triggers: medium confidence
- Threshold-based scoring: variable confidence

## Tool Integration

Use `revav scan --agents behavior` for behavioral profiling.
