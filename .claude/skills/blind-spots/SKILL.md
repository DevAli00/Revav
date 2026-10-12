---
name: blind-spots
description: Detection gap identification — weakness classification, severity ranking
---

# Blind Spot Identification

## Weakness Classes

1. **Zero Coverage** — No detection mechanisms at all. Severity: critical.
2. **Userland Only** — Relies solely on userland hooks. Severity: high.
3. **Single Mechanism** — One detection mechanism, single point of failure. Severity: medium.
4. **Telemetry Only** — Data collection without active detection. Severity: medium.
5. **Partial Sub-technique** — Parent covered but sub-techniques have gaps. Severity: medium.
6. **Low Confidence** — Detection exists but below threshold. Severity: low.

## Severity Ranking

Ranked by:
1. Severity class (critical > high > medium > low)
2. Technique prevalence in real-world attacks
3. Availability of public tooling
4. Difficulty of remediation

## Output

Blind spots feed into bypass briefs, eval scorecards, and vendor audits.

## Tool Integration

Coverage scorer (`revav.tools.coverage_scorer`) automatically identifies blind spots.
Use `revav report --format bypass-brief` for prioritized gap analysis.
