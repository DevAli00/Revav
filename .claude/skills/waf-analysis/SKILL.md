---
name: waf-analysis
description: WAF ruleset analysis — rule extraction, parsing logic, evasion surface mapping
---

# WAF Ruleset Analysis

Methodology for analyzing web application firewalls to extract detection rules and identify coverage gaps.

## Phases

1. **Rule Extraction** — Extract active rulesets (ModSecurity CRS, proprietary rules, custom rules). Identify rule format and parser behavior.
2. **Parser Profiling** — Map HTTP parsing behavior: encoding handling, multipart parsing, chunked transfer, protocol deviations.
3. **Normalization Mapping** — Document normalization pipeline: URL decoding depth, Unicode handling, case folding, comment stripping.
4. **Detection Logic** — Catalog detection operators: regex patterns, libinjection integration, anomaly scoring, ML classifiers.
5. **Response Behavior** — Map blocking modes (block, redirect, challenge, log-only), threshold configurations, and paranoia levels.
6. **Coverage Assessment** — Map rules to web attack taxonomy, identify unprotected attack surfaces.

## Key Artifacts

- Active ruleset inventory with rule IDs and descriptions
- Parser behavior matrix (encoding support, edge cases)
- Normalization pipeline documentation
- Detection operator catalog
- Response configuration profile

## Tool Integration

Use `revav scan` with `--agents rule` for WAF-focused extraction.
Use `revav report --format eval-scorecard` for WAF evaluation reports.
