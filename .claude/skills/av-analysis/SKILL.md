---
name: av-analysis
description: AV engine analysis methodology — static/dynamic scanning, signature formats, heuristic evaluation
---

# AV Engine Analysis

Methodology for analyzing antivirus products to extract their detection architecture.

## Phases

1. **Engine Identification** — Identify scanning engines (static, dynamic, cloud), their invocation order, and fail-open/fail-closed behavior.
2. **Signature Extraction** — Extract signature databases, update formats, and pattern matching logic. Identify hash-based, byte-pattern, and YARA-style rules.
3. **Heuristic Profiling** — Map heuristic/behavioral scoring: what triggers elevated scores, threshold values, and evasion-resistant features.
4. **Emulation Analysis** — Profile code emulation capabilities: supported architectures, emulation depth, anti-emulation detection.
5. **Cloud Lookup** — Map cloud query behavior: what metadata is sent, response handling, offline fallback behavior.
6. **Coverage Assessment** — Map findings to ATT&CK techniques, score confidence per mechanism, identify blind spots.

## Key Artifacts

- Engine component inventory (DLLs, services, drivers)
- Signature format documentation
- Heuristic trigger catalog
- Emulation capability matrix
- Cloud telemetry profile

## Tool Integration

Use `revav scan` with `--agents hook,rule,behavior` for AV-focused extraction.
Map results with `revav analyze` to produce coverage matrices.
