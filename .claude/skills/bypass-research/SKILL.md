---
name: bypass-research
description: "Derive bypass opportunities from identified blind spots and weak detection mechanisms. Use after coverage analysis to identify evasion paths."
metadata:
  version: "0.1.0"
---

# Bypass Research

## Overview

Derives bypass opportunities from the blind spots and weak detection mechanisms identified during coverage analysis. Takes ATT&CK coverage gaps and translates them into actionable bypass strategies.

## Prerequisites

- Completed coverage analysis in `kb/layers/<product>.json`
- Detection catalog in `kb/catalog/<product>.json`
- Product profile in `kb/profiles/<product>.yaml`

## Methodology

### Step 1: Identify Blind Spots

Load the coverage matrix and filter for:
- **Zero coverage**: ATT&CK techniques with no detection mechanism mapped
- **Weak coverage**: Techniques covered by only IAT hooks (bypassable via direct syscall)
- **Partial coverage**: Techniques where some sub-techniques are covered but others aren't

```bash
revav analyze --catalog kb/catalog/<product>.json --output kb/layers/
```

### Step 2: Categorize Bypass Classes

Group identified gaps by bypass method:

**API-level bypasses** (weak hooks):
- IAT-only hooks → direct API call or dynamic resolution bypasses
- Inline hooks on Nt* but not Zw* equivalents
- Missing hooks on newer API variants (NtCreateThreadEx vs NtCreateThread)

**Kernel-level gaps** (missing callbacks):
- No PsSetLoadImageNotifyRoutine → unsigned DLL loading undetected
- No ObRegisterCallbacks → process handle duplication unmonitored
- No CmRegisterCallbackEx → registry operations invisible
- Minifilter altitude gaps → operations between altitudes unmonitored

**Telemetry blind spots** (missing data sources):
- ETW providers not subscribed → events never collected
- No WMI subscription for specific event classes
- Cloud telemetry gaps → events not forwarded for cloud analysis

**Behavioral gaps** (uncorrelated patterns):
- Process trees not in behavioral model → novel parent-child chains undetected
- File paths outside monitored directories
- Timing-based evasion (behavioral analysis windows)

### Step 3: Prioritize by Impact

Rank bypass opportunities by:

1. **Campaign relevance**: Does this technique appear in active threat campaigns? (cross-reference CTI feeds)
2. **Exploit simplicity**: How easy is the bypass to implement?
3. **Detection alternative**: Is there another mechanism that might catch it indirectly?
4. **Scope of impact**: Does this bypass one detection or an entire detection category?

### Step 4: Generate Bypass Brief

```bash
revav report --profile kb/profiles/<product>.yaml --format bypass-brief
```

The bypass brief contains:
- Executive summary of coverage posture
- Ranked list of bypass opportunities with ATT&CK mapping
- For each bypass: the gap, the mechanism class, the impact, and recommended remediation
- ATT&CK Navigator layer with blind spots highlighted in red

## Output Format

The bypass brief uses the template at `templates/bypass_brief.md` and produces:

- **Bypass opportunities**: ranked by impact with technique IDs
- **Coverage heat map**: visual representation of detection density
- **Remediation recommendations**: what hooks/callbacks/rules to add
- **Navigator layer**: importable JSON with gap visualization

## Tools

- `revav.tools.attack_mapper` — ATT&CK technique correlation
- `revav.tools.coverage_scorer` — detection confidence scoring
- `revav.tools.report_gen` — bypass brief generation
- `revav.tools.navigator_export` — gap visualization layer
