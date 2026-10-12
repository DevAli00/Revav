---
name: rule-extraction
description: Detection rule extraction — YARA, Sigma, Snort, custom formats
---

# Detection Rule Extraction

## Supported Rule Formats

1. **YARA** — Binary pattern matching for file/memory scanning
2. **Sigma** — Generic log detection rules
3. **Snort/Suricata** — Network intrusion detection rules
4. **Custom** — Vendor-proprietary formats, byte patterns, regex

## Phases

1. **Rule Location** — Find rule storage: embedded DBs, config files, update packages
2. **Format Identification** — Determine format and parser version
3. **Rule Parsing** — Parse into structured format with conditions, patterns, metadata
4. **Coverage Mapping** — Map rule conditions to ATT&CK techniques
5. **Quality Assessment** — Evaluate specificity and evasion surface

## Tool Integration

Use `revav scan --agents rule` for rule extraction.
Output validates against `detection_catalog.schema.json`.
