# Revav

**Security product reverse engineering framework.**

Systematically extract, catalog, and map the detection mechanisms of EDRs, AVs, WAFs, and HIDS — then map them to [MITRE ATT&CK](https://attack.mitre.org/) to produce coverage maps, blind spot analysis, and bypass research documentation.

## What It Does

Every security product has a finite set of detection mechanisms: userland hooks, kernel callbacks, ETW providers, YARA rules, behavioral signatures. Revav extracts and catalogs these mechanisms, then maps them to ATT&CK techniques to answer:

- **What does this product actually detect?** — not what the vendor claims, but what the hooks, rules, and telemetry actually cover
- **Where are the blind spots?** — ATT&CK techniques with zero or weak coverage
- **How does it compare?** — side-by-side analysis across products or versions
- **What bypasses exist?** — derived from identified gaps and weak detection mechanisms

## Architecture

```
Target Acquisition → Extraction Engine → Analysis & Correlation → Knowledge Base → Reporting
```

**5 Extraction Agents** run in parallel against each target:

| Agent | What It Extracts |
|-------|-----------------|
| Hook Scanner | Userland API hooks — inline, IAT, EAT, syscall stub modifications |
| Callback Enumerator | Kernel callbacks, minifilter registrations, WFP/NDIS filters |
| Rule Extractor | Embedded YARA, Sigma, Snort/Suricata rules |
| Behavioral Profiler | Monitored process trees, registry paths, file operations, memory scan triggers |
| Telemetry Mapper | ETW providers consumed, WMI subscriptions, telemetry endpoints |

**Outputs** include ATT&CK Navigator layers, bypass briefs, evaluation scorecards, vendor claim audits, and structured JSON/YAML for automation pipelines.

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Full extraction pipeline against a target
revav scan --target ./target/ --baseline baselines/ntdll_clean.json --output kb/catalog/

# Map extracted mechanisms to ATT&CK
revav analyze --catalog kb/catalog/product.json --output kb/layers/

# Generate reports
revav report --profile kb/profiles/product.yaml --format bypass-brief
revav report --profile kb/profiles/product.yaml --format eval-scorecard

# Docker
docker build -t revav .
docker run -v ./targets:/targets -v ./kb:/opt/revav/kb revav scan --target /targets/product
```

## Project Structure

```
revav/
  cli.py              # Click-based CLI entry point
  tools/              # Python extraction and analysis tools
  schemas/            # JSON Schema definitions for inter-stage data
.claude/skills/       # Claude methodology skills (SKILL.md files)
templates/            # Report and profile templates
kb/                   # Knowledge base — git-tracked analysis results
  profiles/           # Product identity cards
  catalog/            # Detection mechanism catalogs
  layers/             # ATT&CK Navigator layers
  diffs/              # Version comparison diffs
baselines/            # Clean system baselines for comparison
tests/                # Test suite
docs/                 # Documentation
```

## Use Cases

- **Red teams** identifying blind spots and deriving bypass strategies
- **Blue teams** mapping defensive coverage against adversary TTPs
- **Security architects** evaluating EDR/AV products for procurement
- **Detection engineers** identifying coverage gaps to write new rules
- **Vendor security teams** auditing their own product's detection coverage

## Standards

- [MITRE ATT&CK](https://attack.mitre.org/) — technique mapping lingua franca
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) — coverage visualization
- [STIX/TAXII](https://oasis-open.github.io/cti-documentation/) — threat intelligence format
- [YARA](https://virustotal.github.io/yara/) / [Sigma](https://sigmahq.io/) — detection rule formats

## License

MIT
