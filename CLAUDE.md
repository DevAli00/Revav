# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project: Revav

Security product reverse engineering framework. Systematically extracts, catalogs, and maps the detection mechanisms of EDRs, AVs, WAFs, and HIDS — then maps them to MITRE ATT&CK to produce coverage maps, blind spot analysis, and bypass research.

**Dual-use by design.** The same extraction engine serves red teams (blind spot identification, bypass research) and blue teams (coverage mapping, detection hardening). Reports include bypass briefs for offensive operators and evaluation scorecards for security architects.

## Architecture

Five-layer pipeline where each stage reads its predecessor's output from the shared `kb/` directory:

```
Target Acquisition → Extraction Engine → Analysis & Correlation → Knowledge Base → Reporting
```

### Layer 1: Target Acquisition (`revav/tools/ingest_*.py`)
Normalizes security products (installers, running processes, drivers, configs) into standard artifacts for analysis.

### Layer 2: Extraction Engine (`revav/tools/{hook_scanner,callback_enum,rule_parser,behavior_map,etw_mapper}.py`)
Five specialized extractors run in parallel against normalized artifacts:
- **Hook Scanner** — userland API hooks (inline, IAT, EAT, syscall stubs)
- **Callback Enumerator** — kernel callbacks, minifilters, WFP filters
- **Rule Parser** — YARA, Sigma, Snort/Suricata rules embedded in the product
- **Behavior Mapper** — monitored process trees, registry paths, file operations
- **ETW Mapper** — ETW providers consumed, WMI subscriptions, telemetry endpoints

### Layer 3: Analysis & Correlation (`revav/tools/{attack_mapper,coverage_scorer,diff_engine}.py`)
Maps extracted mechanisms to ATT&CK techniques, scores detection confidence, identifies gaps.

### Layer 4: Knowledge Base (`kb/`)
Structured YAML/JSON storage: `profiles/` (product identity), `catalog/` (detection mechanisms), `layers/` (ATT&CK Navigator JSON), `diffs/` (version comparisons). Git-tracked for historical analysis.

### Layer 5: Reporting (`revav/tools/{navigator_export,report_gen}.py`)
Generates bypass briefs, evaluation scorecards, vendor claim audits, ATT&CK Navigator layers.

## Skills

Skills live in `.claude/skills/<name>/SKILL.md` with YAML frontmatter. Two tiers:

**Product-type skills** (what to analyze):
- `edr-analysis` — EDR product evaluation methodology
- `av-analysis` — AV engine analysis
- `waf-analysis` — WAF ruleset analysis

**Extraction skills** (how to extract):
- `hook-mapping` — userland hook identification
- `kernel-enum` — kernel callback enumeration
- `rule-extraction` — detection rule extraction
- `behavioral` — behavioral detection profiling
- `telemetry` — telemetry channel mapping

**Analysis skills** (how to interpret):
- `coverage` — ATT&CK coverage mapping
- `blind-spots` — detection gap and blind spot identification
- `comparison` — side-by-side product comparison
- `bypass-research` — bypass opportunity derivation from identified gaps

## Commands

```bash
# Install dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/
pytest tests/test_attack_mapper.py -k "test_map_hook_to_technique"  # single test

# Type checking
mypy revav/

# Lint
ruff check revav/ tests/
ruff format revav/ tests/

# CLI usage
revav scan --target <path_or_pid> --output kb/catalog/         # full extraction pipeline
revav analyze --catalog kb/catalog/<product>.json --output kb/layers/  # ATT&CK mapping
revav compare --products product_a.json product_b.json         # side-by-side comparison
revav report --profile kb/profiles/<product>.yaml --format bypass-brief  # generate report
revav export --layer kb/layers/<product>.json --navigator       # ATT&CK Navigator layer

# Run individual tools directly
python -m revav.tools.hook_scanner --input <artifact_path> --output kb/catalog/
python -m revav.tools.attack_mapper --catalog kb/catalog/<product>.json --output kb/layers/
python -m revav.tools.report_gen --profile kb/profiles/<product>.yaml --template templates/bypass_brief.md

# Docker
docker build -t revav .
docker run -v ./targets:/targets -v ./kb:/opt/revav/kb revav scan --target /targets/<product>
```

## Schemas & Data Contracts

All inter-stage data uses JSON Schema definitions in `revav/schemas/`:
- `product_profile.schema.json` — product identity and component inventory
- `detection_catalog.schema.json` — extracted detection mechanisms
- `coverage_matrix.schema.json` — ATT&CK technique coverage with confidence scores
- `navigator_layer.schema.json` — ATT&CK Navigator layer format

Tool outputs MUST validate against their schema before writing to `kb/`. Use `revav.schemas.validate()`.

## Conventions

- Python 3.11+, strict typing with `mypy --strict`
- Every tool is a standalone CLI (`python -m revav.tools.<name>`) AND an importable module
- Tool results carry provenance metadata: source artifact, extraction method, confidence level, timestamp
- ATT&CK technique IDs use the format `T####` or `T####.###` — always validated against the bundled ATT&CK STIX data
- Knowledge base files are git-tracked; never `.gitignore` the `kb/` directory
- Detection mechanisms map to one of: `hook`, `callback`, `rule`, `behavioral`, `telemetry`
