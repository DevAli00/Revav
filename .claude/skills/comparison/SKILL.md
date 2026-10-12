---
name: comparison
description: Side-by-side product comparison — diff engine, coverage deltas, winner determination
---

# Product Comparison

## Comparison Dimensions

1. **Technique Coverage** — ATT&CK techniques each product covers and at what confidence.
2. **Mechanism Depth** — Number and types of detection mechanisms per technique.
3. **Blind Spot Overlap** — Shared vs. unique gaps between products.
4. **Coverage Trends** — Improvements and regressions between versions.

## Diff Statuses

- **Added** — Covered by B but not A
- **Removed** — Covered by A but not B
- **Improved** — Higher confidence in B
- **Regressed** — Lower confidence in B
- **Unchanged** — Same coverage
- **Mechanism Change** — Same confidence, different mechanisms

## Summary Metrics

- Total techniques assessed
- Techniques unique to each product
- Improved/regressed/unchanged counts
- Overall score delta and winner

## Use Cases

- Version comparison across product updates
- Product selection for procurement
- Gap analysis where neither product has coverage

## Tool Integration

Use `revav compare --products a.json b.json` for side-by-side comparison.
