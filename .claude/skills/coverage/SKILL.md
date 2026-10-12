---
name: coverage
description: ATT&CK coverage mapping — technique correlation, confidence scoring, gap identification
---

# ATT&CK Coverage Mapping

## Mapping Process

1. **Mechanism Correlation** — Map each extracted mechanism to ATT&CK techniques it covers.
2. **Confidence Scoring** — Score each technique based on mechanism type, quality, depth, redundancy.
3. **Gap Identification** — Find techniques with zero, single-mechanism, or telemetry-only coverage.
4. **Grade Assignment** — Assign letter grades (A-F) based on composite confidence scores.

## Scoring Weights (defaults)

| Mechanism Type     | Weight |
|-------------------|--------|
| Kernel callback   | 1.0    |
| Inline hook       | 0.85   |
| Behavioral rule   | 0.7    |
| Static rule       | 0.5    |
| IAT hook          | 0.4    |
| Telemetry only    | 0.25   |

Depth bonus: +0.1 per additional mechanism (capped at max_score).

## Grade Scale

- **A** (>= 0.9): Comprehensive coverage with kernel-level visibility
- **B** (>= 0.7): Strong coverage, may lack redundancy
- **C** (>= 0.5): Moderate coverage
- **D** (>= 0.3): Weak coverage, significant gaps
- **F** (< 0.3): Minimal or no coverage

## Tool Integration

Use `revav analyze` to produce coverage matrices.
Use `revav export --navigator` for ATT&CK Navigator visualization.
