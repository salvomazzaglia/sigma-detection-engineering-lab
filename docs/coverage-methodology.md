# Coverage methodology

> **COVERAGE REFLECTS AUTHORED RULES AND SYNTHETIC TESTS ONLY — NOT ENVIRONMENTAL
> DETECTION COVERAGE**

This document defines exactly what the coverage numbers mean, and — at greater length —
what they do not.

## What is measured

Four ratios, all counting **authored content and synthetic test completeness**:

| Metric | Definition | 1.0.0 |
|---|---|---|
| `rules_with_sidecar` | Rules with a bound metadata sidecar | 56 / 56 |
| `rules_with_attack_mapping` | Rules with at least one verified ATT&CK technique | 56 / 56 |
| `rules_with_fixtures` | Rules with at least one fixture case or sequence | 56 / 56 |
| `rules_fully_tested` | Rules meeting their fixture minimums with all cases passing | 56 / 56 |

Supporting counts:

| Count | 1.0.0 |
|---|---|
| Total rules | 56 (50 standard, 6 correlation) |
| Unique techniques | 36 |
| Unique tactics | 6 |
| Distinct logsources | 12 |
| Fixture cases | 253 |
| Correlation sequences | 30 |
| Behavioral results | 283 |

## What is deliberately not measured

`coverage.py` refuses to compute these, and the refusal is printed in every coverage
artefact:

> Precision, recall, and false-positive rate are intentionally not reported: they cannot
> be derived from synthetic fixtures.

| Excluded metric | Why it cannot be computed here |
|---|---|
| **Precision** | Requires real positives and real false positives. Fixtures are written by the same author as the rules, so the calculation is circular by construction. |
| **Recall** | Requires knowing every instance of the behaviour that occurred. Synthetic data has no ground truth beyond what was generated. |
| **False-positive rate** | Requires a real event population. There is none. |
| **Alert volume** | Depends on the environment, and no fixture count predicts it. |
| **Time to detect** | Requires a live pipeline with real ingestion lag. |
| **Environmental coverage** | Requires knowing what your estate actually collects. |

The temptation to report a precision of 1.0 is real: every positive matched and every
negative was rejected. It would also be meaningless — the author chose both the rules and
the events. A circular metric is worse than no metric, because it looks authoritative.

## Four things "36 techniques" does not mean

This is the sentence most likely to be quoted out of context, so it is stated four
different ways.

1. **It is not 36 techniques' worth of detection.** It is 36 techniques for which a rule
   exists. Whether the rule fires on real activity is untested here.
2. **It is not a percentage of ATT&CK.** The denominator would be the whole framework,
   including techniques irrelevant to the platforms this catalog covers. Dividing by it
   would produce a number that is precise and uninformative.
3. **It is not environmental coverage.** If your estate does not collect Sysmon Event ID
   10, the `SDEL-WIN-012` mapping contributes nothing to your visibility no matter what
   the layer shows.
4. **It is not a maturity score.** One rule for a technique and eight rules for a
   technique both count as "mapped".

## Coverage as a regression signal

The metrics are genuinely useful for one purpose: **detecting that something went
backwards**.

```bash
sigma-detection-lab validate --json-out baseline.json
# ... changes ...
sigma-detection-lab validate --json-out current.json
sigma-detection-lab compare baseline.json current.json --fail-on-regression
```

A rule that loses its sidecar, a technique that disappears from the mapping set, a rule
whose fixtures stop passing — all show up as regressions and fail the build. That is a
true statement about the repository, and it does not require any claim about the world.

## Reading a coverage report

```
COVERAGE REFLECTS AUTHORED RULES AND SYNTHETIC TESTS ONLY — NOT ENVIRONMENTAL DETECTION COVERAGE

Coverage
  Rules:                56
  With sidecar:         56
  With ATT&CK mapping:  56
  With fixtures:        56
  Fully tested:         56
  Unique techniques:    36
  Unique tactics:       6

  Precision, recall, and false-positive rate are intentionally not reported:
  they cannot be derived from synthetic fixtures.
```

Three additional lists appear when non-empty:

- **Techniques not present in the vendored ATT&CK catalog** — omitted from any Navigator
  layer. Should always be empty; if not, a mapping or the extraction is wrong.
- **Catalog techniques with no rule** — techniques in the vendored subset that nothing
  addresses. A candidate list for authoring, not a deficiency.
- **Rules without complete testing** — rules below their fixture minimums.

## Navigator layers

```bash
sigma-detection-lab coverage --tests --navigator temp/layer.json
```

Layer format **4.5**. Two properties are enforced:

- Only techniques verified against the vendored catalog are included.
- **Scores reflect rule count, not detection confidence.**

Navigator layers are visually persuasive in a way tables are not. A heat map reads as
"this is how well defended we are", and this one is not that. Anyone presenting the layer
should say what it counts.

## Fixture balance

The report includes `fixture_balance`, the positive-to-negative ratio per rule. In 1.0.0
the catalog is 113 positive to 170 negative — roughly two to three.

Negatives outnumbering positives is intentional. The expensive failure mode in detection
engineering is the rule that matches too much, and only negative cases catch it. A rule
with many positives and one negative is under-tested regardless of how green it looks.

## Logsource distribution

Twelve distinct logsources across two platforms. Distribution matters because a catalog
concentrated in one source has a single point of failure: if that source is not collected,
the whole catalog is inert. Spread across process creation, registry, file events, process
access, WMI, Security, System, PowerShell, and three Linux sources, a gap in any one
source degrades rather than eliminates the catalog's value.

## Honest summary for a report or a CV

Here is language that is accurate:

> The catalog contains 56 original Sigma rules mapped to 36 MITRE ATT&CK techniques
> across 6 tactics, each with a metadata sidecar, documented telemetry requirements, and
> synthetic behavioral tests — 283 test cases in total, all passing. Coverage figures
> count authored content and synthetic test completeness. They are not a measurement of
> environmental detection coverage or of detection efficacy against real adversaries.

And here is language that is not:

> ❌ "56 rules providing coverage of 36 ATT&CK techniques"
> ❌ "100% test coverage with perfect precision"
> ❌ "Production-ready detection content"

The difference is a single clause, and it is the clause that makes the claim true.

## Related documents

[attack-mapping](attack-mapping.md) ·
[attack-detection-model](attack-detection-model.md) ·
[behavioral-testing](behavioral-testing.md) ·
[reports](reports.md)
