# Release notes — 1.0.0

**Released:** 2026-08-07
**Author:** Salvatore Mazzaglia
**License:** MIT

> **SYNTHETIC DEMONSTRATION DATA.** This release makes no claim of production readiness.
> Queries, mappings, and metrics require environment-specific validation before
> operational use.

## What this is

The first release of an **offline detection-as-code laboratory**: 56 original Sigma rules,
each with a metadata sidecar, documented telemetry prerequisites, verified ATT&CK mapping,
and synthetic behavioral tests — enforced by 31 quality gates and reported in six formats.

It runs entirely offline. No SIEM connection, no host log access, no network calls.

## By the numbers

| | |
|---|---|
| Original Sigma rules | **56** (50 standard, 6 correlation) |
| Rule families | Windows 16, PowerShell 10, identity 12, Linux 12, correlation 6 |
| Distinct logsources | 12 |
| ATT&CK techniques | 36 across 6 tactics |
| Behavioral test results | **283** — 113 positive, 170 negative, all passing |
| Fixture cases | 253 single-event, 30 correlation sequences |
| Quality gates | **31**, all passing |
| Conversions | 103 converted, 9 unsupported, 0 errors |
| CLI commands | 9 |
| Report formats | 6 |
| CI matrix | Ubuntu and Windows × Python 3.11 and 3.12 |

## Highlights

### Original rule catalog

Every rule is authored for this project. UUIDs are derived from the repository URL
namespace with `uuid5`, so a catalog identifier and its UUID are always re-computable —
and no upstream identifier can appear by coincidence.

### Sidecar metadata

Each rule ships a sidecar carrying what the Sigma specification does not model: the
detection hypothesis, required logs and channels and fields, field semantics, collection
prerequisites, expected collection gaps, normalization assumptions, ingestion differences,
retention considerations, expected volume, false-positive strategy, tuning guidance, test
strategy, ATT&CK mappings, and backend support.

Sidecars bind by UUID, so renaming a rule file cannot orphan its metadata.

### Deterministic behavioral testing

`sdel-lab-matcher-v1` evaluates a documented Sigma subset with explicit semantics for case
handling, modifiers, and field resolution. Anything outside the subset is `UNSUPPORTED`,
never a pass — and JUnit renders `UNSUPPORTED` as a failure rather than a skip, so a rule
that cannot be evaluated cannot reach a green build.

Negatives outnumber positives roughly three to two, and each negative breaks exactly one
requirement of its rule.

### Correlation

Four types over synthetic sequences: `event_count`, `value_count`, `temporal`,
`temporal_ordered`. Every negative sequence breaks exactly one of ordering, grouping,
threshold, or timespan, so a regression names itself.

### Quality gates

Thirty-one gates spanning structure, identity, authoring convention, metadata, ATT&CK,
fixtures, behaviour, and safety. The governing principle: **absent evidence fails**. A
gate whose evidence was not produced is unproven, and unproven fails — which is why
`--skip-tests` does not produce a green build.

### ATT&CK

36 techniques verified against a vendored ATT&CK Enterprise 19.1 subset. A well-formed
identifier is not accepted as a valid one: `T9999` is rejected because ATT&CK does not
define it. Detection Strategy, Analytic, and Data Component identifiers are recorded only
when present in the pinned extraction; otherwise the arrays stay empty with a stated
reason, and nothing is invented.

### Offline conversion

Splunk SPL and Elasticsearch Lucene via the official pySigma backends. Every query carries
`DEMONSTRATION CONVERSION — ENVIRONMENT-SPECIFIC VALIDATION REQUIRED`.

### Reports

JSON, standalone HTML, SARIF 2.1.0, JUnit XML, CSV, and ATT&CK Navigator layer 4.5. All
derive from one canonical document, so two formats cannot disagree.

SARIF deliberately carries **no** `security-severity` and sets
`isVulnerabilityFinding: false`: these are code-quality findings about detection content,
not vulnerability reports.

### Safety

No network. No host logs. No code execution. Hardened YAML with zero aliases and duplicate
keys rejected. Path containment with symlink refusal. Regex length limits and
catastrophic-pattern rejection. Secret and real-data scanning. HTML, CSV, and XML
injection controls.

## Known limitations

1. The matcher is a documented subset, not a SIEM engine; its semantics may differ from
   vendor backends.
2. Correlation covers four types over in-memory sequences, with no late-arrival,
   watermark, or out-of-order handling.
3. Correlation conversion is unsupported: Splunk declines `temporal_ordered` (3 rules),
   Elasticsearch Lucene declines correlation entirely (6 rules).
4. The vendored ATT&CK subset is deliberately partial.
5. Defensive-object arrays are sparsely populated by design.
6. Coverage counts authored rules, not environmental visibility.
7. Behavioral results are evidence about rule logic, not detection efficacy.
8. Field names follow common Sysmon and Windows Security conventions; real pipelines
   normalize differently.

## Open items carried into 1.0.0

None blocking. The pytest suite and CI workflow alignment noted during documentation
drafting were completed before local packaging.

## Explicitly out of scope

Live SIEM integration and deployment, production log replay, EVTX and PCAP, malware
samples, adversary emulation, cloud provider APIs, machine learning and UBA, YARA and
Suricata, automatic SARIF upload, and SigmaHQ publication.

## Upgrading

First release; nothing to upgrade from. Save your first validation report as a comparison
baseline:

```bash
sigma-detection-lab validate --strict --json-out baseline.json
```

## Verification

```bash
python -m pip install -e ".[dev]"
sigma-detection-lab version --format json
sigma-detection-lab validate --strict
python scripts/run-ci.py
```

Expected: 56 rules, 283 tests passing, 31 gates passing, exit 0.

## Attribution

Independent of SigmaHQ and MITRE. Sigma and SigmaHQ names are the property of their
owners. ATT&CK® is a registered trademark of The MITRE Corporation. No certification or
endorsement is claimed. See [`NOTICE.md`](../NOTICE.md) and
[upstream-attribution](upstream-attribution.md).

## Related documents

[final-release-checklist](final-release-checklist.md) ·
[security-audit-v1.0.0](security-audit-v1.0.0.md) ·
[CHANGELOG](../CHANGELOG.md) ·
[coverage-methodology](coverage-methodology.md)
