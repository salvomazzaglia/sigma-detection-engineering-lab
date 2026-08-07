# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **SYNTHETIC DEMONSTRATION DATA.** No release of this project makes a claim of production
> readiness.

## [Unreleased]

### Fixed

- Documented open items about an empty `tests/` directory and mismatched CI flags were
  closed before the 1.0.0 local packaging commit.

---

## [1.0.0] — 2026-08-07

First release. An offline detection-as-code laboratory for authoring, validating,
behaviorally testing, documenting, mapping, comparing, and converting original Sigma
detection rules against deterministic synthetic telemetry.

### Added — rule catalog

- 56 original Sigma rules: 16 Windows, 10 PowerShell, 12 identity, 12 Linux, 6
  correlation.
- Stable catalog identifiers (`SDEL-WIN`, `SDEL-PS`, `SDEL-ID`, `SDEL-LX`, `SDEL-COR`)
  with UUIDs derived via `uuid5` from the repository URL namespace.
- 56 detection metadata sidecars carrying detection hypothesis, telemetry prerequisites,
  collection gaps, normalization assumptions, ingestion differences, retention
  considerations, false-positive strategy, tuning guidance, ATT&CK mapping, and backend
  support. Sidecars bind to rules by UUID.
- 253 synthetic fixture cases and 30 correlation sequences with per-rule manifests.

### Added — validation

- Hardened YAML loader: depth 32, 5000 nodes, **zero aliases**, 8192-character scalars,
  512-entry mappings and sequences, duplicate keys rejected, custom tags rejected, limits
  enforced during construction.
- Two-stage rule loading: hardened local parse plus pySigma 1.5.0 parse, with pySigma
  treated as optional and its absence reported rather than hidden.
- Specification structure validation, project convention validation, sidecar validation,
  ATT&CK mapping validation, and telemetry requirement validation.
- Secret scanning and non-synthetic data detection over rules and fixtures.
- 31 configurable quality gates. Absent evidence is unproven, and unproven fails.

### Added — behavioral testing

- `sdel-lab-matcher-v1`, a deterministic matcher over a documented Sigma subset:
  `contains`, `startswith`, `endswith`, `re`, `cidr`, `exists`, `all`, `cased`; `and`,
  `or`, `not`, parentheses, named selections, `1 of prefix*`, `all of prefix*`.
- Case-insensitive by default, case-sensitive under `cased`, with the choice recorded in
  `config/evaluator-profile.json`.
- Regex safety: 256-character limit, catastrophic-backtracking rejection.
- Constructs outside the subset report `UNSUPPORTED` and never pass.
- Correlation engine supporting `event_count`, `value_count`, `temporal`, and
  `temporal_ordered`.
- 283 behavioral results, all passing.

### Added — ATT&CK

- Vendored ATT&CK Enterprise 19.1 subset (STIX `ATT&CK-v19.1`, dataset 2026-04-28).
- 36 techniques across 6 tactics, every identifier verified against the vendored catalog.
- Well-formed but undefined identifiers rejected as invented.
- Detection Strategy, Analytic, and Data Component identifiers recorded only when present
  in the pinned extraction, with `unmapped_defensive_objects_reason` required otherwise.
- Legacy Data Sources not used as a primary mapping.
- 19.1 remappings recorded: `T1685.005` superseding `T1070.001`, plus `T1685.006`,
  `T1685`, and `T1686`.

### Added — conversion

- Offline Splunk SPL conversion via `pysigma-backend-splunk` 2.1.0: 53 converted, 3
  unsupported.
- Offline Elasticsearch Lucene conversion via `pysigma-backend-elasticsearch` 2.1.0: 50
  converted, 6 unsupported.
- Every emitted query carries `DEMONSTRATION CONVERSION — ENVIRONMENT-SPECIFIC VALIDATION
  REQUIRED`.
- Correlation conversion marked unsupported for 1.0, with backend reasons reported rather
  than hidden.

### Added — reporting

- Canonical JSON report, schema `sigma-detection-engineering-lab/report/1.0.0`.
- Standalone offline HTML report — no CDN, no script, no external font.
- SARIF 2.1.0 without `security-severity`, with `isVulnerabilityFinding: false` on the run
  and every rule descriptor.
- JUnit XML rendering `UNSUPPORTED` as a failure rather than a skip.
- CSV with formula-injection prefixes neutralised.
- ATT&CK Navigator layer 4.5 containing verified techniques only, scored by rule count.
- Baseline comparison with regression classification and `--fail-on-regression`.

### Added — CLI

- Nine commands: `validate`, `test`, `list-rules`, `explain`, `coverage`, `convert`,
  `compare`, `generate-demo`, `version`.
- Exit codes 0 (success), 1 (analysis failed), 2 (usage error), 3 (refused to run).
- `--strict`, path overrides, profile selection, and five report writers.

### Added — safety

- No network access at runtime; no host log access; no code execution.
- Path containment with symlink refusal, path-length and file-size caps.
- Redaction of credential-shaped strings from reports before writing.
- Sigma `status: stable` blocked; maturity capped at `tested-synthetic`.
- Efficacy metrics refused, with the refusal printed in every coverage artefact.

### Added — project infrastructure

- GitHub Actions CI on Ubuntu and Windows, Python 3.11 and 3.12, with actions pinned to
  full commit SHAs and `permissions: contents: read`.
- Ruff (`E, F, W, I, N, UP, B, C4, SIM, PTH, RUF, S, TID, BLE, DTZ`) and mypy strict.
- JSON Schemas for configuration, sidecars, fixtures, and all report types.
- Deterministic examples: sample rule, sidecar, fixtures, reports in every format, and
  conversions for all 56 rules against both backends.
- Complete documentation set: README with 40 sections plus 30 documents under `docs/`.

### Pinned upstream

| Component | Version |
|---|---|
| Sigma Rules Specification | 2.1.0 (2025-08-02), commit `0c857d07da0e71eaaab2d667b3cce6f2c8469578` |
| pySigma | 1.5.0 |
| pysigma-backend-splunk | 2.1.0 |
| pysigma-backend-elasticsearch | 2.1.0 |
| MITRE ATT&CK Enterprise | 19.1, STIX `ATT&CK-v19.1` |
| ATT&CK Navigator layer format | 4.5 |
| actions/checkout | v7.0.1 (`3d3c42e5aac5ba805825da76410c181273ba90b1`) |
| actions/setup-python | v5.6.0 (`a26af69be951a213d495a4c3e4e4022e16d87065`) |

### Security

- Self-audit recorded in `docs/security-audit-v1.0.0.md`: no real data, no copied upstream
  rules, no unsafe YAML handling, no secrets, no injection paths.
- Threat model recorded in `docs/threat-model.md` covering ten threats with residual-risk
  assessments.

### Not included

Live SIEM integration, deployment, production log replay, EVTX or PCAP handling, malware
samples, adversary emulation, cloud provider APIs, machine learning or UBA, YARA or
Suricata formats, automatic SARIF upload, and SigmaHQ publication.

---

## Change policy

Because this project's output is used to make claims about detection content, some changes
that would normally be minor are treated as significant:

| Change | Requires |
|---|---|
| A new quality gate | Minor version bump and a changelog note — it can turn a green build red |
| Changed matcher semantics | Minor version bump, an evaluator-profile update, and a note — it changes what past results meant |
| A new safety limit or a tightened one | Minor version bump and a note |
| A relaxed safety limit | Major version bump and a recorded justification |
| An ATT&CK dataset update | Minor version bump; may invalidate existing mappings |
| A new backend | Minor version bump |
| Documentation-only changes | Patch version bump |

[Unreleased]: https://github.com/salvomazzaglia/sigma-detection-engineering-lab/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/salvomazzaglia/sigma-detection-engineering-lab/releases/tag/v1.0.0
