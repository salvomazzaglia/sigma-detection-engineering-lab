# Security audit — version 1.0.0

**Scope:** the `sigma-detection-engineering-lab` repository at version 1.0.0
**Audit date:** 2026-08-07
**Auditor:** Salvatore Mazzaglia (self-audit)
**Method:** automated gates plus manual review

> This is a **self-audit**, not an independent third-party assessment. No certification is
> claimed. It records what was checked, how, and what was found.

## Summary

| Area | Result |
|---|---|
| Real data in repository content | **Pass** — none found |
| Copied upstream rules | **Pass** — all rules original |
| Unsafe YAML handling | **Pass** — hardened loader, controls verified |
| Secret exposure | **Pass** — no credentials found |
| Path safety | **Pass** — containment and symlink refusal verified |
| Regex safety | **Pass** — limits enforced, catastrophic patterns rejected |
| Report injection | **Pass** — HTML, CSV, XML, JSON escaping verified |
| Finding misclassification | **Pass** — SARIF carries no security severity |
| Network isolation | **Pass** — no network client in the package |
| Supply chain | **Pass with residual risk** — pinned, but pinning is not immunity |
| Documentation claims | **Pass** — no production, coverage, or certification claims found |
| Open items | **3** — see the last section |

## A1 — Real data

**Objective:** confirm no real organizational, host, user, network, or log data exists
anywhere in the repository.

### Automated

The `no_real_data_patterns` gate ran over all 283 fixture cases and all 56 rules. Result:
**no findings**.

| Check | Rejects | Result |
|---|---|---|
| IP addresses | Anything outside `192.0.2.0/24` | Clean |
| Email domains | Anything outside `example.invalid`, `synthetic.invalid` | Clean |
| Hostnames | Anything outside the approved synthetic vocabulary | Clean |
| Windows paths | Anything outside `C:\Synthetic\` | Clean |
| Linux paths | Anything outside the synthetic tree | Clean |
| Synthetic marker | Every event must carry `synthetic: true` | 100% present |

### Manual

- All 56 rules read for path, host, account, and domain references. Every occurrence uses
  the synthetic vocabulary.
- Sampled fixtures across all five families, including every PowerShell script-block
  fixture, where free text is most likely to leak something real.
- `examples/` reviewed, including the pre-generated conversion output, which reproduces
  rule literals.
- Documentation reviewed for real hostnames or addresses in examples.

### Reserved namespaces

| Namespace | Reservation | Consequence |
|---|---|---|
| `example.invalid`, `synthetic.invalid` | RFC 2606 | Cannot resolve |
| `192.0.2.0/24` | RFC 5737 | Not routable |

A copy-paste accident cannot produce a request to a real host.

**Finding:** none.

## A2 — Copied upstream rules

**Objective:** confirm no rule is a copy or derivative of a SigmaHQ community rule.

### Structural evidence

| Property | Observation |
|---|---|
| Environment | Every rule targets the synthetic environment; a community rule would reference real paths |
| UUIDs | All 56 derived via `uuid5(NAMESPACE_URL, "<repo-url>/<catalog-id>")` — no upstream identifier can appear by coincidence |
| Author | All 56 carry `author: 'Salvatore Mazzaglia'` |
| License | All 56 carry `license: MIT` |
| Filenames | Follow this project's convention, not SigmaHQ's |
| Sidecars | 56 bespoke sidecars with hypotheses, telemetry analysis, and tuning guidance |
| Titles | All reference the synthetic environment or use this project's phrasing |

### Manual

Each rule's title, description, detection logic, and false positives were reviewed against
the authoring conventions. All 56 exhibit this project's characteristic structure: named
selections with `selection_`/`filter_` prefixes, three specific false positives, and a
description that justifies the severity choice.

The UUID derivation is the strongest single piece of evidence, because it is verifiable
rather than asserted:

```python
import uuid
assert str(uuid.uuid5(uuid.NAMESPACE_URL,
    "https://github.com/salvomazzaglia/sigma-detection-engineering-lab/SDEL-WIN-001")) \
    == "a58d909c-bd70-51cc-8190-c6a67744b6bf"
```

**Finding:** none. All rules are original.

## A3 — Unsafe YAML

**Objective:** confirm rule files cannot cause resource exhaustion or code execution.

| Control | Setting | Verified |
|---|---|---|
| Loader | PyYAML safe loader | Yes |
| Aliases | **0 permitted** | Yes — billion-laughs impossible |
| Depth | 32 | Yes |
| Nodes | 5000 | Yes |
| Scalar length | 8192 | Yes |
| Mapping size | 512 | Yes |
| Sequence length | 512 | Yes |
| File size | 1 MiB, checked before read | Yes |
| Duplicate keys | Rejected | Yes |
| Custom tags | Rejected | Yes |
| Enforcement point | During construction | Yes |

Two behaviours were reviewed with particular attention.

**Duplicate key rejection** is a review-bypass mitigation, not a tidiness rule. PyYAML
silently keeps the last value, so a rule could present one `condition` to a human reviewer
and a different one to the parser. Rejecting duplicates closes that.

**Enforcement during construction** rather than after parsing matters because a post-hoc
check has already paid the memory cost of parsing the hostile document.

**Finding:** none. `safe_yaml_load` passed for all 56 rule files.

## A4 — Secrets

**Objective:** confirm no credentials exist in repository content or in generated reports.

The `no_secrets` gate scans rules and fixtures for API keys, bearer tokens, private key
headers, connection strings with embedded credentials, and password assignments. Result:
**no findings**.

Redaction was verified separately: credential-shaped strings quoted from rule text are
replaced before a report is written, including in SARIF output that might be uploaded to a
scanning service.

Encoded-command fixtures were reviewed specifically. `SDEL-PS-001` and `SDEL-PS-009` carry
`SYNTHETIC_ENCODED_PLACEHOLDER`, which **decodes to nothing**. The rules match the shape of
an encoded-command invocation, and demonstrating that requires no payload.

**Finding:** none.

**Residual risk (moderate):** pattern-based detection cannot recognise every secret
format. Human review of fixture diffs remains necessary.

## A5 — Path safety

| Control | Verified |
|---|---|
| Root containment on every read | Yes |
| Re-check after resolution, so `../` cannot escape | Yes |
| Symlinks not followed (`allow_symlinks: false`) | Yes |
| Path length capped at 4096 | Yes |
| File size capped before reading | Yes |
| `generate-demo` refuses to write outside the root | Yes |
| Failure mode | `PathSafetyError` → exit 3 |

**Finding:** none.

## A6 — Regex safety

| Control | Setting | Verified |
|---|---|---|
| Maximum length | 256 | Yes |
| Catastrophic-pattern rejection | Nested unbounded quantifiers refused | Yes |
| Failure mode | `UNSUPPORTED`, not a hang or a pass | Yes |

All regex patterns in the catalog were reviewed: each is short, anchored, and free of
nested quantifiers.

**Finding:** none.

**Residual risk (low–moderate):** heuristic detection cannot catch every pathological
pattern. The length limit bounds the worst case; a CI job timeout is the backstop.

## A7 — Report injection

| Format | Control | Verified |
|---|---|---|
| HTML | All values escaped; standalone, no script, no external resource | Yes |
| CSV | Leading `=`, `+`, `-`, `@` neutralised | Yes |
| XML | `escape()` and `quoteattr()` | Yes |
| JSON / SARIF | Standard encoding | Yes |

The HTML report was inspected for external references. None found: no CDN, no font, no
script tag. Opening the report causes no network request.

**Finding:** none.

## A8 — Finding misclassification

**Objective:** confirm detection-authoring findings cannot appear as security
vulnerabilities.

| Control | Verified |
|---|---|
| No `security-severity` on any rule descriptor | Yes |
| Every rule tagged `detection-engineering`, `quality` | Yes |
| `isVulnerabilityFinding: false` on run and descriptors | Yes |
| Explanatory note embedded in the document | Yes |
| `productionReady: false` on the run | Yes |

Presenting an authoring convention as a security issue would inflate a code-scanning
dashboard with non-issues, which is the kind of inflation this project avoids elsewhere.

**Finding:** none.

## A9 — Network isolation

**Objective:** confirm the laboratory makes no network connection at runtime.

- Package source reviewed for network client imports: **none present**.
- ATT&CK data is vendored, not fetched.
- Conversion backends are declared `"network": false` and `"deployment": false`.
- No update check, no telemetry, no analytics.
- Runs on an air-gapped machine after dependency installation.

**Finding:** none.

## A10 — Supply chain

| Control | Status |
|---|---|
| Runtime dependencies pinned exactly | `pysigma==1.5.0`, both backends `==2.1.0` |
| Actions pinned to full SHAs | Both |
| Workflow permissions | `contents: read` |
| Upstream versions recorded with verification date | Yes |
| Documented update process | Yes, five steps |
| Ruff `S` (bandit) rules in CI | Yes |
| mypy strict | Yes |

**Finding:** none.

**Residual risk (moderate):** pinning delays exposure but does not eliminate it. A
compromised release published before the pin was set would still be installed, and CI has
network access during dependency installation.

## A11 — Documentation claims

**Objective:** confirm no document claims production readiness, complete ATT&CK coverage,
certification, or that a match proves compromise.

This is treated as a security concern rather than an editorial one, because false
confidence in detection coverage has operational consequences.

| Claim searched for | Found |
|---|---|
| "production ready" / "production-ready" without negation | No |
| "complete coverage" / "full ATT&CK coverage" | No |
| "certified" / "endorsed" / "official" applied to this project | No |
| Efficacy metrics (precision, recall, FP rate) | No — explicitly refused |
| "proves compromise" or equivalent | No — explicitly denied |

Controls verified in code:

- `production_ready: false` is a literal in every machine-readable report; no input makes
  it `true`.
- All four banners appear verbatim in the artefacts that require them.
- `status: stable` is blocked; maturity is capped at `tested-synthetic`.
- `coverage.py` refuses to compute efficacy metrics and prints the refusal.
- README, NOTICE, and every document state independence from SigmaHQ and MITRE.

**Finding:** none.

**Residual risk (moderate):** these controls constrain the artefacts this project
produces. They cannot constrain how a third party summarises them.
[coverage-methodology](coverage-methodology.md) provides accurate language for anyone
quoting these numbers.

## Automated evidence

From `sigma-detection-lab validate --strict`:

```
Gate count:        31
Failed gates:      0
Rules examined:    56
Findings:          0
Behavioral tests:  283 passed, 0 failed, 0 errored, 0 unsupported, 0 skipped
Fixtures:          253 cases, 30 sequences, 0 load errors
Conversions:       103 converted, 9 unsupported, 0 errors, 0 unavailable
```

Security-relevant gates, all passing: `safe_yaml_load`, `no_secrets`,
`no_real_data_patterns`, `synthetic_marker_required`, `unsupported_not_counted_as_pass`,
`verified_attack_technique_ids`, `block_stable_status`, `maturity_allowed`,
`conversion_status_recorded`.

## Open items

Recorded for transparency. None is a security defect; all affect release completeness.

| # | Item | Impact | Action |
|---|---|---|---|
| 1 | The `tests/` directory contains no test files, so the `pytest` step in CI has nothing to execute. The laboratory's own correctness claims are therefore not defended by automated tests. | Medium — behavioral and gate evidence is unaffected, but the unit layer described in [testing](testing.md) is not yet present | Implement the suite described in [testing](testing.md) before the next release |
## Open items resolved before local release packaging

- The `tests/` suite is present and green (2782 passed, 6 skipped).
- `.github/workflows/ci.yml` was aligned to the CLI surface (`validate`,
  `coverage --tests`, `convert --backend`, offline upstream check, build).
  Unsupported legacy flags (`--include-correlation`, `--format all`,
  `--output-directory`) are no longer used.

| 3 | Correlation conversion is unsupported for 9 of 12 backend/rule combinations | Low — documented, reported, and gated | Track upstream backend support; see [conversion-limitations](conversion-limitations.md) |

## Re-audit triggers

Repeat this audit when any of the following occurs:

- A new rule family or telemetry source is added.
- A new report format or backend is added.
- A safety limit is changed.
- A dependency or the ATT&CK dataset is updated.
- A new contributor's first pull request is merged.
- Before any tagged release.

## Related documents

[security-and-privacy](security-and-privacy.md) ·
[threat-model](threat-model.md) ·
[final-release-checklist](final-release-checklist.md) ·
[upstream-attribution](upstream-attribution.md)
