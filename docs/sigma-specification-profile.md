# Sigma specification profile

> This project is independent of SigmaHQ. It uses the official specification and the
> official pySigma packages, and claims no endorsement or certification.

## Pinned specification

| Item | Value |
|---|---|
| Sigma Rules Specification | **2.1.0**, released 2025-08-02 |
| Source | `https://github.com/SigmaHQ/sigma-specification` |
| Tag | `v2.1.0` |
| Commit | `0c857d07da0e71eaaab2d667b3cce6f2c8469578` |
| Correlation specification | 2.1.0 (documented subset only) |
| Reference implementation | pySigma **1.5.0** |
| Verification date | 2026-08-07 |

Recorded in `config/upstream-versions.json` and reported by `sigma-detection-lab version`.

## Two levels of conformance

This distinction runs through the whole project and is worth stating plainly.

**Level 1 — Specification conformance.** Every rule must be a valid Sigma 2.1.0 rule.
This is checked by pySigma itself, not by this project's opinion of the specification.

**Level 2 — Evaluator subset.** The laboratory's own deterministic matcher,
`sdel-lab-matcher-v1`, implements a *subset*. A rule can be perfectly valid Sigma and
still fall outside the subset, in which case behavioral testing reports `UNSUPPORTED`.

A rule must pass Level 1. Rules in the main catalog are also written to stay inside Level
2, because `UNSUPPORTED` results fail the `unsupported_not_counted_as_pass` gate.

## How specification conformance is checked

`rule_loader.py` performs a two-stage load:

1. The hardened YAML loader (`yaml_loader.py`) parses the file under strict structural
   limits, producing plain Python data.
2. `SigmaCollection.from_yaml()` parses the same text, and any `errors` attached to the
   resulting rules are collected as findings.

Asking pySigma directly matters: it means the project cannot drift into accepting a rule
that upstream tooling would reject. The `pysigma_parse` gate covers this.

### When pySigma is absent

pySigma is an optional import at runtime. If it cannot be imported, `pysigma_status()`
records why, and the loader reports:

> pySigma is not installed; upstream specification parsing was not performed. Install the
> pinned dependencies to enable it.

The run continues with YAML-level validation. Nothing pretends the upstream parse
succeeded, and the `pysigma_parse` gate is unproven rather than passing.

## Rule fields recognised by the loader

```
title, id, name, related, status, description, references, author, date, modified,
tags, logsource, detection, fields, falsepositives, level, license, correlation, scope
```

An unrecognised top-level key is a **load error**, not a warning. A typo like `logsouce`
would otherwise produce a rule with no logsource that still parsed, which is exactly the
failure mode this project exists to prevent.

## Status vocabulary

The specification defines five statuses. This project restricts them:

| Status | Main catalog | Reason |
|---|---|---|
| `experimental` | Allowed | The default for new content |
| `test` | Allowed | Content with complete synthetic evidence |
| `stable` | **Blocked** | Asserts production validation that synthetic telemetry cannot substantiate |
| `deprecated` | Retired area only | Historical content |
| `unsupported` | Retired area only | Historical content |

`block_stable_status` is a dedicated gate rather than a case inside
`status_experimental_or_test`, because it is the single most consequential restriction in
the project and deserves its own line in the report.

## Maturity: a separate, laboratory-local vocabulary

Sigma `status` describes the rule's place in the upstream lifecycle. Sidecar `maturity`
describes **how much evidence backs it**, which the specification does not model.

| Maturity | Meaning | Allowed here |
|---|---|---|
| `draft` | Authored, not yet reviewed | No (main catalog) |
| `experimental` | Reviewed, partial evidence | Yes |
| `tested-synthetic` | Complete synthetic positive and negative evidence | Yes |
| `validated-lab` | Validated against a real instrumented lab | **No** |
| `production-observed` | Observed working in production | **No** |
| `deprecated` | Retired | Retired area only |

`validated-lab` and `production-observed` are refused by `maturity_allowed` because they
would require real telemetry this laboratory never handles. The ceiling is structural,
not aspirational.

## Logsource taxonomy

Restricted by `config/allowed-taxonomy.json`:

- **Products:** `linux`, `windows`
- **Categories:** `file_event`, `process_access`, `process_creation`, `ps_script`,
  `registry_set`, `wmi_event`
- **Services:** `auth`, `security`, `system`

A logsource outside this set fails `valid_logsource`. Restricting the taxonomy is what
lets `config/telemetry-catalog.json` describe every source the catalog uses in real
detail rather than in generalities.

## Tag taxonomy

- **Tactic tags** use the current hyphenated form: `attack.defense-evasion`,
  `attack.command-and-control`. The older underscore form is not used.
- **Technique tags** use the lowercase identifier: `attack.t1059.001`.
- Sigma tags never carry Detection Strategy, Analytic, or Data Component identifiers.
  Those live in the sidecar only, where their provenance can be stated.

Both `valid_attack_tags` (shape and allowlist) and `verified_attack_technique_ids`
(existence in the vendored catalog) apply. See [attack-mapping](attack-mapping.md).

## Field modifiers

| Modifier | Supported | Semantics in this laboratory |
|---|---|---|
| `contains` | Yes | Substring, case-insensitive by default |
| `startswith` | Yes | Prefix, case-insensitive by default |
| `endswith` | Yes | Suffix, case-insensitive by default |
| `re` | Yes | Python `re`, ≤256 characters, backtracking-safe |
| `cidr` | Yes | IPv4/IPv6 network containment |
| `exists` | Yes | Field presence, independent of value |
| `all` | Yes | Every listed value must match |
| `cased` | Yes | Forces case-sensitive comparison |
| `base64`, `base64offset` | No | Would require decoding synthetic placeholders that decode to nothing |
| `utf16`, `wide` | No | Encoding transforms are outside the subset |
| `gt`, `gte`, `lt`, `lte` | No | Numeric comparison is not implemented |
| `expand` | No | Requires placeholder resolution against a pipeline |
| Unknown modifiers | No | Rejected explicitly rather than ignored |

Rejecting an unknown modifier rather than ignoring it is a deliberate safety property: an
ignored modifier silently broadens a rule.

## Correlation

The specification's correlation rules are supported in a documented subset:
`event_count`, `value_count`, `temporal`, `temporal_ordered`. See
[correlation-subset](correlation-subset.md).

## Interpretation choices

Where the specification permits latitude, this project makes an explicit choice and
records it in `config/evaluator-profile.json`.

| Question | Choice | Rationale |
|---|---|---|
| Default case sensitivity | Insensitive | Matches how most Windows-focused backends behave |
| Case sensitivity under `cased` | Sensitive | The modifier's purpose |
| Null vs absent field | Distinguished; `exists` tests presence | A field present-but-null is a real, different signal |
| List under a field | Implicit OR | Specification default |
| Multiple keys in one selection | Implicit AND | Specification default |
| Numeric vs string comparison | String-normalised unless both sides are numeric | Pipelines vary in whether `EventID` is `4625` or `"4625"` |
| Regex flavour | Python `re` | The implementation language; may differ from vendor engines |

The profile states it directly: *"Lab semantics are explicit and may differ from vendor
backends."* That difference is the reason converted queries need environment-specific
validation.

## What conformance does not buy you

Passing Level 1 and Level 2 means the rule is well-formed and its logic behaves as
written against synthetic events. It does not mean the rule is effective, tolerable at
production volume, or correct against real telemetry. See
[behavioral-testing](behavioral-testing.md) and
[coverage-methodology](coverage-methodology.md).

## Related documents

[sigma-condition-subset](sigma-condition-subset.md) ·
[correlation-subset](correlation-subset.md) ·
[behavioral-testing](behavioral-testing.md) ·
[upstream-attribution](upstream-attribution.md)
