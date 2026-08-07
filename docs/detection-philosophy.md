# Detection philosophy

> SYNTHETIC BEHAVIORAL TESTING — NOT A MEASUREMENT OF PRODUCTION DETECTION EFFICACY

This document states the reasoning behind every rule in the catalog. It is the
justification a reviewer should be able to hold a rule against.

## The problem this catalog is arguing about

Detection content usually enters production through prose review. Someone proposes a
rule, someone else reads the YAML, and it ships. That process reliably produces four
failure modes:

1. **Unrunnable rules.** The rule requires a field the environment never collects. It
   sits in the SIEM producing nothing, and its silence is mistaken for the absence of the
   behaviour.
2. **Undefended false positives.** The `falsepositives` block says "Unknown". The first
   analyst to see the alert has no idea whether it is expected, and the rule is disabled
   within a week.
3. **Decorative ATT&CK mapping.** A technique ID is added because it looked right. Nobody
   checked it against the framework, and the coverage dashboard inherits the error.
4. **Unearned status.** `status: stable` is set on content that was never tested against
   anything.

Each of those is a review failure, and review failures are fixed by making the machine do
the review. That is the entire argument of this laboratory.

## Principle 1 — Hypothesis before rule

Every sidecar carries a `detection_hypothesis`: one sentence stating what observable
consequence the adversary behaviour has.

> If an adversary stages tooling in a user-writable directory, the resulting process
> creation event will show an `Image` path rooted in a temporary or public directory
> rather than in a managed installation directory.

The hypothesis is written first because it is falsifiable and the rule is not. A rule is
a pattern; a hypothesis is a claim about the world that a reviewer can dispute. If you
cannot state the hypothesis, you do not yet have a detection — you have a search.

The `detection_hypothesis_exists` gate enforces this mechanically.

## Principle 2 — Behaviour over indicator

The catalog keys on properties that are expensive for an adversary to change:

| Preferred | Avoided |
|---|---|
| Process lineage (`ParentImage` → `Image`) | Specific malware file names |
| Directory writability semantics | Hard-coded hashes |
| Option *combinations* on a signed binary | Single-flag matches |
| Attribute changes on directory objects | Static account names |
| Structural script patterns | Exact script strings |

`SDEL-WIN-002` is a worked example: it fires on an Office-like application spawning a
command interpreter. Renaming the payload does not evade it, because the lineage is the
signal. Compare a hypothetical rule matching `evil.exe`, which a single rename defeats.

This is also why several rules score `medium` rather than `high`. A rule keyed on
behaviour that legitimate software also exhibits is valuable *and* noisy, and the
description says so explicitly rather than inflating the level to attract attention.

## Principle 3 — Negative evidence is evidence

Every standard rule carries at least two positive cases and **three negative cases**, and
every negative case is a **near miss** rather than unrelated noise. Each one breaks
exactly one requirement of the rule.

For `SDEL-WIN-001` the negatives are:

| Case | What it breaks |
|---|---|
| `managed_program_files` | The path prefix is outside every writable selection |
| `allowed_patch_installer` | The path matches, but the approved-installer filter removes it |
| `system_directory_binary` | The system directory is not user-writable |
| `temp_named_subdirectory_elsewhere` | A managed path merely *contains* "Temp"; `startswith` excludes it |

This design has a specific payoff. If someone later changes `startswith` to `contains`,
exactly one case fails and its name says what broke. A suite of unrelated negative noise
would still pass, and the regression would ship.

Correlation negatives follow the same discipline, each breaking exactly one of ordering,
grouping, threshold, or timespan.

## Principle 4 — Telemetry honesty

A rule that cannot run in your environment is worse than no rule, because it consumes
review attention and produces false confidence. Every sidecar therefore states:

- `required_logs`, `required_channels`, `required_fields`
- `collection_prerequisites` — what must be *enabled*, e.g. "Command-line auditing is
  enabled when Security 4688 is the only available source"
- `expected_collection_gaps` — what will be missing anyway, e.g. "Short-lived processes
  may be lost if the agent is restarted"
- `normalization_assumptions` and `ingestion_differences` — how pipelines differ
- `retention_considerations` and `expected_volume` — what it costs to keep

`config/telemetry-catalog.json` holds the profiles, and the `telemetry.py` validator
rejects a sidecar that claims a field no declared source provides. You cannot quietly
require telemetry that does not exist.

See [logsource-and-telemetry](logsource-and-telemetry.md).

## Principle 5 — No unearned confidence

This is the principle with the most mechanical enforcement, because it is the easiest to
violate by accident.

- Sigma `status: stable` is **blocked** in the main catalog. `stable` asserts production
  validation that synthetic telemetry cannot substantiate.
- Only `experimental` and `test` are permitted.
- Sidecar `maturity` is capped at `tested-synthetic`. The vocabulary also defines
  `validated-lab` and `production-observed`, and both are refused, because they would
  require real telemetry this laboratory never handles.
- Precision, recall, and false-positive rate are **not reported**. They cannot be derived
  from fixtures written by the same person who wrote the rules.
- Every artefact carries `NO_PRODUCTION_CLAIM` verbatim.

**A fixture match does not prove compromise.** It proves a generated event satisfied a
written condition. Whether equivalent real activity is malicious depends on context this
laboratory does not have.

## Principle 6 — Tuning is part of the rule

Every sidecar carries `false_positive_strategy` and `tuning_guidance`, and the guidance is
written to preserve detection value:

> Prefer per-binary exclusions anchored on `Image|endswith` plus a signature or hash
> condition. Do not exclude the whole `AppData\Local\Temp` prefix, because that removes
> the detection value of the rule entirely.

The distinction matters. Broad exclusions are how a rule dies quietly: it stays enabled,
reports zero alerts, and everyone assumes the behaviour is absent. Narrow exclusions keep
the rule honest and make the exclusion itself reviewable.

The `specific_falsepositives` gate rejects the exact strings `Unknown`, `Legitimate
activity`, and `Administrator activity`. Each of the three false positives on every rule
names a concrete scenario, an actor, and a reason.

See [false-positive-engineering](false-positive-engineering.md).

## Severity discipline

`level` answers "how urgently should a human look at this?", not "how bad would the
attack be?".

| Level | Used when |
|---|---|
| `informational` | Correlation base rules that are never alerted on directly |
| `low` | Behaviour that is common but worth having in context |
| `medium` | Genuinely suspicious behaviour with well-known benign causes |
| `high` | Behaviour with few benign explanations in a managed estate |
| `critical` | Reserved; used sparingly, and never for volume-based rules |

The catalog leans towards `medium`. That is deliberate. A catalog where everything is
`high` conveys no information.

## What this philosophy explicitly rejects

- **Coverage as a score.** Counting techniques and calling it coverage confuses authored
  content with environmental visibility. See
  [coverage-methodology](coverage-methodology.md).
- **Matching as proof.** A match is an observation, not a conclusion.
- **Conversion as deployment.** A generated SPL or Lucene query is a portability
  demonstration; it still needs field mappings, indexes, permissions, tuning, and
  validation. See [conversion-limitations](conversion-limitations.md).
- **Silence as safety.** A skipped test, a missing backend, or an unsupported construct
  is reported as such and fails the gate that depends on it.

## Related documents

[rule-authoring-guide](rule-authoring-guide.md) ·
[rule-lifecycle](rule-lifecycle.md) ·
[rule-quality-gates](rule-quality-gates.md) ·
[false-positive-engineering](false-positive-engineering.md) ·
[coverage-methodology](coverage-methodology.md)
