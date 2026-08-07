# Correlation subset

Six correlation rules (`SDEL-COR-001` … `SDEL-COR-006`) exercise the Sigma Correlation
Rules Specification 2.1.0 subset implemented by `correlation_engine.py`.

> SYNTHETIC BEHAVIORAL TESTING — NOT A MEASUREMENT OF PRODUCTION DETECTION EFFICACY

## Supported correlation types

| Type | Question it answers |
|---|---|
| `event_count` | Did at least *N* matching events occur in the window, grouped by the given fields? |
| `value_count` | Did at least *N* **distinct** values of a field appear in the window? |
| `temporal` | Did all referenced base rules fire in the window, in any order? |
| `temporal_ordered` | Did all referenced base rules fire in the window, **in the declared order**? |

Declared in `config/evaluator-profile.json` under `correlation_supported_types` and in
`config/allowed-taxonomy.json` under `allowed_correlation_types`.

## File layout

Base rules and the correlation rule live in one multi-document YAML file. The correlation
document is the **primary** rule — it carries the identity the catalog tracks — and the
base rules are supporting documents in the same file.

```yaml
title: 'Windows Logon Failure (Correlation Input)'
id: b659e109-4522-5d95-a665-0104622f6ff0
name: sdel_cor_001_windows_logon_failure
status: experimental
level: informational
logsource:
    product: windows
    service: security
detection:
    selection_logon_failure:
        EventID: 4625
    condition: selection_logon_failure
# ... falsepositives, references, tags ...
---
title: 'Windows Logon Success (Correlation Input)'
name: sdel_cor_001_windows_logon_success
# ... EventID: 4624 ...
---
title: 'Authentication Failures Followed By A Successful Logon'
id: 0f097239-cd26-5f9d-b6a5-d091141f6a15
status: experimental
correlation:
    type: temporal_ordered
    rules:
        - sdel_cor_001_windows_logon_failure
        - sdel_cor_001_windows_logon_success
    group-by:
        - TargetUserName
    timespan: 15m
level: medium
license: MIT
```

Structural rules enforced by `rule_loader.py`:

- **Exactly one** correlation document per file. Two would make the file's identity
  ambiguous.
- Multi-document files are permitted **only** for correlation rules.
- Base rules are resolved by `name` or by `id`, so a correlation `rules:` entry can use
  either.
- Base rules are scored `informational` and are never alerted on directly. Their
  `falsepositives` say so explicitly: *"All normal interactive and network logons across
  the estate, which is why this base rule is never alerted on directly."*

## Semantics

### Timespan

`timespan` accepts the Sigma suffixes `s`, `m`, `h`, `d`. The window is a **sliding
window anchored on the first contributing event** and is **inclusive of both endpoints**:
an event exactly `timespan` after the anchor is inside the window. The choice is stated
here because "15m" is otherwise ambiguous at the boundary, and one of the negative
sequences for each temporal rule tests exactly that edge.

### Grouping

`group-by` partitions events before evaluation. Every listed field must be present on an
event for it to join a group; an event missing a grouping field cannot contribute. This
prevents a null-keyed bucket from silently accumulating unrelated activity —
`SDEL-COR-002` groups by source address, and an event with no source address genuinely
belongs to no group.

### Ordering

- `temporal` requires every referenced base rule to have fired at least once in the
  window, in **any** order.
- `temporal_ordered` requires the **first** matching occurrence of each base rule to
  appear in the declared sequence. Interleaved unrelated events do not break the order;
  reversed base-rule occurrences do.

Ordering uses `timestamp_utc`. Events with identical timestamps are ordered by their
position in the fixture file, which keeps evaluation deterministic.

### Counting

- `event_count` counts **matching events** per group.
- `value_count` counts **distinct values** of the named field per group.
- Both use a `>= N` threshold in this implementation. Sigma allows other comparison
  operators; only `gte` semantics are implemented, and a rule requesting anything else is
  reported `UNSUPPORTED`.

## The catalog's six correlation rules

| ID | Type | Behaviour | Technique |
|---|---|---|---|
| `SDEL-COR-001` | `temporal_ordered` | Authentication failures followed by a successful logon for the same account | T1110.001 |
| `SDEL-COR-002` | `value_count` | Failures across multiple distinct accounts from one source | T1110.003 |
| `SDEL-COR-003` | `event_count` | Repeated Kerberos pre-authentication failures for one account | T1110.001 |
| `SDEL-COR-004` | `event_count` | Burst of privileged group membership changes by one subject | T1098 |
| `SDEL-COR-005` | `temporal_ordered` | Service creation followed by execution of the same binary | T1543.003 |
| `SDEL-COR-006` | `temporal_ordered` | Executable written to a temporary path and then executed | T1105, T1204.002 |

`SDEL-COR-001` and `SDEL-COR-002` are a deliberate contrast: the same raw telemetry, one
asking "did guessing eventually succeed for this account?" and the other "is one source
touching many accounts?". Password spraying looks unremarkable to the first and obvious to
the second.

## Fixture design

Correlation fixtures live in `fixtures/correlation/<catalog-id>/` and follow the same
positive/negative layout, but each case is a **sequence** of events rather than a single
event. Minimums: **two positive and two negative sequences**, checked by
`minimum_positive_sequences_correlation` and
`minimum_negative_sequences_correlation`. Sequence length is capped by
`max_correlation_sequence_events` (100).

Every negative sequence breaks **exactly one** of four things:

| Broken property | What the sequence looks like |
|---|---|
| **Ordering** | The right events, in the wrong order — success before failure |
| **Grouping** | The right events in the right order, but for different accounts or sources |
| **Threshold** | One event short of the required count |
| **Timespan** | The right events in the right order, one minute outside the window |

That one-property-per-case discipline is what makes a regression diagnosable. If window
arithmetic breaks, the timespan negatives fail and the ordering negatives still pass, and
the failure names itself.

## Conversion is not supported in 1.0

Correlation rules are marked unsupported for backend conversion, and the failures are
reported rather than hidden:

| Backend | Result | Backend message |
|---|---|---|
| `splunk` | 3 of 6 unsupported | `NotImplementedError: Correlation type 'temporal_ordered' is not supported` |
| `elasticsearch-lucene` | 6 of 6 unsupported | `NotImplementedError: Backend does not support correlation rules.` |

`config/conversion-backends.json` states the policy: *"Correlation rules are marked
unsupported for conversion in v1.0 unless a backend conversion succeeds; failures must be
visible."* The `conversion_status_recorded` gate requires every attempt to end in a
recorded status, so a silent conversion failure cannot pass.

See [conversion-limitations](conversion-limitations.md).

## Deliberate limitations

The engine evaluates a bounded, in-memory sequence supplied by a fixture. It therefore
does **not** model:

- late-arriving or out-of-order ingestion, watermarks, or grace periods;
- streaming state, checkpointing, or restart semantics;
- deduplication of repeated identical events;
- cross-index or cross-sourcetype joins;
- backpressure, sampling, or ingestion lag.

A production correlation engine has to handle all of these, and each one changes the
result. Correlation results here are evidence about **the rule's logic**, not about how
that logic would behave against a live stream.

## Related documents

[sigma-condition-subset](sigma-condition-subset.md) ·
[behavioral-testing](behavioral-testing.md) ·
[synthetic-event-model](synthetic-event-model.md) ·
[conversion-limitations](conversion-limitations.md)
