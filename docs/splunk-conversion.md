# Splunk conversion

> **DEMONSTRATION CONVERSION — ENVIRONMENT-SPECIFIC VALIDATION REQUIRED**
>
> No SIEM connection is made. Nothing is deployed.

## Backend configuration

```json
"splunk": {
  "enabled": true,
  "package": "pysigma-backend-splunk",
  "version": "2.1.0",
  "backend_class": "sigma.backends.splunk.SplunkBackend",
  "dialect": "spl",
  "pipeline": null,
  "demonstration_banner": "DEMONSTRATION CONVERSION — ENVIRONMENT-SPECIFIC VALIDATION REQUIRED",
  "network": false,
  "deployment": false
}
```

`pipeline: null` is deliberate. A pipeline encodes assumptions about a specific
deployment's field names and index layout, and shipping one would make the output look
more deployable than it is.

## Running it

```bash
sigma-detection-lab convert --backend splunk
sigma-detection-lab convert --backend splunk --output temp/splunk.json
sigma-detection-lab convert --backend splunk --rule SDEL-WIN-001
sigma-detection-lab convert --backend splunk --rules rules/windows
```

Pre-generated output for the whole catalog lives in
`examples/sample-conversions/splunk/`.

## Results

| Outcome | Count |
|---|---|
| Converted | 53 |
| Unsupported | 3 |
| Backend unavailable | 0 |
| Error | 0 |

All three unsupported results are `temporal_ordered` correlation rules:
`SDEL-COR-001`, `SDEL-COR-005`, `SDEL-COR-006`.

```
NotImplementedError: Correlation type 'temporal_ordered' is not supported
```

Notably, the Splunk backend **does** convert `event_count`, `value_count`, and `temporal`
correlations — `SDEL-COR-002`, `SDEL-COR-003`, and `SDEL-COR-004` succeed. Ordered
temporal correlation is the specific gap.

## Example output

`SDEL-WIN-001` — process launched from a user-writable temporary path:

```
DEMONSTRATION CONVERSION — ENVIRONMENT-SPECIFIC VALIDATION REQUIRED
backend=splunk
catalog_id=SDEL-WIN-001
status=converted

Image IN ("C:\\Synthetic\\Users\\synthetic-user\\AppData\\Local\\Temp\\*", "C:\\Synthetic\\Windows\\Temp\\*", "C:\\Synthetic\\Users\\Public\\*") NOT Image="*\\synthetic_patch_installer.exe"
```

Three translation decisions are visible:

1. `Image|startswith` with a value list becomes `Image IN (...)` with trailing wildcards.
2. `not filter_approved_installer` becomes `NOT Image="*\\synthetic_patch_installer.exe"`,
   with `endswith` rendered as a leading wildcard.
3. Backslashes are doubled for SPL string escaping.

## What the query is missing

The output is a **search expression**, not a search. To run it you must add:

```spl
index=<your_index> sourcetype=<your_sourcetype> earliest=-15m latest=now
| search Image IN (...) NOT Image="*\\synthetic_patch_installer.exe"
```

and reconcile the field names. If your deployment normalises to CIM, the mapping is
roughly:

| Rule field | CIM equivalent |
|---|---|
| `Image` | `Processes.process_path` |
| `CommandLine` | `Processes.process` |
| `ParentImage` | `Processes.parent_process_path` |
| `User` | `Processes.user` |
| `TargetFilename` | `Filesystem.file_path` |
| `TargetObject` | `Registry.registry_path` |
| `ScriptBlockText` | *(no standard CIM field)* |

That table is a starting point, not a specification. CIM compliance varies by add-on and
by version, and `ScriptBlockText` in particular has no standard home.

## Semantic differences from the laboratory matcher

| Behaviour | Laboratory matcher | Splunk SPL |
|---|---|---|
| Case sensitivity | Insensitive by default | Field values are generally case-sensitive; field *names* are not |
| Wildcards | Anchored regex translation | `*` inside quoted strings |
| Regex | Python `re` | PCRE-like via `regex`/`rex` |
| Absent vs null | Distinguished | Frequently equivalent |
| `cidr` | Network containment | Requires `cidrmatch()` |
| Numeric comparison | Normalised when both numeric | Type coercion applies |

Case sensitivity is the difference most likely to bite. A path rule that passes here
because the matcher is case-insensitive may miss in Splunk if the indexed value differs in
case from the rule's literal.

## Performance considerations

The generated expressions are unoptimised by design — the backend translates the rule, it
does not tune it. Before scheduling anything derived from them:

- **Put the selective term first.** SPL benefits from narrowing early; `Image IN (...)`
  before a broad `NOT`.
- **Use `tstats` against accelerated data models** for high-volume sources. Process
  creation and file events in particular.
- **Bound the time range explicitly.** An unbounded search over process creation is
  expensive on any estate.
- **Check the sidecar's volume note.** `SDEL-WIN-012` (process access) is flagged very
  high volume and needs scope filters.

## Correlation in Splunk

For the three rules the backend declines, an ordered temporal correlation in SPL is
typically expressed with `transaction` or with `streamstats` plus a window condition.
Neither is generated here, and neither is trivially equivalent to the Sigma semantics
described in [correlation-subset](correlation-subset.md) — particularly around window
boundary inclusivity and grouping on absent fields.

If you implement one, validate it against the same synthetic sequences the laboratory
uses, including the negative sequences that break ordering, grouping, threshold, and
timespan.

## Before you deploy anything

1. Map every field to your schema.
2. Choose the index, sourcetype, and time range.
3. Verify case sensitivity against real indexed values.
4. Test against known-benign data and measure the volume.
5. Apply the tuning guidance from the sidecar — per-binary exclusions, not directory
   exclusions.
6. Confirm the required telemetry is actually collected; see
   [logsource-and-telemetry](logsource-and-telemetry.md).
7. Re-validate the rule's intent against your results. **Conversion is not validation.**

## Related documents

[conversion-limitations](conversion-limitations.md) ·
[elasticsearch-conversion](elasticsearch-conversion.md) ·
[tuning-and-deployment](tuning-and-deployment.md) ·
[logsource-and-telemetry](logsource-and-telemetry.md)
