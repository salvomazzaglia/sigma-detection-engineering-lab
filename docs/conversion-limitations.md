# Conversion limitations

> **DEMONSTRATION CONVERSION — ENVIRONMENT-SPECIFIC VALIDATION REQUIRED**

Conversion in this laboratory demonstrates **portability**. It does not produce a
deployable artefact, and this document explains precisely why.

## What conversion does

`conversion.py` loads the official pySigma backends offline and asks them to translate
each rule into a backend query. Every emitted query carries the demonstration banner and
its conversion status. Nothing connects to a SIEM; `config/conversion-backends.json`
records `"network": false` and `"deployment": false` for each backend.

## Results for the 1.0.0 catalog

| Backend | Package | Dialect | Converted | Unsupported |
|---|---|---|---|---|
| `splunk` | `pysigma-backend-splunk` 2.1.0 | `spl` | 53 / 56 | 3 |
| `elasticsearch-lucene` | `pysigma-backend-elasticsearch` 2.1.0 | `lucene` | 50 / 56 | 6 |

All nine unsupported results are correlation rules. Splunk declines `temporal_ordered`;
the Elasticsearch Lucene backend declines correlation rules outright.

## The five gaps between a query and a detection

### 1. Field mapping

A converted query references the field names the rule uses — `Image`, `TargetObject`,
`ScriptBlockText`. Your index almost certainly calls them something else:
`process.executable`, `registry.path`, `powershell.file.script_block_text`. Without a
pipeline that performs the mapping, the query is syntactically valid and matches nothing.

pySigma supports processing pipelines for exactly this. This laboratory configures none
(`"pipeline": null` for both backends), because a pipeline encodes assumptions about a
specific deployment, and shipping one would silently make the output look more deployable
than it is.

### 2. Index and sourcetype selection

The queries carry no `index=`, no `sourcetype=`, and no Elasticsearch index pattern. Where
the data lives is a deployment decision. A query run against the wrong index returns
nothing and looks like an absence of the behaviour.

### 3. Time range

Sigma rules describe conditions, not windows. A converted query needs an earliest and
latest bound supplied by whatever schedules it. For correlation this is more than a
convenience — the rule's `timespan` has to be reconciled with the scheduler's interval,
and the two disagreeing is a common source of missed detections.

### 4. Permissions and quotas

Running a query requires role assignment, index permissions, and search-head or cluster
capacity. A rule that is cheap in a laboratory can be expensive at production volume; the
sidecar's `expected_volume` and `retention_considerations` are the inputs to that
judgement.

### 5. Semantic differences

This is the subtle one. The laboratory's matcher, the Splunk backend, and the Lucene
backend do not agree in every case.

| Behaviour | `sdel-lab-matcher-v1` | Splunk SPL | Lucene |
|---|---|---|---|
| Default case sensitivity | Insensitive | Field- and configuration-dependent | Analyzer-dependent |
| Regex flavour | Python `re` | PCRE-like | Lucene regex, no lookaround |
| Wildcard semantics | Anchored translation | `*` in quoted strings | Escaping differs, especially for backslashes |
| Absent vs null field | Distinguished | Often equivalent | Depends on mapping |
| Numeric vs string | Normalised when both numeric | Type coercion applies | Mapping-dependent |

`config/evaluator-profile.json` states it plainly: *"Lab semantics are explicit and may
differ from vendor backends."* A rule that passes behavioral testing may therefore behave
differently once converted — not because the conversion is wrong, but because the engines
are different.

## Correlation conversion

`config/conversion-backends.json`:

```json
"correlation_conversion": {
  "supported_in_v1": false,
  "notes": "Correlation rules are marked unsupported for conversion in v1.0 unless a backend conversion succeeds; failures must be visible."
}
```

The backend messages are reported verbatim:

```
SDEL-COR-001 unsupported
  correlation conversion is not supported in v1.0 and the backend declined the rule:
  NotImplementedError: Correlation type 'temporal_ordered' is not supported

SDEL-COR-002 unsupported  (elasticsearch-lucene)
  NotImplementedError: Backend does not support correlation rules.
```

**Failures must be visible.** The `conversion_status_recorded` gate requires every attempt
to end in a recorded status, so a silent failure cannot pass. The gate passes with nine
unsupported results because it checks that outcomes were recorded, not that they were
successful.

## Conversion status vocabulary

| Status | Meaning |
|---|---|
| `converted` | The backend produced a query |
| `unsupported` | The backend declined the rule; the reason is recorded |
| `backend_unavailable` | The backend package is not installed |
| `error` | Conversion raised unexpectedly; the exception is recorded |
| `skipped` | Excluded by `--rule` or `--backend` filters |

`backend_unavailable` is a distinct status precisely so a missing package cannot be
mistaken for an unsupported rule. Different problem, different fix.

## Output format

```
DEMONSTRATION CONVERSION — ENVIRONMENT-SPECIFIC VALIDATION REQUIRED
backend=splunk
catalog_id=SDEL-WIN-001
status=converted

Image IN ("C:\\Synthetic\\Users\\synthetic-user\\AppData\\Local\\Temp\\*", "C:\\Synthetic\\Windows\\Temp\\*", "C:\\Synthetic\\Users\\Public\\*") NOT Image="*\\synthetic_patch_installer.exe"
```

The banner is part of the artefact, not a wrapper the tool prints around it. Copying the
query out of the file separates it from its warning, which is one reason
[tuning-and-deployment](tuning-and-deployment.md) exists.

## Using conversion output responsibly

**Do:**

- Use it to check that a rule's logic survives translation.
- Use it as a starting point for a query you will then map, scope, and validate.
- Compare Splunk and Lucene output to spot rules whose semantics are backend-sensitive.
- Keep the banner attached.

**Do not:**

- Deploy a query directly from this repository.
- Present converted output as evidence a detection works.
- Assume matching semantics across engines.
- Strip the disclaimer.

## Adding a backend

1. Add the entry to `config/conversion-backends.json` with the package, version, backend
   class, dialect, and demonstration banner.
2. Add the pinned package to `pyproject.toml` and `config/upstream-versions.json`.
3. Confirm the backend runs entirely offline.
4. Record which rules it declines, and why, in a backend-specific document.
5. Update `CHANGELOG.md`.

Do not add a backend that requires network access at conversion time. Offline operation is
a structural property of this laboratory, not a default that can be relaxed.

## Related documents

[splunk-conversion](splunk-conversion.md) ·
[elasticsearch-conversion](elasticsearch-conversion.md) ·
[tuning-and-deployment](tuning-and-deployment.md) ·
[correlation-subset](correlation-subset.md)
