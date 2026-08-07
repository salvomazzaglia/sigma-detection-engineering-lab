# Elasticsearch conversion

> **DEMONSTRATION CONVERSION — ENVIRONMENT-SPECIFIC VALIDATION REQUIRED**
>
> No SIEM connection is made. Nothing is deployed.

## Backend configuration

```json
"elasticsearch-lucene": {
  "enabled": true,
  "package": "pysigma-backend-elasticsearch",
  "version": "2.1.0",
  "backend_class": "sigma.backends.elasticsearch.LuceneBackend",
  "dialect": "lucene",
  "pipeline": null,
  "demonstration_banner": "DEMONSTRATION CONVERSION — ENVIRONMENT-SPECIFIC VALIDATION REQUIRED",
  "network": false,
  "deployment": false
}
```

The Lucene dialect is used rather than ES|QL, EQL, or the DSL. Lucene query strings are
the most portable of the four and the least dependent on a specific stack version, which
suits a portability demonstration.

## Running it

```bash
sigma-detection-lab convert --backend elasticsearch-lucene
sigma-detection-lab convert --backend elasticsearch-lucene --output temp/es.json
sigma-detection-lab convert --backend elasticsearch-lucene --rule SDEL-LX-006
```

Pre-generated output for the whole catalog lives in
`examples/sample-conversions/elasticsearch/`.

## Results

| Outcome | Count |
|---|---|
| Converted | 50 |
| Unsupported | 6 |
| Backend unavailable | 0 |
| Error | 0 |

All six unsupported results are the correlation rules `SDEL-COR-001` … `SDEL-COR-006`:

```
NotImplementedError: Backend does not support correlation rules.
```

Unlike the Splunk backend, which converts three of the six, the Lucene backend declines
correlation entirely. That is a property of the query language: a Lucene query string
matches individual documents and has no mechanism for counting or sequencing across them.

## Example output

`SDEL-WIN-001`:

```
DEMONSTRATION CONVERSION — ENVIRONMENT-SPECIFIC VALIDATION REQUIRED
backend=elasticsearch-lucene
catalog_id=SDEL-WIN-001
status=converted

(Image:(C\:\\Synthetic\\Users\\synthetic\-user\\AppData\\Local\\Temp\\* OR C\:\\Synthetic\\Windows\\Temp\\* OR C\:\\Synthetic\\Users\\Public\\*)) AND (NOT Image:*\\synthetic_patch_installer.exe)
```

The escaping is heavy because Lucene reserves a large set of characters. Note `\:` for the
drive-letter colon, `\\` for path separators, and `\-` for the hyphen in `synthetic-user`.
Hand-editing a query at this density is error-prone; regenerate rather than patch.

## Field mapping to ECS

The queries use the rule's field names. Elastic deployments normally use ECS:

| Rule field | ECS equivalent |
|---|---|
| `Image` | `process.executable` |
| `CommandLine` | `process.command_line` |
| `ParentImage` | `process.parent.executable` |
| `User` | `user.name` |
| `Computer` | `host.name` |
| `TargetFilename` | `file.path` |
| `TargetObject` | `registry.path` |
| `EventID` | `event.code` |
| `Channel` | `winlog.channel` |
| `ScriptBlockText` | `powershell.file.script_block_text` |
| `SourceIp` | `source.ip` |

pySigma ships ECS pipelines that perform this mapping. None is configured here, for the
reason given in [conversion-limitations](conversion-limitations.md): a pipeline is a
deployment assumption.

## Analyzer behaviour is the main hazard

This is the difference most likely to break a converted query, and it has no equivalent in
the laboratory matcher.

A field mapped as `text` is **analyzed**: tokenized, lowercased, and matched per token. A
field mapped as `keyword` is stored whole and matched exactly. A path query behaves
completely differently between the two:

- Against `text`, `C:\Synthetic\Windows\Temp\tool.exe` is split on punctuation. A wildcard
  path match may succeed for the wrong reasons, or fail entirely.
- Against `keyword`, the value is exact and case-sensitive. `Image:*\\Temp\\*` will not
  match a value indexed as `...\\temp\\...`.

In ECS, `process.executable` is a `keyword` with a `.text` multi-field. Which one your
query targets changes the result. Verify the mapping before trusting a match.

| Behaviour | Laboratory matcher | Lucene |
|---|---|---|
| Case sensitivity | Insensitive by default | `keyword` exact; `text` lowercased by the analyzer |
| Tokenization | None; whole-value comparison | Analyzer-dependent |
| Regex | Python `re` | Lucene regex — **no lookahead or lookbehind** |
| Leading wildcard | Supported | Supported but expensive; sometimes disabled |
| Absent vs null | Distinguished | Depends on `null_value` and mapping |
| `cidr` | Network containment | Requires an `ip`-typed field |

Lucene regex lacking lookaround is a hard incompatibility, not a performance note. A rule
using lookaround in a `re` modifier cannot be faithfully translated, and the resulting
query means something different.

## Performance considerations

- **Leading wildcards are expensive.** Many `endswith` translations produce them. Some
  clusters disable them outright via `search.allow_expensive_queries`.
- **Prefer `keyword` fields** for exact path matching.
- **Bound the time range** with a `@timestamp` filter; Lucene query strings carry none.
- **Restrict the index pattern.** Querying `*` across a large cluster is costly and slow.
- **Consider converting hot rules to DSL or EQL** once validated, for better control over
  filter context and caching.

## Correlation in Elasticsearch

For the six declined rules, correlation is expressible in the stack but not in Lucene:

- **EQL sequences** handle ordered temporal correlation naturally.
- **Transform jobs** or **threshold rules** handle `event_count` and `value_count`.
- **Aggregations** handle distinct-value counting.

None of these is generated here. If you implement one, validate it against the same
synthetic sequences the laboratory uses, including the negative sequences that break
ordering, grouping, threshold, and timespan. See [correlation-subset](correlation-subset.md).

## Before you deploy anything

1. Choose the pipeline: ECS, Winlogbeat, or your own.
2. Verify whether each field is `keyword` or `text`, and target the right one.
3. Check that regex patterns do not rely on lookaround.
4. Add an index pattern and a time filter.
5. Measure the cost of leading wildcards on your cluster.
6. Apply the tuning guidance from the sidecar.
7. Confirm the required telemetry is collected; see
   [logsource-and-telemetry](logsource-and-telemetry.md).

## Related documents

[conversion-limitations](conversion-limitations.md) ·
[splunk-conversion](splunk-conversion.md) ·
[tuning-and-deployment](tuning-and-deployment.md) ·
[correlation-subset](correlation-subset.md)
