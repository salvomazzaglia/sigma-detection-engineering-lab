# Examples

> **SYNTHETIC DEMONSTRATION DATA**
>
> Everything here is generated. No real organization, host, user, credential, log, alert,
> incident, or SIEM data is present. Nothing here is validated production detection
> content.

Pre-generated artefacts showing what the laboratory produces, so you can see the output
before installing anything.

## Contents

| Path | Contents |
|---|---|
| `rules/windows/process_creation/demo_staging_path_execution.yml` | The example Sigma rule, `SDEL-DEMO-001` |
| `metadata/rules/SDEL-DEMO-001.json` | Its detection metadata sidecar |
| `fixtures/rules/SDEL-DEMO-001/` | Two positive and three negative cases with a manifest |
| `sample-*.{json,html,sarif,xml,csv}` | Sample reports in every supported format |
| `attack-navigator-layer.json` | Sample ATT&CK Navigator layer |
| `sample-conversions/` | Offline backend conversions for the full catalog |

## The example rule

`SDEL-DEMO-001` — *demo staging path execution* — is a self-contained rule carrying
everything a catalog rule carries: a hypothesis, telemetry prerequisites, collection gaps,
tuning guidance, verified ATT&CK mapping, and fixtures.

Its three negative cases show the near-miss discipline the whole catalog follows:
`managed_program_files` puts the binary outside every writable prefix,
`system_directory` uses a non-writable system path, and `similarly_named_path` uses a
managed directory that merely *contains* the staging directory's name — which is what
pins the `startswith` semantics in place.

Regenerate it, or produce a fresh scaffold for your own rule:

```bash
sigma-detection-lab generate-demo --output examples
sigma-detection-lab generate-demo --output examples --force   # overwrite
```

`generate-demo` refuses to write outside the project root, and refuses to overwrite
without `--force`. The first is a path-safety control, not a limitation — the example has
to live inside the project to be validatable against its configuration.

Validate the generated set on its own:

```bash
sigma-detection-lab validate \
  --rules examples/rules \
  --metadata examples/metadata/rules \
  --fixtures examples/fixtures
```

## Sample reports

One artefact per format, produced from the full 56-rule catalog:

| File | Format | Notes |
|---|---|---|
| `sample-quality-report.json` | JSON | Canonical; the input `compare` consumes |
| `sample-quality-report.html` | HTML | Standalone and offline — no CDN, no script, no external font |
| `sample-quality-report.sarif` | SARIF 2.1.0 | No `security-severity`; `isVulnerabilityFinding: false` |
| `sample-test-results.xml` | JUnit XML | `UNSUPPORTED` renders as a failure, not a skip |
| `sample-rule-catalog.csv` | CSV | Formula-injection prefixes neutralised |
| `sample-coverage-report.json` / `.html` | JSON / HTML | Carries the coverage caveat banner |
| `attack-navigator-layer.json` | Navigator 4.5 | Verified techniques only; scored by rule count |

Open `sample-quality-report.html` in a browser to see what the screenshot in the README
shows. It makes no network request.

Reproduce them:

```bash
sigma-detection-lab validate \
  --json-out examples/sample-quality-report.json \
  --html-out examples/sample-quality-report.html \
  --sarif-out examples/sample-quality-report.sarif \
  --csv-out examples/sample-rule-catalog.csv

sigma-detection-lab test --junit-out examples/sample-test-results.xml

sigma-detection-lab coverage --tests \
  --json-out examples/sample-coverage-report.json \
  --html-out examples/sample-coverage-report.html \
  --navigator examples/attack-navigator-layer.json
```

Output is deterministic: two runs of the same commit differ only in `generated_at`.

## Sample conversions

> **DEMONSTRATION CONVERSION — ENVIRONMENT-SPECIFIC VALIDATION REQUIRED**

`sample-conversions/splunk/` and `sample-conversions/elasticsearch/` hold one file per
rule per backend, each carrying the banner, the backend name, the catalog identifier, and
the conversion status, plus a `conversions.json` summary per backend.

| Backend | Converted | Unsupported |
|---|---|---|
| `splunk` (SPL) | 53 / 56 | 3 |
| `elasticsearch-lucene` | 50 / 56 | 6 |

All nine unsupported results are correlation rules. Splunk declines `temporal_ordered`;
the Lucene backend declines correlation entirely. The failures are recorded, not hidden:

```
DEMONSTRATION CONVERSION — ENVIRONMENT-SPECIFIC VALIDATION REQUIRED
backend=splunk
catalog_id=SDEL-COR-001
status=unsupported

correlation conversion is not supported in v1.0 and the backend declined the rule:
NotImplementedError: Correlation type 'temporal_ordered' is not supported
```

Regenerate:

```bash
sigma-detection-lab convert --backend splunk --output temp/splunk.json
sigma-detection-lab convert --backend elasticsearch-lucene --output temp/es.json
```

### These queries are not deployable

A converted query is a portability demonstration. Between it and a working detection sit
five gaps: field mapping to your schema, index and sourcetype selection, an explicit time
range, permissions and cost, and semantic differences between the laboratory matcher and
each vendor engine.

See [`docs/conversion-limitations.md`](../docs/conversion-limitations.md),
[`docs/splunk-conversion.md`](../docs/splunk-conversion.md),
[`docs/elasticsearch-conversion.md`](../docs/elasticsearch-conversion.md), and
[`docs/tuning-and-deployment.md`](../docs/tuning-and-deployment.md).

## Reading the reports critically

Three things in the sample output are easy to over-read:

**283 tests passing** means every rule's logic behaved as its author claimed against
synthetic events. It does not mean the rules detect real attacks. **A match does not prove
compromise.**

**36 techniques** is a count of authored rules, not a measurement of environmental
coverage. See [`docs/coverage-methodology.md`](../docs/coverage-methodology.md).

**31 gates passing** means the authoring standard was met. It says nothing about
operational effectiveness.

The reports state all three limits themselves, in the banners. They are repeated here
because a report separated from its context is exactly how a synthetic result becomes a
production claim.

## Using examples as templates

The example rule and sidecar are good starting points, provided you replace **all** of:

- the catalog identifier and the derived UUID;
- the title, description, and detection logic;
- the ATT&CK mapping, verified against the vendored catalog;
- the telemetry requirements, matched to a profile in `config/telemetry-catalog.json`;
- the false positives and tuning guidance;
- every fixture.

Copying the structure is the point. Copying the content produces a rule that passes the
gates and detects nothing.

## Related documents

[rule-authoring-guide](../docs/rule-authoring-guide.md) ·
[reports](../docs/reports.md) ·
[conversion-limitations](../docs/conversion-limitations.md) ·
[behavioral-testing](../docs/behavioral-testing.md)
