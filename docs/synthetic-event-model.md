# Synthetic event model

> **SYNTHETIC DEMONSTRATION DATA**
>
> Every event in `fixtures/` is generated. No real organization, host, user, account,
> domain, log, alert, incident, credential, SIEM, or infrastructure data is present.

## Format

Fixtures are **JSON Lines**: one complete JSON object per line, UTF-8, LF endings. One
file is one test case. A standard-rule case usually holds one event; a correlation
sequence holds several.

```json
{"schema_version": "1.0.0", "event_id": "SDEL-WIN-001-POS-01", "timestamp_utc": "2026-08-01T09:01:00Z", "synthetic": true, "platform": "windows", "logsource": {"category": "process_creation", "product": "windows"}, "channel": "Microsoft-Windows-Sysmon/Operational", "provider": "Microsoft-Windows-Sysmon", "host": "SYNTHETIC-HOST-01", "user": "SYNTHETIC-HOST-01\\synthetic-user", "fields": {"Computer": "SYNTHETIC-HOST-01", "Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "Image": "C:\\Synthetic\\Users\\synthetic-user\\AppData\\Local\\Temp\\synthetic_tool.exe", "OriginalFileName": "synthetic_tool.exe", "CommandLine": "C:\\Synthetic\\Users\\synthetic-user\\AppData\\Local\\Temp\\synthetic_tool.exe --synthetic-run", "ParentImage": "C:\\Synthetic\\Windows\\explorer.exe", "ParentCommandLine": "explorer.exe", "CurrentDirectory": "C:\\Synthetic\\Users\\synthetic-user\\AppData\\Local\\Temp\\", "IntegrityLevel": "Medium", "User": "SYNTHETIC-HOST-01\\synthetic-user"}, "scenario": "Binary executed from the per-user temporary directory.", "notes": "Image prefix matches the per-user temporary directory selection."}
```

JSON Lines rather than a JSON array is deliberate: a diff of a fixture change shows one
line per changed event, and a malformed line fails one case instead of the whole file.

## Schema

| Field | Type | Required | Meaning |
|---|---|---|---|
| `schema_version` | string | yes | Fixture schema version, `1.0.0` |
| `event_id` | string | yes | Stable identifier within the case |
| `timestamp_utc` | string | yes | `YYYY-MM-DDTHH:MM:SSZ`, always UTC |
| `synthetic` | boolean | yes | Always `true`; enforced by `synthetic_marker_required` |
| `platform` | string | yes | `windows` or `linux` |
| `logsource` | object | yes | The Sigma logsource the event belongs to |
| `channel` | string | yes | Log channel or file that carried the record |
| `provider` | string | yes | Producer of the record |
| `host` | string | yes | Synthetic host name |
| `user` | string | yes | Synthetic account context |
| `fields` | object | yes | Normalized detection fields the rule matches against |
| `scenario` | string | yes | What the case represents |
| `notes` | string | yes | Why the case matches or does not |

Validated against `schemas/fixture.schema.json` and
`schemas/correlation-fixture.schema.json`.

`synthetic: true` is not decoration. `event_model.py` refuses to construct a
`SyntheticEvent` without it, so there is no code path by which a non-synthetic record
enters the matcher.

## Field resolution

A rule referencing `Image` resolves it in this order:

1. An exact key in `fields`.
2. A top-level attribute mapped to a known field name — `Channel`, `Computer`,
   `Provider_Name`, and similar.
3. Otherwise **absent**.

Absent is distinct from present-and-null. `field|exists: false` matches an absent field;
it does not match a field explicitly set to `null`. That distinction matters because in
real telemetry a present-but-empty field is a different observation from one the producer
never emitted.

## Permitted synthetic vocabulary

Only these placeholder families appear anywhere in fixtures. The `no_real_data_patterns`
gate flags anything outside them.

| Category | Permitted values |
|---|---|
| Windows hosts | `SYNTHETIC-HOST-01`, `SYNTHETIC-DC01` |
| Linux hosts | `SYNTHETIC-LINUX-01` |
| Accounts | `synthetic-user`, `synthetic-admin`, `synthetic-service` |
| Domains | `example.invalid`, `synthetic.invalid` |
| IP addresses | `192.0.2.0/24` (RFC 5737 documentation range) |
| Windows paths | Under `C:\Synthetic\` |
| Linux paths | Under `/tmp/synthetic-example` |
| Encoded content | `SYNTHETIC_ENCODED_PLACEHOLDER` |
| URLs | `https://example.invalid/synthetic` |

`.invalid` is reserved by RFC 2606 and can never resolve. `192.0.2.0/24` is reserved by
RFC 5737 and is not routable. Both choices mean a copy-paste accident cannot produce a
request to a real host.

### What is deliberately absent

- **No real credentials.** No passwords, tokens, keys, hashes, or session identifiers.
  The `no_secrets` gate scans for credential-shaped strings on every run.
- **No routable addresses.** Only the documentation range.
- **No executable payloads.** Fixtures are data; nothing is decoded, written, or run.
- **No decodable encoded content.** The encoded-command fixtures for `SDEL-PS-001` and
  `SDEL-PS-009` carry `SYNTHETIC_ENCODED_PLACEHOLDER`, which **decodes to nothing**. The
  rules match on the *shape* of an encoded-command invocation, and demonstrating that
  needs no payload.
- **No real organizational identifiers.** No company names, no internal domains, no
  ticket references.

## Windows path convention

Real Windows paths are rewritten under `C:\Synthetic\`:

| Real | Synthetic |
|---|---|
| `C:\Windows\System32\cmd.exe` | `C:\Synthetic\Windows\System32\cmd.exe` |
| `C:\Users\alice\AppData\Local\Temp\` | `C:\Synthetic\Users\synthetic-user\AppData\Local\Temp\` |
| `C:\Program Files\App\app.exe` | `C:\Synthetic\Program Files\SyntheticApp\app.exe` |

The relative structure is preserved, so `startswith` and `endswith` semantics behave
exactly as they would against real telemetry, while the absolute prefix is unmistakably
synthetic. Rules are written against the same convention, so rule and fixture agree.

## Timestamps

- Always UTC, always `Z`-suffixed, always second precision.
- Fixed rather than generated at run time, so results are reproducible.
- The catalog anchors on `2026-08-01T09:00:00Z` and steps by whole minutes.
- Correlation sequences use spacing chosen relative to the rule's `timespan`, with the
  boundary case one minute outside the window.

## Correlation sequences

```
fixtures/correlation/SDEL-COR-001/
├── manifest.json
├── positive/case_01_failures_then_success.jsonl
└── negative/case_01_success_before_failures.jsonl
```

Each file holds an ordered sequence, one event per line, in the order they occurred.
Sequence length is capped at `max_correlation_sequence_events` (100).

Each negative sequence breaks exactly one of ordering, grouping, threshold, or timespan.
See [correlation-subset](correlation-subset.md).

## Limits

Enforced by `config/default.config.json` and applied by `fixture_loader.py`:

| Limit | Value |
|---|---|
| `max_file_bytes` | 1 048 576 |
| `max_events_per_fixture` | 200 |
| `max_correlation_sequence_events` | 100 |
| `max_scalar_length` | 8 192 |
| `max_path_length` | 4 096 |
| `allow_symlinks` | `false` |

A fixture exceeding a limit produces an `SDEL-FIX-001` finding, not a crash, and the run
continues.

## Real-data detection

`redaction.py` performs two distinct jobs.

**Redaction** strips credential-shaped strings from report content before it is written,
so a finding message that quotes rule text cannot leak a secret into a published report.

**Real-data detection** scans fixtures for content that should not be there:

- routable IP addresses outside `192.0.2.0/24`;
- email domains outside `example.invalid` and `synthetic.invalid`;
- hostnames outside the approved synthetic vocabulary;
- strings matching credential patterns — API keys, bearer tokens, private key headers,
  connection strings with embedded passwords.

Findings from the first feed `no_secrets`; findings from the second feed
`no_real_data_patterns`. Both gates block.

## Regeneration

Fixtures, rules, and sidecars are generated together by `tools/generate_all_rules.py`,
which verifies that every positive case matches its rule and every negative case does not
**before** writing the manifests. Edit the data definitions in that script rather than
editing generated files by hand, or the next regeneration will discard your changes.

## Adding fixtures for a new rule

1. Create `fixtures/rules/<catalog-id>/positive/` and `.../negative/`.
2. Write at least two positive cases, each exercising a different branch.
3. Write at least three negative cases, each breaking exactly one requirement.
4. Write `manifest.json` naming every case with `expected`, `scenario`, and `rationale`.
5. Use only the permitted synthetic vocabulary.
6. Run `sigma-detection-lab test --rule <catalog-id>` and then
   `sigma-detection-lab validate --strict`.

## Related documents

[behavioral-testing](behavioral-testing.md) ·
[correlation-subset](correlation-subset.md) ·
[logsource-and-telemetry](logsource-and-telemetry.md) ·
[security-and-privacy](security-and-privacy.md)
