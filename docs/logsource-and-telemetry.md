# Logsource and telemetry

A rule that cannot run in your environment is worse than no rule: it consumes review
attention and produces false confidence through silence. This document describes how the
laboratory forces every rule to state its telemetry prerequisites and how those
statements are checked.

## The telemetry catalog

`config/telemetry-catalog.json` describes every log source the rule catalog uses. Each
profile records the logsource, required logs, channels, providers, optional fields,
collection prerequisites, expected collection gaps, normalization assumptions, ingestion
differences, and retention considerations.

| Profile | Platform | Logsource | Channels |
|---|---|---|---|
| `win_process_creation` | windows | `category: process_creation` | Sysmon Operational, Security |
| `win_registry_set` | windows | `category: registry_set` | Sysmon Operational |
| `win_file_event` | windows | `category: file_event` | Sysmon Operational |
| `win_process_access` | windows | `category: process_access` | Sysmon Operational |
| `win_wmi_event` | windows | `category: wmi_event` | Sysmon Operational |
| `win_security` | windows | `service: security` | Security |
| `win_system` | windows | `service: system` | System |
| `win_ps_script` | windows | `category: ps_script` | PowerShell Operational |
| `linux_process_creation` | linux | `category: process_creation` | auditd |
| `linux_file_event` | linux | `category: file_event` | auditd |
| `linux_auth` | linux | `service: auth` | `/var/log/auth.log`, `/var/log/secure` |

The catalog also carries a `field_semantics` dictionary defining every field name the
rules use, so `TargetObject` and `GrantedAccess` mean one specific thing across the whole
project rather than whatever each rule author assumed.

## Validation

`telemetry.py` checks each sidecar against the catalog:

1. The declared logsource matches a known profile.
2. Every `required_log` is provided by that profile.
3. Every `required_channel` appears in the profile's channels.
4. Every `required_field` and `optional_field` is either in the profile's field list or
   defined in `field_semantics`.
5. `collection_prerequisites` and `expected_collection_gaps` are non-empty.

A sidecar that requires a field no declared source provides fails
`telemetry_requirements_exist`. You cannot quietly require telemetry that does not exist.

## Anatomy of a profile

```json
"win_process_creation": {
  "platform": "windows",
  "logsource": { "category": "process_creation", "product": "windows" },
  "required_logs": ["Windows process creation telemetry"],
  "channels": ["Microsoft-Windows-Sysmon/Operational", "Security"],
  "providers": ["Microsoft-Windows-Sysmon", "Microsoft-Windows-Security-Auditing"],
  "optional_fields": ["OriginalFileName", "IntegrityLevel", "CurrentDirectory", "Hashes"],
  "collection_prerequisites": [
    "A process creation source is enabled (Sysmon Event ID 1 or Security Event ID 4688).",
    "Command-line auditing is enabled when Security 4688 is the only available source."
  ],
  "expected_collection_gaps": [
    "Security 4688 without command-line auditing provides no CommandLine value.",
    "Short-lived processes may be lost if the agent is restarted during collection."
  ],
  "normalization_assumptions": [
    "Image and ParentImage are absolute paths using backslash separators.",
    "CommandLine retains the original argument order and spacing."
  ],
  "ingestion_differences": [
    "Some pipelines lowercase paths; the lab matcher is case-insensitive by default.",
    "Sysmon and 4688 differ in parent process fidelity and in User field formatting."
  ],
  "retention_considerations": "Process creation is high volume; 30 to 90 days of hot retention is typical."
}
```

Each block answers a different operational question.

**`collection_prerequisites`** — what must be *switched on*. This is where most
deployment failures live. A rule matching `CommandLine` is inert on a host where the only
process source is Security 4688 without command-line auditing, and stating that up front
saves a triage cycle.

**`expected_collection_gaps`** — what will be missing even when everything is configured
correctly. Registry auditing is usually filtered to a key allowlist. Process access
auditing is frequently disabled outright because of volume. Containers without a shared
audit namespace do not report `execve`. These are not edge cases; they are the normal
state of real estates.

**`normalization_assumptions`** — the shape the rule expects. `GrantedAccess` is a
hexadecimal string such as `0x1010`; a pipeline emitting a decimal integer breaks the
match without failing anything.

**`ingestion_differences`** — how producers disagree. Some pipelines rename `EventID` to
`event.code`. Some split `TargetObject` into key and value name. Quoted service paths may
or may not retain their quotation marks. Each one is a mapping task at deployment time.

**`retention_considerations`** — what it costs to keep. Authentication logs are cheap and
commonly held for a year; process access telemetry is very high volume and needs scope
filters.

## Volume and cost

Sidecars carry `expected_volume` alongside the profile's retention note:

| Telemetry | Volume | Typical hot retention |
|---|---|---|
| Windows Security (identity events) | Varies widely | 180–365 days |
| Windows System | Low | 365 days |
| WMI subscription | Low | 365 days |
| Linux authentication | Low | 365 days |
| Registry value set | Moderate | 90 days |
| Linux file watch | Moderate | 90 days |
| PowerShell script block | Moderate to high | 90 days |
| Windows file creation | High | 30 days |
| Windows process creation | High | 30–90 days |
| Linux execve | High | 30–60 days |
| Windows process access | Very high | Scope filters required |

Retention interacts directly with correlation. `SDEL-COR-001` uses a 15-minute window and
needs both sides of the sequence inside that window; if one source lands in a different
index with a shorter retention or a different lag, the correlation silently stops firing.

## Field semantics

Excerpt from the shared dictionary:

| Field | Meaning |
|---|---|
| `Image` | Absolute path of the executable backing the created process |
| `OriginalFileName` | Original file name recorded in the binary version resource |
| `CommandLine` | Full command line including arguments as supplied to the process |
| `ParentImage` | Absolute path of the executable that created the process |
| `TargetObject` | Full registry path of the value that was written |
| `Details` | Rendered data written to the registry value |
| `GrantedAccess` | Hexadecimal access mask granted for the process handle |
| `ScriptBlockText` | Decoded PowerShell script block text as executed |
| `TargetUserName` | Account or group that was the object of the audited action |
| `ObjectDN` | Distinguished name of the directory object involved |
| `AttributeLDAPDisplayName` | Directory attribute affected by the change |
| `ImagePath` | Executable path configured for the service, including arguments |
| `SourceIp` | Network address of the remote authentication client |

A field used by a rule but absent from this dictionary fails validation. That constraint
is what keeps the catalog internally consistent as it grows.

## Multi-source rules

Several rules declare more than one channel because more than one source can satisfy them.
`SDEL-WIN-001` accepts Sysmon Operational **or** Security, and its
`ingestion_differences` records that the two differ in parent process fidelity and in
`User` formatting. The rule works with either; the sidecar tells the deployer what changes
between them.

## Collection gaps and honest silence

The hardest failure to detect in production is a rule that reports nothing because the
telemetry never arrives. Two properties of this project mitigate it:

1. **Prerequisites are explicit**, so a deployer can verify them before enabling the rule.
2. **Gaps are documented**, so a zero-alert rule can be checked against a known gap rather
   than assumed to mean the behaviour is absent.

Neither replaces telemetry health monitoring, which is out of scope here. See
[tuning-and-deployment](tuning-and-deployment.md).

## Adding a telemetry profile

1. Add the profile to `config/telemetry-catalog.json` with all seven blocks populated.
2. Add any new field names to `field_semantics`.
3. Add the logsource product, category, or service to `config/allowed-taxonomy.json`.
4. Reference the profile from the sidecar's telemetry fields.
5. Run `sigma-detection-lab validate --strict`.

Do not add a profile with placeholder prerequisites or empty gaps. An unfilled profile
passes the gate while conveying nothing, which is the exact failure this catalog exists to
prevent.

## Related documents

[rule-authoring-guide](rule-authoring-guide.md) ·
[synthetic-event-model](synthetic-event-model.md) ·
[tuning-and-deployment](tuning-and-deployment.md) ·
[configuration](configuration.md)
