# False-positive engineering

Most detection rules are not deleted because they were wrong. They are disabled because
nobody could explain their alerts. This document describes how the catalog treats false
positives as a first-class part of a rule rather than an afterthought.

## The rule that dies quietly

A rule ships with `falsepositives: [Unknown]`. The first alert arrives. The analyst has no
context, escalates, and it turns out to be a patch installer. The second alert arrives; it
is the same installer. Within two weeks somebody adds an exclusion for the whole
`AppData\Local\Temp` tree.

The rule is now enabled, green, and inert. It produces zero alerts, and everyone reads
that as "the behaviour is not happening". This is the worst outcome available — worse than
deleting the rule, because deleting it would at least be honest.

Every convention below exists to make that sequence impossible.

## Requirement 1 — Three specific false positives

Each rule carries at least three, and `specific_falsepositives` rejects these exact
strings:

- `Unknown`
- `Legitimate activity`
- `Administrator activity`

A usable false positive names **who** does it, **why**, and **what it looks like**:

> Endpoint management agents that copy remediation binaries into the Windows temporary
> directory during scheduled maintenance windows.

That sentence tells an analyst what to check (is there a maintenance window?), tells an
engineer what to exclude (the agent's binary, not the directory), and tells a reviewer
whether the author actually understood the environment.

Compare:

| Rejected | Why it fails |
|---|---|
| `Unknown` | Admits no analysis was done |
| `Legitimate activity` | True of every rule; conveys nothing |
| `Administrator activity` | Names a role, not a behaviour |
| `Some software may do this` | No actor, no reason, no shape |

## Requirement 2 — A false-positive strategy

The sidecar's `false_positive_strategy` describes the *shape* of benign matches, one level
above the individual examples:

> Benign matches concentrate around packaged installers, patch management, and developer
> workstations. Tune with the writing or launching process identity and with the specific
> binary name rather than excluding the temporary directory tree.

Where the `falsepositives` list enumerates instances, the strategy states the pattern. A
new benign case that has never been seen before still falls under it.

## Requirement 3 — Tuning guidance that preserves detection value

`tuning_guidance` must name both the safe exclusion shape and the unsafe one:

> Prefer per-binary exclusions anchored on `Image|endswith` plus a signature or hash
> condition. **Do not exclude the whole `AppData\Local\Temp` prefix, because that removes
> the detection value of the rule entirely.**

The second sentence is the important one. Without it, the obvious exclusion is the
destructive one.

## The exclusion hierarchy

Ordered from most to least preferred:

| Rank | Exclusion shape | Cost to the rule |
|---|---|---|
| 1 | Specific binary **and** signature or hash | Minimal |
| 2 | Specific binary path (`Image|endswith`) | Small, and re-checkable |
| 3 | Specific parent-child lineage | Small, but lineage can be spoofed |
| 4 | Specific account **and** specific behaviour | Moderate; accounts get compromised |
| 5 | Account alone | Large; a compromised service account is invisible |
| 6 | Host or host group | Large; usually hides exactly the interesting hosts |
| 7 | Whole directory tree or whole logsource | Total; the rule is dead |

Ranks 5 to 7 should require a written justification and an expiry date. In the catalog,
rank 1 and 2 are the only shapes used: `SDEL-WIN-001` excludes
`\synthetic_patch_installer.exe` by name, not the temporary directory it runs from.

## Filters belong in the rule

Where a benign case is universal and stable, it becomes a named filter selection rather
than deployment-time tuning:

```yaml
detection:
    selection_writable_path:
        Image|startswith:
            - 'C:\Synthetic\Users\synthetic-user\AppData\Local\Temp\'
            - 'C:\Synthetic\Windows\Temp\'
            - 'C:\Synthetic\Users\Public\'
    filter_approved_installer:
        Image|endswith: '\synthetic_patch_installer.exe'
    condition: 'selection_writable_path and not filter_approved_installer'
```

Two properties make this better than a deployment exclusion. The filter is **reviewable**
in the rule's diff, and it is **testable** — `case_02_allowed_patch_installer` asserts the
filter works, so removing it breaks a named test.

The trade-off is portability: a filter that is only true in one environment does not
belong in a shared rule. Universal and stable go in the rule; local goes in deployment
tuning, documented in `tuning_guidance`.

## Negative fixtures encode false positives

Every documented benign case has a corresponding negative fixture. For `SDEL-WIN-001`,
`case_02_allowed_patch_installer` is exactly the installer scenario from the
`falsepositives` list, rendered as an event that must not match.

This closes the loop. A false positive is not merely described in prose; it is asserted as
a test. If the filter is removed, the assertion fails and CI says so.

## Severity as a false-positive statement

`level` is partly a claim about noise. The catalog leans towards `medium` because most of
its rules key on behaviour that legitimate software also exhibits, and the descriptions
say so:

> Staging binaries in directories that any interactive user can write to is a recurring
> pattern in delivery and post-exploitation activity, and it also occurs during legitimate
> software installation, **so the rule is scored medium rather than high**.

Writing the severity justification into the description means a reviewer can dispute the
score on the record. A catalog where everything is `high` conveys no information.

## Base rules and volume

Correlation base rules are scored `informational` and are never alerted on directly.
`SDEL-COR-001`'s logon-success base rule states this in its own false positives:

> All normal interactive and network logons across the estate, which is why this base rule
> is never alerted on directly.

The correlation rule is where the signal lives; the base rule is a component. Alerting on
components is a common way to generate a great deal of noise from a well-designed
correlation.

## Reviewing false positives

Ask five questions:

1. Are there at least three, and is each one a concrete scenario with an actor?
2. Does the strategy describe a *shape*, not just a list?
3. Does the tuning guidance name the destructive exclusion and forbid it?
4. Is every documented benign case represented by a negative fixture?
5. Does the severity match the stated noise level, and is the justification in the
   description?

If any answer is no, the rule is not ready, regardless of whether the gates pass.

## What this cannot do

The false-positive analysis in this repository is **reasoned, not measured**. It is based
on how the behaviours are known to occur, not on observed alert volumes, because there are
none. Nothing here predicts your alert rate.

Precision, recall, and false-positive rate are intentionally not reported: they cannot be
derived from synthetic fixtures. See [coverage-methodology](coverage-methodology.md).

## Related documents

[detection-philosophy](detection-philosophy.md) ·
[rule-authoring-guide](rule-authoring-guide.md) ·
[tuning-and-deployment](tuning-and-deployment.md) ·
[rule-quality-gates](rule-quality-gates.md)
