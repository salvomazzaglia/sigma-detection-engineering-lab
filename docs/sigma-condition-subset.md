# Sigma condition subset

Evaluator: **`sdel-lab-matcher-v1`**, declared in `config/evaluator-profile.json` and
recorded in every behavioral test report.

> Purpose: deterministic behavioral unit testing only. **Not a SIEM backend substitute.**

## Why a subset

A full Sigma evaluator would have to implement aggregation, backend-specific field
resolution, pipeline transformations, and placeholder expansion. Each of those needs
context the laboratory does not have — an index, a schema, a deployment. Implementing
them approximately would produce a matcher whose results look authoritative and are
quietly wrong.

The alternative chosen here is a small, exactly specified subset with one hard rule:
**anything outside it is reported `UNSUPPORTED`, never as a pass.**

## Grammar

`condition_parser.py` implements a real recursive-descent parser over this grammar, not a
regular expression. That is what makes rejection reliable rather than best-effort.

```
condition   := or_expr
or_expr     := and_expr ( "or" and_expr )*
and_expr    := not_expr ( "and" not_expr )*
not_expr    := "not" not_expr | primary
primary     := "(" condition ")"
             | quantifier "of" pattern
             | selection_name
quantifier  := "1" | "all"
pattern     := identifier "*" | "them"
```

Operator precedence, highest first: parentheses, `not`, `and`, `or`. Operators are
case-insensitive; selection names are case-sensitive.

## Supported constructs

| Construct | Example | Notes |
|---|---|---|
| Named selection | `selection_writable_path` | The preferred form |
| Conjunction | `selection_a and selection_b` | |
| Disjunction | `selection_a or selection_b` | |
| Negation | `not filter_approved_installer` | |
| Grouping | `(a or b) and not c` | |
| Any-of prefix | `1 of selection_*` | |
| All-of prefix | `all of selection_*` | |
| Any-of all | `1 of them` | Parsed, but discouraged in the main catalog |
| All-of all | `all of them` | Parsed, but discouraged in the main catalog |

`config/allowed-taxonomy.json` lists `1 of them` and `all of them` under
`avoid_in_main_catalog`, with the reason: *"Explicit selection names keep conditions
readable and keep the deterministic lab matcher in scope."* A wildcard over "them" makes
the rule's meaning depend on which selections happen to exist, which makes review harder
and refactoring dangerous.

## Rejected constructs

| Construct | Example | Why |
|---|---|---|
| Aggregation | `| count() > 5` | Requires a query engine and a time window; use a correlation rule |
| Aggregation with grouping | `| count() by User > 5` | Same |
| Numeric comparison | `field > 10` | Not implemented; would need type inference the pipelines do not guarantee |
| `near` | `a near b` | Temporal proximity belongs in a correlation rule |
| Backend-specific fields | vendor-prefixed keys | Not portable, not evaluable offline |
| Arbitrary expressions | anything not in the grammar | Rejected by the parser |
| Unknown modifiers | `field|frobnicate` | Rejected rather than ignored |

A rejection surfaces as an `UNSUPPORTED` test outcome carrying the parser's message, for
example:

```
unsupported condition: aggregation expressions are not evaluated by
sdel-lab-matcher-v1; express the requirement as a correlation rule instead
```

## Matching semantics

### Field resolution

A rule field is resolved against the synthetic event in this order:

1. An exact key in the event's `fields` mapping.
2. A top-level event attribute that maps to a known field name (`Channel`, `Computer`,
   `Provider_Name`, and similar).
3. Otherwise the field is **absent**, which is distinct from present-and-null.

### Case handling

Comparisons are **case-insensitive by default** and case-sensitive under `cased`. This
matches the behaviour most Windows-focused backends exhibit, and it means a pipeline that
lowercases paths does not silently break every path rule. The choice is recorded in the
evaluator profile with the caveat that vendor backends may differ.

### Value lists and multiple keys

```yaml
selection:
  Image|endswith:            # implicit OR across the list
    - '\cmd.exe'
    - '\powershell.exe'
  User|contains: 'synthetic' # implicit AND with the key above
```

### Modifier semantics

| Modifier | Behaviour |
|---|---|
| *(none)* | Full-value equality after case normalisation |
| `contains` | Substring |
| `startswith` | Prefix |
| `endswith` | Suffix |
| `re` | Python `re.search`, so the pattern is unanchored unless you anchor it |
| `cidr` | Parses the value as an IP address and tests network containment; a non-address value does not match |
| `exists` | `true` requires the field present, `false` requires it absent; the value is not examined |
| `all` | Every listed value must match, turning the implicit OR into an AND |
| `cased` | Composes with the others to force case-sensitive comparison |

### Wildcards

`*` and `?` in plain values are treated as Sigma wildcards and translated to an anchored
regular expression internally. Escape them with a backslash to match literally. Windows
paths therefore need care: `C:\Synthetic\*` is a wildcard, and a literal backslash before
a `*` must be escaped.

## Regex safety

Regular expressions are attacker-influenced input in a repository that CI executes, so
they are constrained:

- **Maximum length 256 characters** (`max_regex_length`).
- **Catastrophic-backtracking rejection.** Patterns with nested unbounded quantifiers —
  the `(a+)+` shape — are refused before compilation.
- **Python `re` flavour**, which differs from RE2, PCRE, and Lucene's engine. A rule that
  relies on Python-specific behaviour will not convert faithfully.
- Compilation failure is a finding, not a crash.

A rejected regex produces an `UNSUPPORTED` outcome, so the rule cannot pass by having an
unevaluatable pattern.

## Explaining a condition

```bash
sigma-detection-lab explain SDEL-WIN-001
```

prints the reconstructed AST:

```
Parsed condition
  (selection_writable_path AND NOT filter_approved_installer)
```

followed by a per-case table with the verdict, the actual result, and the reason. If the
printed condition is not what you meant, the rule is wrong regardless of whether the
tests pass.

## Extending the subset

Widening the subset is a deliberate change, not a convenience fix. It requires, in order:

1. A statement of the semantics in `config/evaluator-profile.json`.
2. An implementation in `condition_parser.py` or `event_matcher.py`.
3. Unit tests covering the semantics, including the boundary cases.
4. An entry in this document and in
   [sigma-specification-profile](sigma-specification-profile.md).
5. A `CHANGELOG.md` note, because the change alters what past results meant.

Adding a construct without documenting its semantics is worse than not supporting it: an
undocumented interpretation is indistinguishable from a bug.

## Related documents

[sigma-specification-profile](sigma-specification-profile.md) ·
[correlation-subset](correlation-subset.md) ·
[synthetic-event-model](synthetic-event-model.md) ·
[behavioral-testing](behavioral-testing.md)
