# Holdout corpus

Pairs that are **never used to tune** rules, prompts or the auditor's funnel.
They are only run in the final measurement of each stage, and their results are
reported apart from `corpus/`. Nothing discovers them by default: every command
needs `--corpus corpus-holdout` (or `corpus-holdout/angular`).

If a holdout case ever drives a change to the auditor, it stops being a
holdout: move it to `corpus/` and write a new one.

## Status

| family | written | slots left |
|---|---|---|
| xss-sanitizer-bypass | 001 obvious, 002 indirect, 003 decoy | **004** (any difficulty) |
| client-side-secrets | 001 obvious, 002 indirect, 003 decoy | **004** (any difficulty) |
| broken-authorization | 001 obvious, 002 decoy | **003** (indirect), **004** (any difficulty) |

The four open slots are for the project owner to write. The other eight need
the owner's review before the stage closes.

## How to write a pair

Same format as `corpus/`, see PROJECT.md for the full rules.

```
corpus-holdout/angular/<family>/<NNN>-<slug>/
  meta.yaml
  vulnerable/   the flawed version
  safe/         the same pattern done right
```

```yaml
id: ngh-authz-003            # ngh = Angular holdout; xss | sec | authz
ecosystem: angular
family: broken-authorization # xss-sanitizer-bypass | client-side-secrets | broken-authorization
cwe: CWE-639
difficulty: indirect         # obvious | indirect | decoy
source: authored
variants:
  vulnerable:
    label: vulnerable
    sink: {file: vulnerable/orders.service.ts, line: 14}
    rationale: >
      What is wrong and why it is exploitable.
  safe:
    label: safe
    rationale: >
      What is different and why it is fine.
```

Checklist:

1. **New pattern.** Do not reuse a case from `corpus/`; a holdout that repeats
   the main corpus tests nothing.
2. **Twins differ only where the flaw is.** Same files, names and structure.
3. **The safe twin is clean of every family**, not only its own (a token in
   localStorage in a "safe" authorization twin is a secrets flaw).
4. **Self-contained.** The whole source → sink chain lives in the variant.
5. **Comments never reveal the label.** Say what the code does, never whether
   it is safe; where both twins have a comment, it reads the same.
6. **Sink** = file and line where the flaw happens, in the vulnerable variant.
7. **Difficulty**: obvious (source to sink directly), indirect (through other
   functions, services or files), decoy (both sides have a visible check; the
   vulnerable one is insufficient).

Check it with:

```bash
uv run sast-bench corpus validate --corpus corpus-holdout
uv run sast-bench corpus stats --corpus corpus-holdout
```
