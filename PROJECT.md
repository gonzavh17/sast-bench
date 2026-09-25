# sast-bench

A benchmark that measures how well security scanners detect Angular-specific
vulnerabilities. It measures two things: **how much of what is there they
find** and **how much they flag that they should not**. Almost no benchmark
reports the second one, and it is what hurts most in practice.

RealVuln exists for Python and the OWASP Benchmark for Java. There is nothing
equivalent for Angular. That is the gap.

**Defensive focus**: find flaws in your own code in order to fix them.

---

## v1 scope

Three vulnerability families. Everything else comes later.

| id | family | what it covers |
|---|---|---|
| `xss-sanitizer-bypass` | XSS and sanitizer escapes | manually marking content as trusted, raw HTML in the DOM, direct DOM manipulation that goes around the framework, URLs with an unvalidated scheme |
| `client-side-secrets` | sensitive data on the client | secrets in config files, tokens in browser storage, data in state or logs |
| `broken-authorization` | misplaced authorization | guards as the only protection, role-based UI with no validation behind it, trusting something the user can modify |

**Ready for other ecosystems, without abstracting yet**: corpus by directory,
an `ecosystem` field on every case, scoring that takes the corpus path as a
parameter. No abstraction layers until there is a real second ecosystem.

---

## Phase 1 — Corpus

36 hand-labeled pairs = **72 variants**.

### The twin rule

Every vulnerable case has a safe twin: the same pattern done right. That
measures whether the tool understands the pattern or only recognizes a shape.

### Distribution

|                        | obvious | indirect | decoy | total |
|------------------------|---------|----------|-------|-------|
| `xss-sanitizer-bypass` | 4       | 4        | 4     | 12    |
| `client-side-secrets`  | 4       | 4        | 4     | 12    |
| `broken-authorization` | 4       | 4        | 4     | 12    |
|                        |         |          |       | **36 pairs** |

- **obvious** — the data goes from source to sink directly.
- **indirect** — the data goes through several functions before reaching the sink.
- **decoy** — both variants have visible validation; on the vulnerable side it
  is insufficient. It measures whether the tool *reads* the validation or only
  sees that it exists. The pair is kept: there are no loose cases without a twin.

### `broken-authorization` criterion

Authorization is enforced on the server, which is not in the corpus. What is
measured is whether the tool notices that **the client makes or transmits an
authorization decision based on data the user can modify**: a role in
localStorage, claims from a JWT decoded without verification, an id taken from
the URL, an identity header set by the client.

The safe variant uses data the server resolved (`/api/me`, `/api/me/...`
routes, a session cookie). It assumes the server enforces the rule; the case
does not prove it. Known limit: an Angular guard can always be bypassed, in the
safe variant too. What sets the vulnerable one apart is that the authority lives
on the client.

### On-disk format

One directory per pair, shared metadata. The link between twins is the
directory itself.

```
corpus/angular/xss-sanitizer-bypass/001-bypass-security-trust-html/
  meta.yaml
  vulnerable/
    profile.component.ts
    profile.component.html
  safe/
    profile.component.ts
    profile.component.html
```

```yaml
# meta.yaml
id: ng-xss-001
ecosystem: angular
family: xss-sanitizer-bypass
cwe: CWE-79
difficulty: obvious          # obvious | indirect | decoy
source: authored            # authored | oss
variants:
  vulnerable:
    label: vulnerable
    sink: {file: vulnerable/profile.component.ts, line: 24}
    rationale: >
      bypassSecurityTrustHtml applied to a value that comes from the
      query param without sanitizing.
  safe:
    label: safe
    rationale: >
      Same render, using a [textContent] binding; Angular escapes by default.
```

### Corpus rules

- **Every variant is self-contained**: the source → sink chain lives inside
  that variant's files. Without this, tools that resolve imports get an
  arbitrary advantage and `indirect` cases are not comparable.
- Cases are written by me or come from open source projects (`source: oss`,
  with attribution). **No code from work.**
- `tests/` validates every case's `meta.yaml`: required fields, family and
  difficulty inside the enum, existing `sink` paths, both variants present.

---

## Phase 2 — Scoring

Runs rule-based tools and LLMs against the corpus and produces the numbers.
**This phase can be published on its own.**

### Rule-based tools

| tool | why it is here |
|---|---|
| **Semgrep OSS** | the obvious baseline: TS/Angular rules, runs locally, SARIF output |
| **CodeQL** (`javascript-typescript`) | the only one with real taint tracking; it should shine on `indirect` cases |
| **ESLint** (`@angular-eslint` + `eslint-plugin-security`) | not SAST, but it is what most Angular teams already have. It is the floor: what you catch without installing anything new |

Every runner normalizes its output to a common `Finding`: `{path, line, rule_id, severity}`.

### Matching — when a hit counts

Granularity is **case + family**. Location accuracy is reported separately
and does not penalize recall.

```
TP  = vulnerable variant with >=1 finding mapped to the expected family
FN  = vulnerable variant without any finding of that family
FP  = safe variant with >=1 finding of any security family
TN  = clean safe variant
```

It needs a `rule_id → family` table per tool, in `scoring/rule_map/`,
maintained by hand and versioned. It is the most fragile piece of the scoring:
which rules version was mapped, and when, is documented.

### Metrics

**Headline — pair score:**

```
pair score = pairs with (TP on vulnerable AND TN on safe) / 36
```

A tool with 100% recall and 100% FPR scores a pair score of 0. That is exactly
what the benchmark wants to show.

**Always next to it:**

```
recall    = TP / (TP + FN)
FPR       = FP / (FP + TN)          <- over the safe twins
precision = TP / (TP + FP)
F1
```

**Breakdown:** by family (3) and by difficulty (3), plus:

```
localization = % of TPs whose finding lands on sink.line ± 3
noise        = extra findings per variant
```

### LLMs

**Two arms**, the same corpus run twice. It separates "cannot look" from
"does not know what to look for", and the blind arm is the only one truly
comparable with the rule-based tools.

- **A — blind**: *"You are a security reviewer. Analyze this Angular code and
  report the vulnerabilities you find. If there are none, return an empty
  list."* The families are not named.
- **B — guided**: the same code plus the three families described. It measures
  the ceiling with a narrowed scope.

Both arms get **one variant alone**, without saying whether it is the
vulnerable or the safe one. Structured output via `output_config.format`:

```json
{"findings": [{"family": "...", "line": 0, "severity": "...", "rationale": "..."}]}
```

**Axes to sweep** (one run per cell; no repetitions in v1):

| axis | values |
|---|---|
| tier | `claude-opus-5`, `claude-sonnet-5`, `claude-haiku-4-5` |
| effort | `low` / `high` / `xhigh` on `claude-opus-5` |

API notes: adaptive thinking (`thinking: {type: "adaptive"}`) on the models
that support it; `output_config.effort` only applies to the 5 family —
`claude-haiku-4-5` runs without that parameter and stays out of the effort
sweep. A single provider in v1.

The API key goes in `.env`, outside the repo. `.env.example` is versioned.

---

## Phase 3 — Hybrid analyzer (optional)

Rules for the first pass + an LLM that reviews each finding and dismisses false
alarms. It is measured against the same corpus, with the same metrics, and it
goes in as one more row in the phase 2 table.

It is the last phase. If phases 1 and 2 go well, this is an extra; it is not
the deliverable.

---

## Stack and layout

Python + `uv`. The corpus is Angular; the harness does not need to be.

```
sast-bench/
  corpus/
    angular/
      xss-sanitizer-bypass/001-.../
      client-side-secrets/...
      broken-authorization/...
  runners/
    semgrep.py  codeql.py  hybrid.py
    codeql-ext/         # CodeQL extension: session-credential names
    eslint.py  llm.py   # planned
  scoring/
    normalize.py        # each tool's output -> common Finding
    console.py          # presentation: tables, live log, SVG export
    rule_map/           # semgrep.yaml, codeql.yaml
    metrics.py
    report.py  compare.py
  sast_bench/           # the `sast-bench` CLI
  results/
    runs/<run-id>/      # one directory per CLI run: results + manifest.json
    prediccion-*.md     # predictions, written before each run
    compare*.md/.svg    # side-by-side tables
  tests/
  pyproject.toml
  .env.example
```

The scoring takes the corpus path as a parameter (`--corpus corpus/angular`);
it does not hardcode it.

---

## Open questions

- `rule_map` maintenance: freeze it per rules version or regenerate it on
  every run.
- How the blind LLM arm's free-form taxonomy maps to the three families (by
  hand, or by asking for the enum `family` in the schema and accepting `other`).
- Which open source projects to use as a source for `source: oss` cases.
