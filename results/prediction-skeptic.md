# Prediction: skeptic pass over the guided LLM (written and committed BEFORE the run)

## Setup

- Base: the guided arm's findings from Opus (`results/merged/all-llm-guided.json`:
  run 20260925-203248 with ng-authz-006 and ng-authz-011 from the re-run after
  the corpus fix). 107 findings: 85 on vulnerable variants, 22 on safe ones.
- Skeptic: the hybrid's filter prompt, unchanged ("dismiss only if you can quote
  the exact line of the control"), one request per finding.
- Model: **`nvidia/nemotron-3-ultra-550b-a55b` on NIM**, so this is a **debug
  run**, not a Claude measurement. Chosen after a probe on ng-xss-010: the
  smaller NIM models (gpt-oss-20b, nemotron-3-super) dismissed the vulnerable
  side by quoting the late `sanitize()` call, which is exactly the decoy's trap;
  kimi-k3 returned unreadable answers; nemotron-3-ultra got both sides right.

## Baseline (guided arm, corpus fixed)

26/36 pairs · 35/36 vulnerable variants detected · 9/36 safe twins flagged
(xss 007, 010, 011, 012; secrets 003, 007, 011; authz 006, 009).

## The numbers

| | baseline | predicted | range |
|---|---|---|---|
| safe twins flagged | 9 | **4** | 3-6 |
| vulnerable variants detected | 35 | **33** | 32-35 |
| pairs solved | 26 | **29** | 27-31 |

**Acceptance criterion: lose at most 2 detections.** If the skeptic drops 3 or
more true detections, it fails, even if the pair score goes up.

## Why

- **Should be dismissed** (a control can be quoted): xss-010, 011 and 012 safe
  (sanitize before the bypass, or the bypass on `clean`), secrets-011 safe
  (`slice(0, 8)`), authz-006 safe (the role comes from `/api/me`).
- **Should stay**: xss-007 safe (the protection is Angular's own sanitizing of a
  plain string, there is no line to quote), authz-009 safe (a cache that is
  never invalidated has no control line either). secrets-003 and 007 safe are a
  coin toss.
- **Detections at risk**: the vulnerable decoys, built so that a control is in
  plain sight but insufficient: xss-009 (`startsWith`), xss-011 (the regex),
  secrets-012 (`includes`), authz-010 (the ownerId check after fetching),
  authz-011 (the `exp` check), authz-012 (the guard). A detection is lost only
  if every finding on that variant gets dismissed, so most of these survive;
  expect one to three to fall.
