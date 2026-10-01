# The auditor's funnel on corpus/angular — results (NIM, debug)

Prediction: [prediction-auditor-angular.md](prediction-auditor-angular.md),
committed before these runs. Holdout not touched.

Models, both runs:
- **A — no funnel**: guided prompt on every variant whole, then the skeptic.
  Analysis and skeptic: NIM `nvidia/nemotron-3-ultra-550b-a55b`.
- **B — auditor**: rules → slices → triage (NIM `openai/gpt-oss-20b`) →
  analysis and skeptic (NIM `nvidia/nemotron-3-ultra-550b-a55b`).

Combined results: `results/merged/all-llm-guided-ultra-skeptic.json` (A),
`results/merged/all-auditor-nim.json` and `all-auditor-nim-funnel.json` (B).

## Survival per stage in B (vulnerable lines, out of 36)

| | rules | slice | triage | analysis | skeptic |
|---|---|---|---|---|---|
| predicted | 33 | 36 | 35 (34-36) | 33 (30-35) | 32 (29-34) |
| **B** | 33 | 36 | **34** | **34** | **33** |

Lost: ng-xss-010 and ng-sec-004 at triage (gpt-oss-20b called them harmless),
ng-sec-012 at the skeptic.

## Safe twins flagged in B (out of 36)

| | after analysis | after skeptic |
|---|---|---|
| predicted | 10 (7-14) | 5 (3-8) |
| **B** | **14** | **9** ✗ out of range |

## A against B

| | A — no funnel | B — auditor |
|---|---|---|
| pairs solved | **28/36** (predicted 26) | **24/36** (predicted 27) |
| vulnerable detected | 31/36 | 33/36 |
| safe twins flagged | 3/36 | 9/36 |
| input tokens, analysis stage | 58,896 | 45,460 (**−23%**, predicted −25%) |
| input tokens, all stages | 93,877 | 131,831 (**+40%**, predicted ±15%) ✗ |
| output tokens, all stages | 93,003 | 147,141 (+58%) |
| same tokens priced as Opus 5 | ~US$ 2.79 | ~US$ 4.34 |

## Reading

- **The slicing works**: every vulnerable line is in a slice (36/36), and the
  analysis stage reads 23% less code, as predicted.
- **The funnel costs more than it saves on this corpus**, which the prediction
  listed as a falsifier (total input 30% or more above A). Triage adds a call
  per slice, and the analysis on slices produces more findings, so the skeptic
  has more to review. On projects of 1-4 files there is little code to skip.
- **The skeptic clears fewer false alarms on slices**: 14 → 9 in B against
  9 → 3 in A. A plausible reason: on a slice it sees less of the surrounding
  code, so it finds fewer controls to quote. Not tested yet.
- B detects 2 more vulnerable lines than A and flags 6 more safe twins. With
  36 pairs, read these as directions to test, not as results.

What this does not show: whether the funnel saves on a real project, where most
of the code has nothing to do with security. That is stage 5.
