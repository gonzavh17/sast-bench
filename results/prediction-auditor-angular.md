# Prediction: the auditor's funnel on corpus/angular (written and committed BEFORE the run)

All runs on NIM (debug). Holdout not touched.

## Two runs, same models, so the only difference is the funnel

- **A — no funnel**: `llm --arm guided` with `nvidia/nemotron-3-ultra-550b-a55b`
  on every variant whole, then the skeptic (`hybrid --base-engine llm-guided`)
  with the same model.
- **B — auditor**: rules → slices → triage with `openai/gpt-oss-20b` → analysis
  and skeptic with `nvidia/nemotron-3-ultra-550b-a55b`.

The free stages are already measured (run 20260930-231458): rules at the sink
33/36, a slice shows the sink 36/36, 75 slices for 72 variants.

## Survival per stage in B (vulnerable lines, out of 36)

| rules | slice | triage | analysis | skeptic |
|---|---|---|---|---|
| 33 (measured) | 36 (measured) | **35** (34-36) | **33** (30-35) | **32** (29-34) |

Triage is told to keep anything unsure, so it should drop at most one or two.
The analysis model is weaker than Opus, and slices hide some context, so a few
indirect cases may be missed there.

## Safe twins flagged in B (out of 36)

after analysis **10** (7-14) → after skeptic **5** (3-8).

## B against A

| | A (no funnel) | B (auditor) |
|---|---|---|
| pairs solved | **26** (23-29) | **27** (24-30) |
| input tokens, analysis stage | baseline | **~25% fewer** |
| input tokens, all stages | baseline | **about the same** (±15%): triage adds calls |

What the bet says: on this corpus the funnel neither helps nor hurts the score
by more than a couple of pairs, and it does not save much, because every
variant is 1 to 4 files and the slices hold most of the code. The saving has to
show on real projects (stage 5), not here. A difference of 1-2 pairs between A
and B means nothing at this size.

## What would falsify it

- B below 22/36, or more than 4 vulnerable lines lost at triage: the funnel
  throws away what matters, and the slicing or the triage prompt is wrong.
- B's total input tokens 30% or more above A: the funnel costs more than it
  saves even before real projects.
