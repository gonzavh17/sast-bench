# Comparativa — semgrep, codeql, codeql+ext

## Titular

| herramienta | pair score | recall | FPR | precision | F1 | localizacion | ruido |
|---|---|---|---|---|---|---|---|
| `semgrep 1.177.0` | **0.00** (0/12) | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| `codeql 2.27.1` | **0.00** (0/12) | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| `codeql+ext 2.27.1` | **0.17** (2/12) | 0.25 | 0.08 | 0.75 | 0.38 | 0.67 | 0.00 |

## Por par

| caso | dificultad | semgrep | codeql | codeql+ext |
|---|---|---|---|---|
| `ng-sec-001` | obvious | FN/TN · no | FN/TN · no | FN/TN · no |
| `ng-sec-002` | obvious | FN/TN · no | FN/TN · no | TP/TN · si |
| `ng-sec-003` | obvious | FN/TN · no | FN/TN · no | FN/TN · no |
| `ng-sec-004` | obvious | FN/TN · no | FN/TN · no | FN/TN · no |
| `ng-sec-005` | indirect | FN/TN · no | FN/TN · no | TP/TN · si |
| `ng-sec-006` | indirect | FN/TN · no | FN/TN · no | FN/TN · no |
| `ng-sec-007` | indirect | FN/TN · no | FN/TN · no | FN/TN · no |
| `ng-sec-008` | indirect | FN/TN · no | FN/TN · no | FN/TN · no |
| `ng-sec-009` | decoy | FN/TN · no | FN/TN · no | FN/TN · no |
| `ng-sec-010` | decoy | FN/TN · no | FN/TN · no | FN/TN · no |
| `ng-sec-011` | decoy | FN/TN · no | FN/TN · no | TP/FP · no |
| `ng-sec-012` | decoy | FN/TN · no | FN/TN · no | FN/TN · no |

## Solapamiento

- resuelven **todas**: —
- solo `semgrep`: —
- solo `codeql`: —
- solo `codeql+ext`: `ng-sec-002`, `ng-sec-005`
- **no resuelve ninguna**: `ng-sec-001`, `ng-sec-003`, `ng-sec-004`, `ng-sec-006`, `ng-sec-007`, `ng-sec-008`, `ng-sec-009`, `ng-sec-010`, `ng-sec-011`, `ng-sec-012`

Union = 2/12 pares (0.17). Es el techo de correr todas juntas.
