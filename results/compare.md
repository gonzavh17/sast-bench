# Comparativa — semgrep, codeql, codeql+llm

## Titular

| herramienta | pair score | recall | FPR | precision | F1 | localizacion | ruido |
|---|---|---|---|---|---|---|---|
| `semgrep 1.177.0` | **0.42** (5/12) | 0.42 | 0.00 | 1.00 | 0.59 | 1.00 | 0.00 |
| `codeql 2.27.1` | **0.92** (11/12) | 1.00 | 0.08 | 0.92 | 0.96 | 1.00 | 0.00 |
| `codeql+llm codeql 2.27.1 + claude-opus-5` | **1.00** (12/12) | 1.00 | 0.00 | 1.00 | 1.00 | 1.00 | 0.00 |

## Por par

| caso | dificultad | semgrep | codeql | codeql+llm |
|---|---|---|---|---|
| `ng-xss-001` | obvious | FN/TN · no | TP/TN · si | TP/TN · si |
| `ng-xss-002` | obvious | TP/TN · si | TP/TN · si | TP/TN · si |
| `ng-xss-003` | obvious | FN/TN · no | TP/TN · si | TP/TN · si |
| `ng-xss-004` | indirect | FN/TN · no | TP/TN · si | TP/TN · si |
| `ng-xss-005` | indirect | TP/TN · si | TP/TN · si | TP/TN · si |
| `ng-xss-006` | indirect | TP/TN · si | TP/TN · si | TP/TN · si |
| `ng-xss-007` | indirect | FN/TN · no | TP/TN · si | TP/TN · si |
| `ng-xss-008` | obvious | FN/TN · no | TP/TN · si | TP/TN · si |
| `ng-xss-009` | decoy | FN/TN · no | TP/FP · no | TP/TN · si |
| `ng-xss-010` | decoy | TP/TN · si | TP/TN · si | TP/TN · si |
| `ng-xss-011` | decoy | TP/TN · si | TP/TN · si | TP/TN · si |
| `ng-xss-012` | decoy | FN/TN · no | TP/TN · si | TP/TN · si |

## Solapamiento

- resuelven **todas**: `ng-xss-002`, `ng-xss-005`, `ng-xss-006`, `ng-xss-010`, `ng-xss-011`
- solo `semgrep`: —
- solo `codeql`: —
- solo `codeql+llm`: `ng-xss-009`
- **no resuelve ninguna**: —

Union = 12/12 pares (1.00). Es el techo de correr todas juntas.
