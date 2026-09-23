# Comparativa — semgrep, codeql, codeql+llm

## Titular

| herramienta | pair score | recall | FPR | precision | F1 | localizacion | ruido |
|---|---|---|---|---|---|---|---|
| `semgrep 1.177.0` | **0.00** (0/12) | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| `codeql 2.27.1` | **0.00** (0/12) | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| `codeql+llm codeql 2.27.1 + claude-opus-5` | **0.00** (0/12) | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |

## Por par

| caso | dificultad | semgrep | codeql | codeql+llm |
|---|---|---|---|---|
| `ng-sec-001` | obvious | FN/TN · no | FN/TN · no | FN/TN · no |
| `ng-sec-002` | obvious | FN/TN · no | FN/TN · no | FN/TN · no |
| `ng-sec-003` | obvious | FN/TN · no | FN/TN · no | FN/TN · no |
| `ng-sec-004` | obvious | FN/TN · no | FN/TN · no | FN/TN · no |
| `ng-sec-005` | indirect | FN/TN · no | FN/TN · no | FN/TN · no |
| `ng-sec-006` | indirect | FN/TN · no | FN/TN · no | FN/TN · no |
| `ng-sec-007` | indirect | FN/TN · no | FN/TN · no | FN/TN · no |
| `ng-sec-008` | indirect | FN/TN · no | FN/TN · no | FN/TN · no |
| `ng-sec-009` | decoy | FN/TN · no | FN/TN · no | FN/TN · no |
| `ng-sec-010` | decoy | FN/TN · no | FN/TN · no | FN/TN · no |
| `ng-sec-011` | decoy | FN/TN · no | FN/TN · no | FN/TN · no |
| `ng-sec-012` | decoy | FN/TN · no | FN/TN · no | FN/TN · no |

## Solapamiento

- resuelven **todas**: —
- solo `semgrep`: —
- solo `codeql`: —
- solo `codeql+llm`: —
- **no resuelve ninguna**: `ng-sec-001`, `ng-sec-002`, `ng-sec-003`, `ng-sec-004`, `ng-sec-005`, `ng-sec-006`, `ng-sec-007`, `ng-sec-008`, `ng-sec-009`, `ng-sec-010`, `ng-sec-011`, `ng-sec-012`

Union = 0/12 pares (0.00). Es el techo de correr todas juntas.
