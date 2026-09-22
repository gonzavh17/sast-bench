# semgrep — 7 pares

- herramienta: `semgrep 1.177.0`
- reglas: semgrep/semgrep-rules@40b8c63f75dc (javascript, typescript)
- corrida: 2026-09-22T02:22:47+00:00

## Titular

**pair score = 0.43** (3/7 pares)

| metrica | valor |
|---|---|
| recall | 0.43 |
| FPR | 0.00 |
| precision | 1.00 |
| F1 | 0.60 |
| localizacion | 1.00 |
| ruido (hallazgos sin mapear por variante) | 0.00 |

TP 3 · FN 4 · FP 0 · TN 7

## Por par

| caso | vulnerable | safe | par | reglas que dispararon |
|---|---|---|---|---|
| `ng-xss-001` | FN | TN | no | — |
| `ng-xss-002` | TP | TN | si | `insecure-document-method`, `insecure-innerhtml` |
| `ng-xss-003` | FN | TN | no | — |
| `ng-xss-004` | FN | TN | no | — |
| `ng-xss-005` | TP | TN | si | `angular-bypasssecuritytrust` |
| `ng-xss-006` | TP | TN | si | `angular-bypasssecuritytrust` |
| `ng-xss-007` | FN | TN | no | — |

## rule_id sin mapear

Ninguno: todo lo que disparo esta en el rule_map.
