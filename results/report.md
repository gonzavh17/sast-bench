# semgrep — 3 pares

- herramienta: `semgrep 1.177.0`
- reglas: semgrep/semgrep-rules@40b8c63f75dc (javascript, typescript)
- corrida: 2026-09-21T23:34:17+00:00

## Titular

**pair score = 0.33** (1/3 pares)

| metrica | valor |
|---|---|
| recall | 0.33 |
| FPR | 0.00 |
| precision | 1.00 |
| F1 | 0.50 |
| localizacion | 1.00 |
| ruido (hallazgos sin mapear por variante) | 0.00 |

TP 1 · FN 2 · FP 0 · TN 3

## Por par

| caso | vulnerable | safe | par | reglas que dispararon |
|---|---|---|---|---|
| `ng-xss-001` | FN | TN | no | — |
| `ng-xss-002` | TP | TN | si | `insecure-document-method`, `insecure-innerhtml` |
| `ng-xss-003` | FN | TN | no | — |

## rule_id sin mapear

Ninguno: todo lo que disparo esta en el rule_map.
