# codeql — 12 pares

- herramienta: `codeql 2.27.1`
- reglas: github/codeql-action@codeql-bundle-v2.27.1 (codeql/javascript-queries:codeql-suites/javascript-security-extended.qls)
- corrida: 2026-09-23T01:14:30+00:00

## Titular

**pair score = 0.92** (11/12 pares)

| metrica | valor |
|---|---|
| recall | 1.00 |
| FPR | 0.08 |
| precision | 0.92 |
| F1 | 0.96 |
| localizacion | 1.00 |
| ruido (hallazgos sin mapear por variante) | 0.00 |

TP 12 · FN 0 · FP 1 · TN 11

## Por par

| caso | vulnerable | safe | par | reglas que dispararon |
|---|---|---|---|---|
| `ng-xss-001` | TP | TN | si | `js/xss` |
| `ng-xss-002` | TP | TN | si | `js/xss` |
| `ng-xss-003` | TP | TN | si | `js/xss` |
| `ng-xss-004` | TP | TN | si | `js/xss` |
| `ng-xss-005` | TP | TN | si | `js/xss` |
| `ng-xss-006` | TP | TN | si | `js/xss` |
| `ng-xss-007` | TP | TN | si | `js/xss` |
| `ng-xss-008` | TP | TN | si | `js/xss` |
| `ng-xss-009` | TP | FP | no | `js/client-side-unvalidated-url-redirection`, `js/incomplete-url-substring-sanitization` |
| `ng-xss-010` | TP | TN | si | `js/xss` |
| `ng-xss-011` | TP | TN | si | `js/bad-tag-filter`, `js/incomplete-multi-character-sanitization`, `js/xss` |
| `ng-xss-012` | TP | TN | si | `js/xss` |

## rule_id sin mapear

Ninguno: todo lo que disparo esta en el rule_map.
