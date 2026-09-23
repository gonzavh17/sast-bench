# codeql+llm — 12 pares

- herramienta: `codeql+llm codeql 2.27.1 + claude-opus-5`
- reglas: github/codeql-action@codeql-bundle-v2.27.1 (codeql/javascript-queries:codeql-suites/javascript-security-extended.qls)
- corrida: 2026-09-23T02:28:08+00:00

## Titular

**pair score = 1.00** (12/12 pares)

| metrica | valor |
|---|---|
| recall | 1.00 |
| FPR | 0.00 |
| precision | 1.00 |
| F1 | 1.00 |
| localizacion | 1.00 |
| ruido (hallazgos sin mapear por variante) | 0.00 |

TP 12 · FN 0 · FP 0 · TN 12

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
| `ng-xss-009` | TP | TN | si | `js/client-side-unvalidated-url-redirection`, `js/incomplete-url-substring-sanitization` |
| `ng-xss-010` | TP | TN | si | `js/xss` |
| `ng-xss-011` | TP | TN | si | `js/bad-tag-filter`, `js/incomplete-multi-character-sanitization`, `js/xss` |
| `ng-xss-012` | TP | TN | si | `js/xss` |

## rule_id sin mapear

Ninguno: todo lo que disparo esta en el rule_map.
