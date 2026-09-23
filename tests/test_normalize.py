"""Normalizacion de la salida cruda de cada herramienta al Finding comun.

Los payloads son sinteticos y minimos: cubren la forma del SARIF y del JSON de
Semgrep sin invocar ninguna de las dos herramientas.
"""

from __future__ import annotations

from pathlib import Path

from scoring.normalize import from_codeql, from_semgrep


def sarif(results: list[dict], rules: list[dict] | None = None) -> dict:
    return {
        "runs": [
            {
                "tool": {"driver": {"name": "CodeQL", "rules": rules or []}},
                "results": results,
            }
        ]
    }


def result(rule_id: str, uri: str, line: int, level: str | None = None) -> dict:
    payload = {
        "ruleId": rule_id,
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                }
            }
        ],
    }
    if level is not None:
        payload["level"] = level
    return payload


def test_codeql_extrae_ruta_linea_y_regla():
    findings = from_codeql(sarif([result("js/xss", "trusted-html.ts", 8, "error")]))
    assert len(findings) == 1
    assert findings[0].path == "trusted-html.ts"
    assert findings[0].line == 8
    assert findings[0].rule_id == "js/xss"
    assert findings[0].severity == "ERROR"


def test_codeql_usa_el_default_de_la_regla_cuando_el_result_no_trae_level():
    """CodeQL solo emite `level` si difiere del default del driver."""
    payload = sarif(
        [result("js/incomplete-sanitization", "a.ts", 3)],
        rules=[
            {
                "id": "js/incomplete-sanitization",
                "defaultConfiguration": {"level": "warning"},
            }
        ],
    )
    assert from_codeql(payload)[0].severity == "WARNING"


def test_codeql_no_acorta_el_rule_id():
    """`js/xss` no lleva prefijo de ruta: cortar por el punto lo rompería."""
    findings = from_codeql(sarif([result("js/incomplete-url-substring-sanitization", "a.ts", 1)]))
    assert findings[0].rule_id == "js/incomplete-url-substring-sanitization"


def test_codeql_descarta_results_sin_ubicacion():
    """Una query sin location no se puede atribuir a ninguna variante."""
    assert from_codeql(sarif([{"ruleId": "js/xss", "locations": []}])) == []


def test_codeql_ordena_estable():
    findings = from_codeql(
        sarif(
            [
                result("js/xss", "b.ts", 1),
                result("js/xss", "a.ts", 9),
                result("js/xss", "a.ts", 2),
            ]
        )
    )
    assert [(f.path, f.line) for f in findings] == [("a.ts", 2), ("a.ts", 9), ("b.ts", 1)]


def test_semgrep_acorta_el_rule_id_y_relativiza_la_ruta():
    """El de Semgrep sigue funcionando igual: los dos alimentan el mismo scoring."""
    variant_dir = Path("/corpus/ng-xss-001/vulnerable")
    payload = {
        "results": [
            {
                "check_id": "javascript.browser.security.insecure-innerhtml",
                "path": str(variant_dir / "note.component.ts"),
                "start": {"line": 15},
                "extra": {"severity": "ERROR"},
            }
        ]
    }
    findings = from_semgrep(payload, variant_dir)
    assert findings[0].rule_id == "insecure-innerhtml"
    assert findings[0].path == "note.component.ts"
