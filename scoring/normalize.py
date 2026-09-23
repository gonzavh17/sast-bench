"""Salida cruda de cada herramienta -> Finding comun."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scoring.models import Finding


def from_semgrep(payload: dict[str, Any], variant_dir: Path) -> list[Finding]:
    """Normaliza el JSON de `semgrep --json` de una corrida sobre una variante.

    Las rutas quedan relativas a la carpeta de la variante, asi el resultado no
    depende de donde este montado el corpus.
    """
    findings: list[Finding] = []
    for result in payload.get("results", []):
        findings.append(
            Finding(
                path=_relative(result.get("path", ""), variant_dir),
                line=max(1, int(result.get("start", {}).get("line", 1))),
                rule_id=_short_rule_id(result.get("check_id", "")),
                severity=str(result.get("extra", {}).get("severity", "UNKNOWN")),
            )
        )
    return sorted(findings, key=lambda f: (f.path, f.line, f.rule_id))


def from_codeql(payload: dict[str, Any]) -> list[Finding]:
    """Normaliza el SARIF de `codeql database analyze` de una variante.

    Las rutas del SARIF ya vienen relativas al --source-root, que es la carpeta
    de la variante, asi que no hace falta recalcularlas.
    """
    findings: list[Finding] = []
    for run in payload.get("runs", []):
        levels = _sarif_default_levels(run)
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            location = _sarif_location(result)
            if location is None:
                continue
            path, line = location
            findings.append(
                Finding(
                    path=path,
                    line=line,
                    rule_id=rule_id,
                    # CodeQL solo emite `level` cuando difiere del default de la
                    # regla, asi que el default del driver es el que manda.
                    severity=str(result.get("level") or levels.get(rule_id, "warning")).upper(),
                )
            )
    return sorted(findings, key=lambda f: (f.path, f.line, f.rule_id))


def _sarif_default_levels(run: dict[str, Any]) -> dict[str, str]:
    rules = run.get("tool", {}).get("driver", {}).get("rules", [])
    return {
        rule.get("id", ""): rule.get("defaultConfiguration", {}).get("level", "warning")
        for rule in rules
    }


def _sarif_location(result: dict[str, Any]) -> tuple[str, int] | None:
    locations = result.get("locations", [])
    if not locations:
        return None
    physical = locations[0].get("physicalLocation", {})
    uri = physical.get("artifactLocation", {}).get("uri")
    if not uri:
        return None
    return Path(uri).as_posix(), max(1, int(physical.get("region", {}).get("startLine", 1)))


def _relative(raw_path: str, variant_dir: Path) -> str:
    try:
        return Path(raw_path).resolve().relative_to(variant_dir.resolve()).as_posix()
    except ValueError:
        return Path(raw_path).as_posix()


def _short_rule_id(check_id: str) -> str:
    """Semgrep prefija el check_id con la ruta del archivo de reglas.

    `javascript.browser.security.insecure-innerhtml` -> `insecure-innerhtml`.
    El rule_map usa el id corto, que es el que publica la regla.
    """
    return check_id.rsplit(".", 1)[-1] if check_id else check_id
