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
