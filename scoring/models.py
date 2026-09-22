"""Modelos compartidos por el corpus, los runners y el scoring."""

from __future__ import annotations

import enum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

META_FILENAME = "meta.yaml"
VARIANT_LABELS = ("vulnerable", "safe")


class Family(str, enum.Enum):
    XSS_SANITIZER_BYPASS = "xss-sanitizer-bypass"
    CLIENT_SIDE_SECRETS = "client-side-secrets"
    BROKEN_AUTHORIZATION = "broken-authorization"


class Difficulty(str, enum.Enum):
    OBVIOUS = "obvious"
    INDIRECT = "indirect"
    DECOY = "decoy"


class SourceKind(str, enum.Enum):
    AUTHORED = "authored"
    OSS = "oss"


class Strict(BaseModel):
    """Base que rechaza campos desconocidos: un typo en meta.yaml rompe el test."""

    model_config = ConfigDict(extra="forbid")


class Finding(Strict):
    """Salida normalizada de cualquier herramienta (PROJECT.md: 'Finding comun')."""

    path: str
    line: int = Field(ge=1)
    rule_id: str
    severity: str


class Sink(Strict):
    file: str
    line: int = Field(ge=1)


class Variant(Strict):
    label: str
    rationale: str
    sink: Sink | None = None


class CaseMeta(Strict):
    id: str
    ecosystem: str
    family: Family
    cwe: str
    difficulty: Difficulty
    source: SourceKind
    variants: dict[str, Variant]


class Case(Strict):
    """Un meta.yaml ya leido, junto con la carpeta de la que salio."""

    meta: CaseMeta
    directory: Path

    def variant_dir(self, label: str) -> Path:
        return self.directory / label


def load_case(directory: Path) -> Case:
    """Lee y valida el meta.yaml de una carpeta de caso."""
    raw = yaml.safe_load((directory / META_FILENAME).read_text(encoding="utf-8"))
    return Case(meta=CaseMeta.model_validate(raw), directory=directory)


def discover_cases(corpus: Path) -> list[Case]:
    """Todos los casos bajo el corpus, ordenados por id para salida estable."""
    dirs = sorted(p.parent for p in corpus.rglob(META_FILENAME))
    return sorted((load_case(d) for d in dirs), key=lambda c: c.meta.id)


class RuleMapMeta(Strict):
    tool: str
    rules_source: str
    mapped_at: str


class RuleMap(Strict):
    """Tabla rule_id -> familia, mantenida a mano y versionada.

    Tres estados posibles para un rule_id:
      - en `rules`  -> cuenta para la familia mapeada
      - en `ignore` -> se vio, se decidio que no es security, no cuenta
      - en ninguna  -> `unmapped`: cuenta como ruido y el reporte lo lista,
                       para que no se ignore por omision.
    """

    meta: RuleMapMeta
    rules: dict[str, Family]
    ignore: list[str] = Field(default_factory=list)

    def family_of(self, rule_id: str) -> Family | None:
        return self.rules.get(rule_id)

    def is_unmapped(self, rule_id: str) -> bool:
        return rule_id not in self.rules and rule_id not in self.ignore


def load_rule_map(path: Path) -> RuleMap:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return RuleMap.model_validate(raw)
