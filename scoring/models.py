"""Models shared by the corpus, the runners and the scoring."""

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
    """Base that rejects unknown fields: a typo in meta.yaml fails the test."""

    model_config = ConfigDict(extra="forbid")


class Finding(Strict):
    """Normalized output of any tool (PROJECT.md: 'common Finding')."""

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
    """A parsed meta.yaml, together with the directory it came from."""

    meta: CaseMeta
    directory: Path

    def variant_dir(self, label: str) -> Path:
        return self.directory / label


def load_case(directory: Path) -> Case:
    """Read and validate the meta.yaml of a case directory."""
    raw = yaml.safe_load((directory / META_FILENAME).read_text(encoding="utf-8"))
    return Case(meta=CaseMeta.model_validate(raw), directory=directory)


def discover_cases(corpus: Path) -> list[Case]:
    """Every case under the corpus, sorted by id for stable output."""
    dirs = sorted(p.parent for p in corpus.rglob(META_FILENAME))
    return sorted((load_case(d) for d in dirs), key=lambda c: c.meta.id)


class RuleMapMeta(Strict):
    tool: str
    rules_source: str
    mapped_at: str


class RuleMap(Strict):
    """rule_id -> family table, maintained by hand and versioned.

    A rule_id is in one of three states:
      - in `rules`  -> counts for the mapped family
      - in `ignore` -> seen, judged not security-relevant, does not count
      - in neither  -> `unmapped`: counts as noise and the report lists it,
                       so it is never ignored by omission.
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
