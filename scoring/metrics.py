"""Tally del corpus y metricas (PROJECT.md, 'Matching' y 'Metricas')."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from scoring.models import Case, Finding, RuleMap

LOCALIZATION_TOLERANCE = 3


@dataclass
class VariantOutcome:
    """Como le fue a una variante: la celda de la matriz que ocupa."""

    case_id: str
    label: str
    cell: str  # TP | FN | FP | TN
    matched: list[Finding] = field(default_factory=list)
    unmapped: list[str] = field(default_factory=list)
    noise: int = 0
    localized: bool | None = None


@dataclass
class PairOutcome:
    case_id: str
    vulnerable: VariantOutcome
    safe: VariantOutcome

    @property
    def solved(self) -> bool:
        """El par cuenta solo si acierta en la vulnerable Y queda limpio en la sana."""
        return self.vulnerable.cell == "TP" and self.safe.cell == "TN"


@dataclass
class Score:
    pairs: list[PairOutcome]
    tp: int
    fn: int
    fp: int
    tn: int
    unmapped: Counter

    @property
    def pair_score(self) -> float:
        return _ratio(sum(p.solved for p in self.pairs), len(self.pairs))

    @property
    def recall(self) -> float:
        return _ratio(self.tp, self.tp + self.fn)

    @property
    def fpr(self) -> float:
        return _ratio(self.fp, self.fp + self.tn)

    @property
    def precision(self) -> float:
        return _ratio(self.tp, self.tp + self.fp)

    @property
    def f1(self) -> float:
        denominator = self.precision + self.recall
        return 0.0 if denominator == 0 else 2 * self.precision * self.recall / denominator

    @property
    def localization(self) -> float:
        """% de TPs cuyo hallazgo cae en sink.line +/- LOCALIZATION_TOLERANCE."""
        located = [p.vulnerable for p in self.pairs if p.vulnerable.cell == "TP"]
        return _ratio(sum(bool(v.localized) for v in located), len(located))

    @property
    def noise(self) -> float:
        """Hallazgos no mapeados por variante."""
        variants = [v for p in self.pairs for v in (p.vulnerable, p.safe)]
        return _ratio(sum(v.noise for v in variants), len(variants))


def _ratio(numerator: int, denominator: int) -> float:
    return 0.0 if denominator == 0 else numerator / denominator


def _sink_path(sink_file: str, label: str) -> str:
    """meta.yaml guarda el sink con la variante adelante (`vulnerable/x.ts`),
    pero los Finding vienen relativos a la carpeta de la variante (`x.ts`)."""
    prefix = f"{label}/"
    return sink_file[len(prefix):] if sink_file.startswith(prefix) else sink_file


def _findings_by_variant(results: dict[str, Any]) -> dict[tuple[str, str], list[Finding]]:
    return {
        (entry["case_id"], entry["variant"]): [
            Finding.model_validate(f) for f in entry["findings"]
        ]
        for entry in results["variants"]
    }


def _judge(
    case: Case,
    label: str,
    findings: list[Finding],
    rule_map: RuleMap,
) -> VariantOutcome:
    expected = case.meta.family
    matched: list[Finding] = []
    security_hits: list[Finding] = []
    unmapped: list[str] = []

    for finding in findings:
        family = rule_map.family_of(finding.rule_id)
        if family is not None:
            security_hits.append(finding)
            if family == expected:
                matched.append(finding)
        elif rule_map.is_unmapped(finding.rule_id):
            unmapped.append(finding.rule_id)

    outcome = VariantOutcome(
        case_id=case.meta.id,
        label=label,
        cell="",
        matched=matched,
        unmapped=unmapped,
        noise=len(unmapped),
    )

    if label == "vulnerable":
        # TP = >=1 hallazgo mapeado a la familia esperada; si no, FN.
        outcome.cell = "TP" if matched else "FN"
        sink = case.meta.variants[label].sink
        if outcome.cell == "TP" and sink is not None:
            target = _sink_path(sink.file, label)
            outcome.localized = any(
                f.path == target and abs(f.line - sink.line) <= LOCALIZATION_TOLERANCE
                for f in matched
            )
    else:
        # FP = >=1 hallazgo de *cualquier* familia de seguridad; si no, TN.
        outcome.cell = "FP" if security_hits else "TN"

    return outcome


def tally(cases: list[Case], results: dict[str, Any], rule_map: RuleMap) -> Score:
    by_variant = _findings_by_variant(results)
    pairs: list[PairOutcome] = []
    unmapped: Counter = Counter()

    for case in cases:
        outcomes = {}
        for label in ("vulnerable", "safe"):
            findings = by_variant.get((case.meta.id, label), [])
            outcome = _judge(case, label, findings, rule_map)
            unmapped.update(outcome.unmapped)
            outcomes[label] = outcome
        pairs.append(
            PairOutcome(
                case_id=case.meta.id,
                vulnerable=outcomes["vulnerable"],
                safe=outcomes["safe"],
            )
        )

    cells = Counter(v.cell for p in pairs for v in (p.vulnerable, p.safe))
    return Score(
        pairs=pairs,
        tp=cells["TP"],
        fn=cells["FN"],
        fp=cells["FP"],
        tn=cells["TN"],
        unmapped=unmapped,
    )
