"""Slices: the few units the LLM needs to judge a candidate, instead of the whole project.

For a candidate at file:line:

1. the unit it falls in (for a template, the component that uses it);
2. the units that call it, one level up: who passes what into it;
3. what all of those use, one level down: injected services, helpers,
   interfaces, the environment object;
4. the template of every component in the slice.

Candidates that produce the same set of units share one slice, so the LLM gets
one request per slice, not one per rule hit. A slice keeps the original line
numbers, so the model reports lines that exist in the project.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from auditor.project import Project, Unit

CHARS_PER_TOKEN = 3.5
# Slices that share code are merged while the result stays under this size: a
# small project ends up as one request, a large one keeps separate slices.
SLICE_BUDGET_TOKENS = 4000


@dataclass(frozen=True)
class Candidate:
    file: str
    line: int
    rule_id: str
    family_hint: str | None = None


@dataclass
class Slice:
    units: tuple[Unit, ...]
    templates: tuple[str, ...]
    candidates: list[Candidate] = field(default_factory=list)

    @property
    def key(self) -> tuple:
        return (tuple(u.key for u in self.units), self.templates)

    def covers(self, file: str, line: int) -> bool:
        """Does the slice show this line? Templates count whole."""
        if file in self.templates:
            return True
        return any(u.file == file and u.start <= line <= u.end for u in self.units)

    def render(self, project: Project) -> str:
        """The slice as text, file by file, with the project's line numbers."""
        blocks = []
        by_file: dict[str, list[Unit]] = {}
        for unit in self.units:
            by_file.setdefault(unit.file, []).append(unit)
        for file in sorted(by_file):
            lines = project.files[file].lines
            parts = []
            for unit in sorted(by_file[file], key=lambda u: u.start):
                parts.append("\n".join(f"{n:4} | {lines[n - 1]}" for n in range(unit.start, unit.end + 1)))
            blocks.append(f"--- {file} ---\n" + "\n   ...\n".join(parts))
        for template in self.templates:
            lines = project.templates[template]
            blocks.append(f"--- {template} ---\n" + "\n".join(f"{n:4} | {t}" for n, t in enumerate(lines, 1)))
        return "\n\n".join(blocks)

    def tokens(self, project: Project) -> int:
        return round(len(self.render(project)) / CHARS_PER_TOKEN)


def _seed(project: Project, candidate: Candidate) -> list[Unit]:
    if candidate.file in project.templates:
        return project.components_for_template(candidate.file)
    unit = project.unit_at(candidate.file, candidate.line)
    return [unit] if unit is not None else []


def _uses(project: Project, unit: Unit) -> list[Unit]:
    found = []
    for name in unit.refs:
        target = project.resolve(name, unit.file)
        if target is not None and target.key != unit.key:
            found.append(target)
    return found


def slice_for(project: Project, candidate: Candidate) -> Slice | None:
    seed = _seed(project, candidate)
    if not seed:
        return None
    chosen: dict[tuple[str, int], Unit] = {u.key: u for u in seed}
    for unit in seed:
        for caller in project.callers(unit):
            chosen.setdefault(caller.key, caller)
    for unit in list(chosen.values()):
        for used in _uses(project, unit):
            chosen.setdefault(used.key, used)
    units = tuple(sorted(chosen.values(), key=lambda u: (u.file, u.start)))
    templates = tuple(sorted({u.template for u in units if u.template}))
    return Slice(units=units, templates=templates, candidates=[candidate])


def _union(a: Slice, b: Slice) -> Slice:
    units = {u.key: u for u in a.units + b.units}
    return Slice(
        units=tuple(sorted(units.values(), key=lambda u: (u.file, u.start))),
        templates=tuple(sorted(set(a.templates) | set(b.templates))),
        candidates=a.candidates + b.candidates,
    )


def _overlap(a: Slice, b: Slice) -> bool:
    return bool({u.key for u in a.units} & {u.key for u in b.units}) or bool(set(a.templates) & set(b.templates))


def merge_slices(project: Project, slices: list[Slice], budget: int = SLICE_BUDGET_TOKENS) -> list[Slice]:
    """Merge slices that share code while the merged slice fits the budget."""
    merged = list(slices)
    changed = True
    while changed:
        changed = False
        for i in range(len(merged)):
            for j in range(i + 1, len(merged)):
                if not _overlap(merged[i], merged[j]):
                    continue
                union = _union(merged[i], merged[j])
                if union.tokens(project) <= budget:
                    merged[i] = union
                    del merged[j]
                    changed = True
                    break
            if changed:
                break
    return merged


def build_slices(
    project: Project, candidates: list[Candidate], budget: int = SLICE_BUDGET_TOKENS
) -> tuple[list[Slice], list[Candidate]]:
    """Group candidates into slices. Returns (slices, candidates that fit no unit)."""
    slices: dict[tuple, Slice] = {}
    orphans: list[Candidate] = []
    for candidate in candidates:
        piece = slice_for(project, candidate)
        if piece is None:
            orphans.append(candidate)
            continue
        existing = slices.get(piece.key)
        if existing is None:
            slices[piece.key] = piece
        else:
            existing.candidates.append(candidate)
    return merge_slices(project, list(slices.values()), budget), orphans
