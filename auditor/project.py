"""A TypeScript/Angular project as units the slicer can pick from.

A **unit** is one top-level declaration of a file: a class with its decorators,
a function, an exported constant (Angular functional guards and resolvers are
constants), an interface or a type. Units are what a slice is made of, so a
slice never cuts a function in half.

For every unit the project records which names it declares, which identifiers
it references, and where each imported name comes from. That is enough to walk
"what does this use" and "who uses this" one level at a time, without type
resolution.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path

import tree_sitter as ts
import tree_sitter_typescript as ts_typescript

SOURCE_SUFFIXES = (".ts",)
TEMPLATE_SUFFIXES = (".html",)
SKIP_DIRS = {"node_modules", "dist", ".angular", ".git", "coverage"}

UNIT_TYPES = {
    "class_declaration",
    "abstract_class_declaration",
    "function_declaration",
    "generator_function_declaration",
    "lexical_declaration",
    "variable_declaration",
    "interface_declaration",
    "type_alias_declaration",
    "enum_declaration",
}

TEMPLATE_URL = re.compile(r"templateUrl\s*:\s*['\"]([^'\"]+)['\"]")


@cache
def _parser() -> ts.Parser:
    return ts.Parser(ts.Language(ts_typescript.language_typescript()))


@dataclass(frozen=True)
class Unit:
    file: str  # relative to the project root
    start: int  # 1-based, inclusive
    end: int
    names: tuple[str, ...]  # what it declares
    kind: str
    refs: frozenset[str] = field(default=frozenset(), compare=False)  # identifiers it uses
    template: str | None = None  # templateUrl of a component, resolved

    @property
    def key(self) -> tuple[str, int]:
        return (self.file, self.start)


@dataclass
class SourceFile:
    path: str
    lines: list[str]
    units: list[Unit]
    imports: dict[str, str]  # local name -> resolved relative file


@dataclass
class Project:
    root: Path
    files: dict[str, SourceFile]
    templates: dict[str, list[str]]  # relative html path -> lines

    def unit_at(self, file: str, line: int) -> Unit | None:
        source = self.files.get(file)
        if source is None:
            return None
        for unit in source.units:
            if unit.start <= line <= unit.end:
                return unit
        return None

    def components_for_template(self, template: str) -> list[Unit]:
        return [u for f in self.files.values() for u in f.units if u.template == template]

    def resolve(self, name: str, from_file: str) -> Unit | None:
        """The unit a name refers to: declared in the same file, or imported from a local file."""
        source = self.files[from_file]
        for unit in source.units:
            if name in unit.names:
                return unit
        target = source.imports.get(name)
        if target and target in self.files:
            for unit in self.files[target].units:
                if name in unit.names:
                    return unit
        return None

    def callers(self, unit: Unit) -> list[Unit]:
        """Units in other places that reference something this unit declares."""
        found = []
        for source in self.files.values():
            for other in source.units:
                if other.key == unit.key:
                    continue
                for name in unit.names:
                    if name in other.refs and self.resolve(name, other.file) == unit:
                        found.append(other)
                        break
        return found


def _text(node: ts.Node, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _declared_names(node: ts.Node, src: bytes) -> tuple[str, ...]:
    if node.type in ("lexical_declaration", "variable_declaration"):
        names = []
        for child in node.named_children:
            if child.type == "variable_declarator":
                name = child.child_by_field_name("name")
                if name is not None and name.type == "identifier":
                    names.append(_text(name, src))
        return tuple(names)
    name = node.child_by_field_name("name")
    return (_text(name, src),) if name is not None else ()


def _refs(node: ts.Node, src: bytes) -> frozenset[str]:
    found: set[str] = set()
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type in ("identifier", "type_identifier", "property_identifier", "shorthand_property_identifier"):
            found.add(_text(current, src))
        stack.extend(current.children)
    return frozenset(found)


def _resolve_import(from_file: str, spec: str, known: set[str]) -> str | None:
    if not spec.startswith("."):
        return None
    base = os.path.normpath((Path(from_file).parent / spec).as_posix())
    for candidate in (f"{base}.ts", f"{base}/index.ts", base):
        if candidate in known:
            return candidate
    return None


def _imports(tree: ts.Tree, src: bytes, from_file: str, known: set[str]) -> dict[str, str]:
    imports: dict[str, str] = {}
    for node in tree.root_node.named_children:
        if node.type != "import_statement":
            continue
        source = node.child_by_field_name("source")
        if source is None:
            continue
        target = _resolve_import(from_file, _text(source, src).strip("'\""), known)
        if target is None:
            continue
        for ident in _refs(node, src):
            imports[ident] = target
    return imports


def _units(tree: ts.Tree, src: bytes, path: str, known_templates: set[str]) -> list[Unit]:
    units = []
    for node in tree.root_node.named_children:
        decl = node
        if node.type == "export_statement":
            inner = node.child_by_field_name("declaration") or next(
                (c for c in node.named_children if c.type in UNIT_TYPES), None
            )
            if inner is None:
                continue
            decl = inner
        if decl.type not in UNIT_TYPES:
            continue
        body = _text(node, src)
        template = None
        match = TEMPLATE_URL.search(body)
        if match:
            resolved = os.path.normpath((Path(path).parent / match.group(1)).as_posix())
            template = resolved if resolved in known_templates else None
        units.append(
            Unit(
                file=path,
                start=node.start_point[0] + 1,
                end=node.end_point[0] + 1,
                names=_declared_names(decl, src),
                kind=decl.type,
                refs=_refs(node, src),
                template=template,
            )
        )
    return units


def load_project(root: Path) -> Project:
    root = root.resolve()
    paths = [
        p
        for p in sorted(root.rglob("*"))
        if p.is_file() and not any(part in SKIP_DIRS for part in p.relative_to(root).parts)
    ]
    sources = [p for p in paths if p.suffix in SOURCE_SUFFIXES and not p.name.endswith(".d.ts")]
    known = {p.relative_to(root).as_posix() for p in sources}
    templates = {
        p.relative_to(root).as_posix(): p.read_text(encoding="utf-8", errors="replace").splitlines()
        for p in paths
        if p.suffix in TEMPLATE_SUFFIXES
    }
    files: dict[str, SourceFile] = {}
    for path in sources:
        rel = path.relative_to(root).as_posix()
        src = path.read_bytes()
        tree = _parser().parse(src)
        files[rel] = SourceFile(
            path=rel,
            lines=src.decode("utf-8", errors="replace").splitlines(),
            units=_units(tree, src, rel, set(templates)),
            imports=_imports(tree, src, rel, known),
        )
    return Project(root=root, files=files, templates=templates)
