"""The project index and the slicer, on corpus variants and small synthetic projects."""

from __future__ import annotations

from pathlib import Path

from auditor.project import load_project
from auditor.slicer import Candidate, build_slices, merge_slices, slice_for

ANGULAR = Path(__file__).resolve().parent.parent / "corpus" / "angular"


def test_a_component_slice_brings_its_template_and_injected_service():
    project = load_project(ANGULAR / "xss-sanitizer-bypass/004-service-route-component-bypass/vulnerable")
    piece = slice_for(project, Candidate("profile.component.ts", 19, "hot-xss-bypass-trust"))
    files = {u.file for u in piece.units}
    assert files == {"profile.component.ts", "profile-bio.service.ts"}
    assert piece.templates == ("profile.component.html",)


def test_a_helper_slice_brings_whoever_calls_it():
    """The storage wrapper alone does not say what is stored; its caller does."""
    project = load_project(ANGULAR / "client-side-secrets/005-storage-service-token/vulnerable")
    piece = slice_for(project, Candidate("storage.service.ts", 7, "hot-sec-browser-storage"))
    assert "session.service.ts" in {u.file for u in piece.units}
    assert piece.covers("session.service.ts", 13)  # the sink, in the caller


def test_a_template_candidate_maps_to_its_component():
    project = load_project(ANGULAR / "xss-sanitizer-bypass/006-safe-html-pipe/vulnerable")
    piece = slice_for(project, Candidate("comment.component.html", 1, "hot-xss-template-binding"))
    assert "comment.component.ts" in {u.file for u in piece.units}


def test_the_rendered_slice_keeps_the_project_line_numbers():
    project = load_project(ANGULAR / "client-side-secrets/002-token-in-localstorage/vulnerable")
    piece = slice_for(project, Candidate("auth.service.ts", 12, "hot-sec-browser-storage"))
    assert "  12 |         localStorage.setItem('access_token', response.accessToken);" in piece.render(project)


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return root


def test_imports_with_parent_directories_resolve(tmp_path):
    root = _write(
        tmp_path,
        {
            "shared/escape.ts": "export function escapeHtml(v: string): string {\n  return v;\n}\n",
            "app/view.ts": "import { escapeHtml } from '../shared/escape';\n\nexport function show(x: string) {\n  return escapeHtml(x);\n}\n",
        },
    )
    project = load_project(root)
    piece = slice_for(project, Candidate("app/view.ts", 4, "hot"))
    assert "shared/escape.ts" in {u.file for u in piece.units}


def test_a_candidate_outside_any_unit_is_an_orphan(tmp_path):
    root = _write(tmp_path, {"a.ts": "import { x } from './b';\n\nexport const y = 1;\n", "b.ts": "export const x = 1;\n"})
    slices, orphans = build_slices(load_project(root), [Candidate("a.ts", 1, "hot")])
    assert slices == [] and len(orphans) == 1


def test_overlapping_slices_merge_only_under_the_budget(tmp_path):
    root = _write(
        tmp_path,
        {
            "lib.ts": "export function shared() {\n  return 1;\n}\n",
            "a.ts": "import { shared } from './lib';\nexport function a() {\n  return shared();\n}\n",
            "b.ts": "import { shared } from './lib';\nexport function b() {\n  return shared();\n}\n",
        },
    )
    project = load_project(root)
    pa = slice_for(project, Candidate("a.ts", 3, "hot"))
    pb = slice_for(project, Candidate("b.ts", 3, "hot"))
    assert len(merge_slices(project, [pa, pb], budget=10_000)) == 1
    assert len(merge_slices(project, [pa, pb], budget=1)) == 2
