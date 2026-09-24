"""
The architecture documents are part of the deliverable. The diagram in ARCHITECTURE.md must be the
one in its source file (the rendered PNG and SVG are made from that file), and every file the
documents link to must exist.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _statements(mermaid: str):
    return [line.strip() for line in mermaid.splitlines() if line.strip() and not line.strip().startswith("%% ")]


def test_the_diagram_in_the_architecture_document_is_its_source_file():
    doc = (ROOT / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8")
    block = re.search(r"```mermaid\n(.*?)```", doc, re.S).group(1)
    source = (ROOT / "docs" / "diagrams" / "architecture.mmd").read_text(encoding="utf-8")
    assert _statements(block) == _statements(source)


def test_every_relative_link_in_the_documents_resolves():
    missing = []
    for md in [ROOT / "README.md", ROOT / "CLAUDE.md", *sorted((ROOT / "docs").rglob("*.md"))]:
        for target in re.findall(r"\]\(([^)\s#]+)(?:#[^)]*)?\)", md.read_text(encoding="utf-8")):
            if "://" in target or target.startswith("mailto:"):
                continue
            if not (md.parent / target).exists():
                missing.append(f"{md.relative_to(ROOT)} -> {target}")
    assert missing == []
