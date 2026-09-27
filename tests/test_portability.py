"""
Linux and Windows must give the same results.

The code runs natively on both (python run_app.py on a Windows laptop) and in Linux containers on
both (docker compose). Three things differ between the two and have broken tests before:

- text files: without encoding="utf-8", Python reads and writes them in the locale's encoding,
  which is UTF-8 on Linux and cp1252 on Windows, so any non-ASCII character (an em dash in a
  config comment, a user name in a log line) is read differently or fails;
- line endings: Windows programs write CRLF, and git for Windows checks text files out with CRLF
  unless .gitattributes says otherwise, so a line cut at LF keeps a CR at its end;
- child processes: their output is decoded in the locale's encoding unless told otherwise.

The first and third are checked here by reading the source, so they fail on Linux too, before a
Windows machine ever sees them. The second is covered by .gitattributes (checked below) and by
the CRLF tests of every input (test_connectors.py, test_lossless.py).
"""
import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CHECKED = ["backend", "frontend", "scripts", "tests", "run_app.py"]


def python_files():
    for entry in CHECKED:
        path = ROOT / entry
        yield from ([path] if path.is_file() else sorted(path.rglob("*.py")))


def _keywords(call: ast.Call) -> set:
    return {k.arg for k in call.keywords}


def _literal(node) -> str:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else ""


def locale_dependent_calls(tree: ast.AST):
    """(line, what) for each call whose result depends on the machine's locale encoding."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f, kw = node.func, _keywords(node)
        if isinstance(f, ast.Name) and f.id == "open":
            mode = _literal(node.args[1]) if len(node.args) > 1 else next(
                (_literal(k.value) for k in node.keywords if k.arg == "mode"), "r")
            if "b" not in mode and "encoding" not in kw:
                yield node.lineno, f"open(..., {mode!r}) without encoding="
        elif isinstance(f, ast.Attribute) and f.attr in ("read_text", "write_text") and "encoding" not in kw:
            yield node.lineno, f".{f.attr}() without encoding="
        elif isinstance(f, ast.Attribute) and f.attr == "open" and node.args and "encoding" not in kw:
            mode = _literal(node.args[0])       # Path.open("a"); gzip.open(path, "rb") has a path first
            if mode and set(mode) <= set("rwax+t") and "b" not in mode:
                yield node.lineno, f".open({mode!r}) without encoding="
        elif (isinstance(f, ast.Attribute) and f.attr in ("run", "Popen", "check_output")
              and isinstance(f.value, ast.Name) and f.value.id == "subprocess"
              and ({"text", "universal_newlines"} & kw) and "encoding" not in kw):
            yield node.lineno, f"subprocess.{f.attr}(text=True) without encoding="


def test_no_text_io_depends_on_the_locale():
    found = []
    for path in python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        found += [f"{path.relative_to(ROOT)}:{line}: {what}" for line, what in locale_dependent_calls(tree)]
    assert not found, "pass encoding=\"utf-8\" (see this file's docstring):\n" + "\n".join(found)


@pytest.mark.parametrize("snippet, flagged", [
    ('open("x")', True), ('open("x", "rb")', False), ('open("x", "w", encoding="utf-8")', False),
    ('p.read_text()', True), ('p.write_text(s, encoding="utf-8")', False), ('p.open("a")', True),
    ('gzip.open(p, "rt")', False), ('subprocess.run(a, text=True)', True),
    ('subprocess.run(a, text=True, encoding="utf-8")', False), ('subprocess.run(a)', False),
])
def test_the_locale_check_itself(snippet, flagged):
    assert bool(list(locale_dependent_calls(ast.parse(snippet)))) is flagged


def test_git_checks_text_out_with_lf_on_every_os():
    rules = (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
    assert "* text=auto eol=lf" in rules, "git for Windows would check out CRLF (core.autocrlf=true)"
    # files whose bytes are pinned by a hash, and binaries, are never converted
    assert any(r.startswith("backend/static/swagger-ui/**") and "-text" in r for r in rules)
    for ext in ("png", "pdf", "parquet", "gz"):
        assert any(r.startswith(f"*.{ext}") and "binary" in r for r in rules), ext



class _LeapYear(__import__("datetime").datetime):
    @classmethod
    def now(cls, tz=None):
        return __import__("datetime").datetime(2028, 3, 1, 12, 0, tzinfo=tz)


def test_a_timestamp_without_a_year_is_read_with_this_years(monkeypatch):
    """BSD syslog leaves the year out. Read on its own, "Feb 29" is dated 1900, which has no Feb 29,
    and Python 3.13+ warns about it (3.15 changes the default year); read with the current year it
    is an ordinary date in a leap year."""
    import warnings

    from backend.services import timefmt
    from backend.services.normalization import ocsf_normalizer
    from backend.services.parsing import inference
    monkeypatch.setattr(inference, "datetime", _LeapYear)
    monkeypatch.setattr(ocsf_normalizer, "datetime", _LeapYear)
    timefmt.clear()
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert inference.as_time("Feb 29 10:00:00") == "2028-02-29T10:00:00+00:00"
        dt = ocsf_normalizer.OCSFNormalizer._read_time("Feb 29 10:00:00")
    assert (dt.year, dt.month, dt.day) == (2028, 2, 29)
    timefmt.clear()
