"""Parrot OS 6 ships Python 3.11: guard against syntax that only parses on newer interpreters."""
import pathlib
import re

ROOT = pathlib.Path(__file__).parents[1]


def _nested_quote_pattern(q: str) -> re.Pattern:
    # f"...{ ... " ... }..."  (reusing the f-string's own quote inside a replacement field: Python 3.12+ only)
    body = r'(?:[^' + q + r'\\\n]|\\.)*'
    field = r'\{[^{}\n]*' + q + r'[^{}\n]*\}'
    return re.compile("f" + q + body + field)


def test_no_python_312_only_fstring_quotes():
    pats = [_nested_quote_pattern('"'), _nested_quote_pattern("'")]
    offenders = []
    for p in [*ROOT.joinpath("src").rglob("*.py"), *ROOT.joinpath("tests").rglob("*.py")]:
        if p.name == "test_portability.py":
            continue
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if any(pt.search(line) for pt in pats):
                offenders.append(f"{p.relative_to(ROOT)}:{n}: {line.strip()[:100]}")
    assert offenders == [], "Python 3.12-only f-string quoting:\n" + "\n".join(offenders)


def test_declared_minimum_python_matches_the_target_os():
    text = ROOT.joinpath("pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'requires-python\s*=\s*"[>=]*(\d+)\.(\d+)"', text)
    assert m and (int(m.group(1)), int(m.group(2))) <= (3, 11)


def test_no_walrus_free_syntax_beyond_311():
    banned = [re.compile(r"^\s*type\s+\w+\s*=", re.M), re.compile(r"\bexcept\*")]   # 3.12 `type` statements, (3.11 ok for except*)
    for p in ROOT.joinpath("src").rglob("*.py"):
        text = p.read_text(encoding="utf-8")
        assert not banned[0].search(text), f"3.12 `type` statement in {p}"
