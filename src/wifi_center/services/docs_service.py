"""Documentation catalogue for the in-app reader: WIFI Center's own guides (Markdown), manual pages of installed tools
(rendered offline with `man`), package README files, and links to the tools' websites (opened only when the user asks).

Nothing is downloaded: guides and man pages are local files, and website links are never fetched by the application.
"""
from __future__ import annotations

import gzip
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..integrations.catalog import PROFILES

GUIDES, MANPAGES, PACKAGE_DOCS, WEBSITES = "WIFI Center guides", "Manual pages (offline)", "Package documentation (offline)", "Tool websites"
MAN_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,60}$")
OVERSTRIKE = re.compile(r".\x08")
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
MAX_DOC_BYTES = 2_000_000


@dataclass(frozen=True)
class DocEntry:
    id: str
    title: str
    group: str
    kind: str            # markdown | man | text | link
    source: str          # file path, man page name or URL
    summary: str = ""


# ------------------------------------------------------------------ pure helpers
def markdown_title_and_summary(text: str, fallback: str) -> tuple[str, str]:
    title, summary = fallback, ""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("# "):
            title = line[2:].strip()
            for nxt in lines[i + 1:]:
                s = nxt.strip()
                if s and not s.startswith(("#", "|", "```", "-", "*", ">")):
                    summary = s[:200]
                    break
            break
    return title, summary


def markdown_outline(text: str) -> list[tuple[int, str]]:
    """(level, heading) pairs, skipping code fences."""
    out, fence = [], False
    for line in text.splitlines():
        if line.startswith("```"):
            fence = not fence
        m = None if fence else re.match(r"^(#{1,4})\s+(.+?)\s*#*$", line)
        if m:
            out.append((len(m.group(1)), re.sub(r"[`*_]", "", m.group(2))))
    return out


def man_outline(text: str) -> list[tuple[int, str]]:
    """Man page section headings are lines in capitals starting at column 0."""
    return [(1, line.strip()) for line in text.splitlines()
            if line and not line[0].isspace() and line.upper() == line and re.match(r"^[A-Z][A-Z0-9 /&-]{2,}$", line.strip())]


def clean_man_output(text: str) -> str:
    return ANSI.sub("", OVERSTRIKE.sub("", text)).replace("\r", "")


def read_text_file(path: str, limit: int = MAX_DOC_BYTES) -> str:
    p = Path(path)
    opener = gzip.open if p.suffix == ".gz" else open
    with opener(p, "rb") as f:                                  # type: ignore[operator]
        data = f.read(limit + 1)
    text = data[:limit].decode("utf-8", errors="replace")
    return text + ("\n\n[… the file continues; only the first 2 MB are shown]" if len(data) > limit else "")


def resolve_link(current: str, href: str) -> str | None:
    """A relative Markdown link to another local guide (`OSINT_GUIDE.md`), as an absolute path, else None."""
    if "://" in href or href.startswith(("#", "mailto:")):
        return None
    target = (Path(current).parent / href.split("#")[0]).resolve()
    return str(target) if target.suffix.lower() == ".md" and target.is_file() else None


# ------------------------------------------------------------------ service
class DocsService:
    def __init__(self, docs_dirs: list[Path] | None = None, which: Callable[[str], str | None] = shutil.which,
                 run: Callable | None = None, doc_root: Path = Path("/usr/share/doc")) -> None:
        self._dirs = docs_dirs if docs_dirs is not None else [Path(__file__).resolve().parents[3] / "docs", Path("/usr/share/doc/wifi-center")]
        self._which = which
        self._run = run or (lambda argv, env, t: subprocess.run(argv, capture_output=True, text=True, env=env, timeout=t, errors="replace"))
        self._doc_root = doc_root

    # ---- catalogue
    def guides(self) -> list[DocEntry]:
        out: list[DocEntry] = []
        for base in self._dirs:
            if not base.is_dir():
                continue
            for p in sorted(base.iterdir()):
                if p.suffix.lower() not in (".md", ".txt"):
                    continue
                try:
                    text = read_text_file(str(p), 60_000)
                except OSError:
                    continue
                title, summary = markdown_title_and_summary(text, p.stem.replace("_", " ").title())
                out.append(DocEntry(f"guide:{p.name}", title, GUIDES, "markdown" if p.suffix == ".md" else "text", str(p), summary))
            if out:
                break
        return out

    def websites(self) -> list[DocEntry]:
        out = []
        for prof in PROFILES:
            out.append(DocEntry(f"web:{prof.id}:docs", f"{prof.name}: documentation", WEBSITES, "link", prof.docs_url, prof.description))
            if prof.source_url and prof.source_url != prof.docs_url:
                out.append(DocEntry(f"web:{prof.id}:src", f"{prof.name}: source / project", WEBSITES, "link", prof.source_url, prof.description))
        return out

    def _man_exists(self, name: str) -> bool:
        if not self._which("man") or not MAN_NAME.match(name):
            return False
        try:
            r = self._run(["man", "-w", name], self._env(), 8)
        except (OSError, subprocess.TimeoutExpired):
            return False
        return r.returncode == 0 and bool(r.stdout.strip())

    def local_tool_docs(self) -> list[DocEntry]:
        """Manual pages and package READMEs that exist on this system for the integrated tools."""
        out: list[DocEntry] = []
        seen: set[str] = set()
        for prof in PROFILES:
            for name in dict.fromkeys((*prof.executables, *prof.apt_packages)):
                if name not in seen and self._man_exists(name):
                    seen.add(name)
                    out.append(DocEntry(f"man:{name}", f"{name}({self._section(name)})  ·  {prof.name}", MANPAGES, "man", name, prof.description))
            for pkg in prof.apt_packages:
                d = self._doc_root / pkg
                if d.is_dir():
                    for fn in sorted(os.listdir(d)):
                        if re.match(r"^(README|NEWS|TODO)(\.[A-Za-z]+)?(\.gz)?$", fn, re.I):
                            out.append(DocEntry(f"pkg:{pkg}/{fn}", f"{pkg}: {fn.replace('.gz', '')}", PACKAGE_DOCS, "text", str(d / fn), prof.name))
        return out

    def _section(self, name: str) -> str:
        try:
            r = self._run(["man", "-w", name], self._env(), 8)
            m = re.search(r"man(\d)/", r.stdout)
            return m.group(1) if m else "1"
        except (OSError, subprocess.TimeoutExpired):
            return "1"

    def catalogue(self) -> list[DocEntry]:
        return self.guides() + self.local_tool_docs() + self.websites()

    @staticmethod
    def _env() -> dict[str, str]:
        return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8", "MANWIDTH": "100", "TERM": "dumb",
                "MANPAGER": "cat", "PAGER": "cat"}

    # ---- content
    def render(self, entry: DocEntry) -> tuple[str, str]:
        """(format, text): format is 'markdown' or 'text'. Raises OSError / ValueError when it cannot be read."""
        if entry.kind == "markdown":
            return "markdown", read_text_file(entry.source)
        if entry.kind == "text":
            return "text", read_text_file(entry.source)
        if entry.kind == "man":
            if not MAN_NAME.match(entry.source):
                raise ValueError("invalid manual page name")
            r = self._run(["man", "-P", "cat", entry.source], self._env(), 15)
            if r.returncode != 0 or not r.stdout.strip():
                raise OSError(f"no manual page for {entry.source}")
            return "text", clean_man_output(r.stdout)[:MAX_DOC_BYTES]
        raise ValueError("this entry is a website link; it opens in your browser")
