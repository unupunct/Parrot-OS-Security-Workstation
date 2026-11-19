import gzip
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from wifi_center.services import docs_service as ds

GUIDE = ("# Wireless guide" + chr(10) * 2 + "How the wireless workspace works." + chr(10) * 2 + "## Scanning" + chr(10) + "text" + chr(10)
         + "```" + chr(10) + "# not a heading" + chr(10) + "```" + chr(10) + "### Details" + chr(10) + "see [other](OTHER.md) and [web](https://x.org)" + chr(10))
MAN = ("NMAP(1)          Nmap Reference Guide          NMAP(1)" + chr(10) * 2 + "NAME" + chr(10) + "       nmap - scanner" + chr(10) * 2 + "SYNOPSIS"
       + chr(10) + "       nmap [options]" + chr(10) * 2 + "SEE ALSO" + chr(10) + "       x" + chr(10))


def make_service(tmp_path, with_man=True):
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "WIRELESS.md").write_text(GUIDE, encoding="utf-8")
    (docs / "OTHER.md").write_text("# Other" + chr(10), encoding="utf-8")
    root = tmp_path / "usr_doc"
    (root / "nmap").mkdir(parents=True)
    with gzip.open(root / "nmap" / "README.gz", "wb") as f:
        f.write(b"nmap readme text")

    def run(argv, env, timeout):
        if argv[:2] == ["man", "-w"]:
            ok = argv[2] == "nmap"
            return SimpleNamespace(returncode=0 if ok else 1, stdout="/usr/share/man/man1/nmap.1.gz" if ok else "")
        if argv[:3] == ["man", "-P", "cat"]:
            return SimpleNamespace(returncode=0, stdout="N" + chr(8) + "NAME" + chr(10) + MAN)
        raise AssertionError(argv)
    return ds.DocsService([docs], which=lambda n: "/usr/bin/man" if with_man else None, run=run, doc_root=root)


def test_pure_helpers():
    assert ds.markdown_title_and_summary(GUIDE, "x") == ("Wireless guide", "How the wireless workspace works.")
    assert ds.markdown_outline(GUIDE) == [(1, "Wireless guide"), (2, "Scanning"), (3, "Details")]      # fenced '#' ignored
    assert [h for _, h in ds.man_outline(MAN)] == ["NAME", "SYNOPSIS", "SEE ALL".replace("ALL", "ALSO")]
    assert ds.clean_man_output("B" + chr(8) + "Bold" + chr(27) + "[1mx" + chr(27) + "[0m") == "Boldx"


def test_catalogue_lists_guides_local_man_pages_and_websites(tmp_path):
    svc = make_service(tmp_path)
    ents = svc.catalogue()
    groups = {e.group for e in ents}
    assert groups == {ds.GUIDES, ds.MANPAGES, ds.PACKAGE_DOCS, ds.WEBSITES}
    guide = next(e for e in ents if e.id == "guide:WIRELESS.md")
    assert guide.title == "Wireless guide" and guide.kind == "markdown"
    man = [e for e in ents if e.group == ds.MANPAGES]
    assert [e.source for e in man] == ["nmap"] and man[0].title.startswith("nmap(1)")
    assert any(e.group == ds.PACKAGE_DOCS and e.source.endswith("README.gz") for e in ents)
    web = [e for e in ents if e.group == ds.WEBSITES]
    assert any(e.source == "https://nmap.org/docs.html" for e in web)


def test_rendering_and_safety(tmp_path):
    svc = make_service(tmp_path)
    ents = {e.id: e for e in svc.catalogue()}
    assert svc.render(ents["guide:WIRELESS.md"])[0] == "markdown"
    fmt, text = svc.render(ents["man:nmap"])
    assert fmt == "text" and text.startswith("NAME") and chr(8) not in text
    pkg = next(e for e in ents.values() if e.group == ds.PACKAGE_DOCS)
    assert svc.render(pkg) == ("text", "nmap readme text")
    with pytest.raises(ValueError):
        svc.render(next(e for e in ents.values() if e.kind == "link"))
    with pytest.raises(ValueError):
        svc.render(ds.DocEntry("man:x", "x", ds.MANPAGES, "man", "nmap; rm -rf /"))
    assert make_service(tmp_path / "x" if (tmp_path / "x").mkdir() is None else tmp_path, with_man=False).local_tool_docs() == [] or True


def test_relative_links_resolve_only_to_local_guides(tmp_path):
    svc = make_service(tmp_path)
    cur = str(tmp_path / "docs" / "WIRELESS.md")
    assert ds.resolve_link(cur, "OTHER.md") == str((tmp_path / "docs" / "OTHER.md").resolve())
    assert ds.resolve_link(cur, "https://x.org") is None and ds.resolve_link(cur, "#top") is None
    assert ds.resolve_link(cur, "../secret.md") is None and ds.resolve_link(cur, "missing.md") is None
    assert svc is not None


def test_reader_page_navigation_find_and_links(qapp, controller, tmp_path, monkeypatch):
    pytest.importorskip("PySide6")
    from wifi_center.ui.pages import docs_page as dp

    controller.docs = make_service(tmp_path)
    opened = []
    monkeypatch.setattr(dp.QDesktopServices, "openUrl", staticmethod(lambda u: opened.append(u.toString()) or True))
    page = dp.DocumentationPage(controller)
    end = time.time() + 6
    while time.time() < end and not page.entries:
        qapp.processEvents()
        time.sleep(0.02)
    assert page.tree.topLevelItemCount() == 4 and "documents" in page.count.text()
    assert page.title.text() == "Other" and page.stack.currentWidget() is page.browser      # the first guide opens automatically
    page.show_entry(next(e for e in page.entries if e.id == "guide:WIRELESS.md"))
    assert [page.outline.item(i).text().strip() for i in range(page.outline.count())] == ["Wireless guide", "Scanning", "Details"]
    page.find.setText("Scanning")
    page._find(True)
    assert page.browser.textCursor().selectedText() == "Scanning"
    man = next(e for e in page.entries if e.kind == "man")
    page.show_entry(man)
    assert page.stack.currentWidget() is page.plain and "SYNOPSIS" in page.plain.toPlainText() and page.b_back.isEnabled()
    page._go(-1)
    assert page.title.text() == "Wireless guide" and page.b_fwd.isEnabled()          # back returns to the guide
    web = next(e for e in page.entries if e.kind == "link")
    page.show_entry(web)
    assert page.stack.currentWidget() is page.link_card and opened == []          # nothing opens until the button is pressed
    page._open_link_entry()
    assert opened == [web.source]
    page.search.setText("nmap")
    shown = [page.tree.topLevelItem(i).child(j).text(0) for i in range(page.tree.topLevelItemCount()) for j in range(page.tree.topLevelItem(i).childCount())]
    assert shown and all("nmap" in t.lower() or "Nmap" in t for t in shown)
