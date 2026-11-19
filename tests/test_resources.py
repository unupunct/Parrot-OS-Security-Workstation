import gzip
import hashlib
import os
import sys

import pytest

from wifi_center.services import password_policy as pp
from wifi_center.services import resource_catalog as rc
from wifi_center.services.resource_library import LibraryError, LibraryService, sniff_format


@pytest.fixture
def lib(controller, tmp_path):
    root = tmp_path / "lib"
    return LibraryService(controller.db, lambda: root, "wordlists")


def make(tmp_path, name="words.txt", content="alpha\nbravo\ncharlie\n"):
    p = tmp_path / "incoming" / name
    p.parent.mkdir(exist_ok=True)
    p.write_bytes(content.encode() if isinstance(content, str) else content)
    return str(p)


# ---------------- catalog ----------------
def test_catalog_has_the_ten_entries_with_required_metadata():
    assert len(rc.CATALOG) == 10 and len({e.id for e in rc.CATALOG}) == 10
    kinds = [e.kind for e in rc.CATALOG]
    assert kinds.count("reference") == 4 and kinds.count("generated") == 5 and kinds.count("local") == 1
    refs = {e.source_url for e in rc.CATALOG if e.kind == "reference"}
    assert refs == {"https://github.com/topics/rockyou-wordlist", "https://github.com/berzerk0/Probable-Wordlists",
                    "https://github.com/danielmiessler/SecLists/tree/master/Passwords",
                    "https://github.com/berzerk0/Probable-Wordlists/blob/master/Real-Passwords/WPA-Length/"
                    "Real-Password-WPA-MegaLinks.md"}
    for e in rc.CATALOG:
        assert e.license and e.description
        if e.kind == "reference":
            assert e.attribution and e.license_note and e.source_url.startswith("https://github.com/")
    assert rc.entry("probable-wordlists").license == "CC-BY-SA-4.0" and rc.entry("seclists-passwords").license == "MIT"


# ---------------- generators ----------------
def test_generators_are_deterministic_and_sized():
    for e in rc.CATALOG:
        if e.generator:
            a, b = rc.generate(e.id, seed=5), rc.generate(e.id, seed=5)
            assert a == b and a and all(line and "\n" not in line for line in a)
    assert len(rc.generate("synthetic-strong", 50, seed=1)) == 50
    assert rc.generate("synthetic-strong", 20, seed=1) != rc.generate("synthetic-strong", 20, seed=2)
    assert len(set(rc.generate("synthetic-weak-patterns", 0))) == len(rc.generate("synthetic-weak-patterns", 0))
    with pytest.raises(ValueError):
        rc.generate("probable-wordlists")


def test_generated_sets_behave_as_labelled_under_the_policy_engine():
    pol = pp.Policy()
    weak = rc.generate("synthetic-weak-patterns", 500, seed=3)
    assert 0.5 < sum(1 for p in weak if pp.evaluate(p, pol)) / len(weak) < 1.0     # rules alone miss some of them...
    words = set(rc._WORDS) | set(rc._SEASONS)
    assert all("blocklisted" in pp.evaluate(p, pol, None, words) for p in weak)    # ...a blocklist catches every one
    walks = rc.generate("synthetic-keyboard-walks", 0)
    assert sum(1 for p in walks if pp.evaluate(p, pol)) / len(walks) > 0.95
    strong = rc.generate("synthetic-strong", 300, seed=3)
    assert all(pp.evaluate(p, pol) == [] for p in strong)                          # all meet the default policy
    pairs = pp.parse_entries("\n".join(rc.generate("synthetic-userpass", 100, seed=3)), userpass=True)
    assert len(pairs) == 100 and all(u and u.startswith("user") for _, u, _p in pairs)
    ladder = rc.generate("synthetic-length-ladder")
    assert len(ladder) == len(set(ladder)) and min(map(len, ladder)) == 4 and max(map(len, ladder)) == 24
    p1 = pp.Policy(min_length=12, min_classes=4, forbid_sequences=True, max_repeat=3)
    ok = [x for x in ladder if not pp.evaluate(x, p1)]
    assert ok and all(len(x) >= 12 and pp.char_classes(x) == 4 for x in ok)       # the ladder probes the thresholds


# ---------------- import / safety ----------------
def test_import_copies_hashes_and_records_source(lib, tmp_path):
    src = make(tmp_path)
    res = lib.import_file(src, "Probable", source_url="https://example.org/x", license="MIT", attribution="Someone",
                          entry_id="seclists-passwords")
    d = lib.get(res.id)
    assert d["sha256"] == hashlib.sha256(b"alpha\nbravo\ncharlie\n").hexdigest()
    assert (d["size_bytes"], d["line_count"], d["format"], d["folder"]) == (20, 3, "text", "Probable")
    assert (lib.root / "Probable" / "words.txt").read_bytes() == b"alpha\nbravo\ncharlie\n"
    assert d["source_url"] == "https://example.org/x" and d["license"] == "MIT" and d["acquired_at"]
    assert os.path.exists(src)                                           # the original is left alone
    h = lib.history(res.id)
    assert h[0]["action"] == "import" and "words.txt" in h[0]["detail"]
    assert list((lib.root / "Probable").glob("*.part")) == []


def test_duplicates_and_name_collisions(lib, tmp_path):
    a = lib.import_file(make(tmp_path, "a.txt"))
    again = lib.import_file(make(tmp_path, "b.txt"))                      # same content, different name
    assert again.id == 0 and again.duplicate_of == a.id
    assert not (lib.root / "b.txt").exists()                              # nothing was kept
    forced = lib.import_file(make(tmp_path, "b.txt"), allow_duplicate=True)
    assert forced.id and forced.duplicate_of == a.id
    groups = lib.duplicates()
    assert len(groups) == 1 and {d["name"] for d in groups[0]} == {"a.txt", "b.txt"}
    with pytest.raises(LibraryError, match="already exists"):
        lib.import_file(make(tmp_path, "a.txt", "different\n"))


@pytest.mark.parametrize("bad", ["../evil.txt", "a/b.txt", "..", ".hidden", "name\x00.txt", "", "x" * 130, "con:.txt",
                                 "bad|name.txt", "trailing."])
def test_unsafe_names_are_refused(lib, tmp_path, bad):
    with pytest.raises(LibraryError):
        lib.import_file(make(tmp_path), name=bad)


@pytest.mark.parametrize("folder", ["..", "../x", "a/b", ".hidden", "x" * 70])
def test_unsafe_folders_are_refused(lib, tmp_path, folder):
    with pytest.raises(LibraryError):
        lib.import_file(make(tmp_path), folder)


def test_resolve_blocks_traversal_and_symlinks(lib, tmp_path):
    lib.ensure_root()
    with pytest.raises(Exception):
        lib.resolve("../outside.txt")
    outside = tmp_path / "outside"
    outside.mkdir()
    link = lib.root / "linked"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform")
    with pytest.raises(LibraryError, match="symbolic"):
        lib.resolve("linked/file.txt")


def test_import_rejects_missing_relative_and_symlink_sources(lib, tmp_path):
    for bad in ("relative.txt", str(tmp_path / "nope.txt"), str(tmp_path)):
        with pytest.raises(LibraryError):
            lib.import_file(bad)


def test_format_detection(tmp_path):
    def f(name, data):
        p = tmp_path / name
        p.write_bytes(data)
        return sniff_format(p)
    assert f("a.txt", b"hello\n") == "text" and f("a.csv", b"a,b\n") == "csv"
    assert f("a.gz", gzip.compress(b"x")) == "gzip" and f("a.zip", b"PK\x03\x04rest") == "zip"
    assert f("a.pdf", b"%PDF-1.7") == "pdf" and f("a.bin", b"\x00\x01\x02") == "binary"


# ---------------- rename / remove / verify ----------------
def test_rename_keeps_everything_consistent(lib, tmp_path):
    rid = lib.import_file(make(tmp_path), "Sets").id
    lib.rename(rid, "renamed.txt")
    d = lib.get(rid)
    assert d["name"] == "renamed.txt" and d["rel"] == "Sets/renamed.txt"
    assert (lib.root / "Sets" / "renamed.txt").exists() and not (lib.root / "Sets" / "words.txt").exists()
    other = lib.import_file(make(tmp_path, "o.txt", "other\n"), "Sets").id
    with pytest.raises(LibraryError, match="already exists"):
        lib.rename(other, "renamed.txt")
    with pytest.raises(LibraryError):
        lib.rename(other, "../escape.txt")
    assert lib.history(rid)[0]["action"] == "rename"


def test_remove_never_deletes_unless_asked(lib, tmp_path):
    rid = lib.import_file(make(tmp_path)).id
    f = lib.root / "words.txt"
    lib.remove(rid)                                                      # default: stop tracking only
    assert f.exists() and lib.get(rid) is None
    assert lib.untracked() == ["words.txt"]                              # and it shows up again, not lost
    rid2 = lib.adopt("words.txt")
    lib.remove(rid2, delete_file=True)                                   # explicit deletion
    assert not f.exists() and lib.history()[0]["action"] == "delete-file"


def test_integrity_verification(lib, tmp_path):
    rid = lib.import_file(make(tmp_path)).id
    assert lib.verify(rid) == "ok"
    (lib.root / "words.txt").write_text("tampered\n")
    assert lib.verify(rid) == "changed"
    (lib.root / "words.txt").unlink()
    assert lib.verify(rid) == "missing"
    assert lib.verify_all() == {rid: "missing"} and lib.verify(9999) == "missing"
    assert [h["detail"].split(": ")[-1] for h in lib.history(rid) if h["action"] == "verify"][:3] == [
        "missing", "missing", "changed"]


# ---------------- browsing / adopting ----------------
def test_untracked_discovery_and_adopt(lib, tmp_path):
    lib.ensure_root()
    (lib.root / "mine").mkdir()
    (lib.root / "mine" / "list.txt").write_text("a\nb\n")
    (lib.root / "top.lst").write_text("z\n")
    (lib.root / ".hidden").write_text("x")
    (lib.root / "half.txt.part").write_text("x")
    assert lib.untracked() == ["mine/list.txt", "top.lst"]
    rid = lib.adopt("mine/list.txt")
    assert lib.get(rid)["line_count"] == 2 and lib.get(rid)["folder"] == "mine"
    assert lib.untracked() == ["top.lst"]
    with pytest.raises(LibraryError, match="already tracked"):
        lib.adopt("mine/list.txt")
    with pytest.raises(LibraryError):
        lib.adopt("missing.txt")


def test_search_folders_favorites_and_storage(lib, tmp_path):
    a = lib.import_file(make(tmp_path, "alpha.txt", "one\n"), "A", source_url="https://s.example/a").id
    lib.import_file(make(tmp_path, "beta.txt", "two\n"), "B")
    assert set(lib.folders()) == {"A", "B"} and lib.folders()["A"] == 1
    assert [d["name"] for d in lib.files(query="alp")] == ["alpha.txt"]
    assert [d["name"] for d in lib.files(query="s.example")] == ["alpha.txt"]
    assert [d["name"] for d in lib.files(folder="B")] == ["beta.txt"]
    lib.set_favorite(a, True)
    assert [d["name"] for d in lib.files(favorites=True)] == ["alpha.txt"]
    st = lib.storage()
    assert st["used"] == 8 and st["files"] == 2 and st["free"] > 0


def test_two_libraries_do_not_mix(controller, tmp_path):
    w = LibraryService(controller.db, lambda: tmp_path / "w", "wordlists")
    l = LibraryService(controller.db, lambda: tmp_path / "l", "local")
    w.import_file(make(tmp_path, "same.txt"))
    l.import_file(make(tmp_path, "same.txt"))                            # same name and content, other library: fine
    assert [d["name"] for d in w.files()] == ["same.txt"] == [d["name"] for d in l.files()]
    assert w.duplicates() == [] and len(w.history()) == 1


# ---------------- generate + check source ----------------
def test_generate_registers_a_labelled_file(lib):
    rid = lib.generate("synthetic-strong", 40, seed=9)
    d = lib.get(rid)
    assert d["folder"] == "Generated" and d["line_count"] == 40 and d["entry_id"] == "synthetic-strong"
    assert "Synthetic" in d["license"] and d["attribution"].startswith("Generated locally")
    assert lib.history(rid)[0]["action"] == "generate"
    with pytest.raises(LibraryError):
        lib.generate("probable-wordlists")


def test_check_source_reports_license_and_availability(monkeypatch):
    class Resp:
        def __init__(self, body): self.body = body
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return self.body

    import json as _json
    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=0: Resp(_json.dumps(
        {"license": {"spdx_id": "CC-BY-SA-4.0"}, "archived": False, "pushed_at": "2023-10-04T20:22:09Z"}).encode()))
    r = LibraryService.check_source(rc.entry("probable-wordlists"))
    assert r["available"] and r["license"] == "CC-BY-SA-4.0" and r["license_matches"]
    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=0: Resp(_json.dumps(
        {"license": {"spdx_id": "GPL-3.0"}}).encode()))
    assert LibraryService.check_source(rc.entry("probable-wordlists"))["license_matches"] is False

    def boom(req, timeout=0):
        raise OSError("offline")
    monkeypatch.setattr("urllib.request.urlopen", boom)
    assert LibraryService.check_source(rc.entry("seclists-passwords"))["available"] is False
    assert LibraryService.check_source(rc.entry("rockyou-references"))["available"] is False


def test_library_follows_the_configured_directory(controller, tmp_path):
    controller.settings.set("general.resources_dir", str(tmp_path / "chosen"))
    assert controller.wordlists.root == tmp_path / "chosen"
    controller.settings.set("general.resources_dir", "")
    assert controller.wordlists.root == controller.paths.default_resources_dir
    assert controller.local_resources.root == controller.paths.default_resources_dir.parent / "Local"
