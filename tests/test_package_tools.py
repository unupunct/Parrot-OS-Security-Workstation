import gzip
from types import SimpleNamespace

import pytest

from wifi_center.services import package_tools as pt
from wifi_center.services.apt_service import Transaction


def nl(*lines):
    return chr(10).join(lines) + chr(10)


DEPENDS = nl("htop", "  Depends: libc6", "  Depends: libncursesw6", " |Depends: libtinfo6", "  Depends: <awk>", "  Recommends: lm-sensors",
             "  Suggests: strace", "  Conflicts: oldhtop")
VERIFY = nl("??5??????  c /etc/htoprc", "missing     /usr/bin/htop", ".M.......    /usr/share/doc/htop/x", "garbage line")
RDEPS = nl("htop", "Reverse Depends:", "  parrot-apps-basics", " |meta-tools", "  parrot-apps-basics")


class FakeApt:
    def __init__(self):
        self.calls = []

    def plan(self, kind, packages=None):
        self.calls.append(kind)
        return Transaction(kind)


def make(tmp_path, outputs):
    def run(argv, t):
        key = " ".join(argv[:2])
        for k, v in outputs.items():
            if key.startswith(k):
                return SimpleNamespace(ok=True, stdout=v)
        return SimpleNamespace(ok=False, stdout="")
    doc = tmp_path / "doc"
    (doc / "htop").mkdir(parents=True)
    with gzip.open(doc / "htop" / "changelog.Debian.gz", "wb") as f:
        f.write(b"htop (3.4.1-5) unstable; urgency=medium\n\n  * Fix\n")
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "a_1_amd64.deb").write_bytes(b"x" * 100)
    (cache / "b_1_amd64.deb").write_bytes(b"y" * 300)
    (cache / "lock").write_bytes(b"")
    return pt.PackageTools(FakeApt(), run, doc, cache, which=lambda n: "/usr/bin/" + n)


def test_parsers():
    assert pt.parse_files(nl("/.", "/usr", "/usr/bin/htop", "diverted by x")) == ["/usr", "/usr/bin/htop"]
    deps = pt.parse_depends(DEPENDS)
    assert [(d.kind, d.name, d.alternative, d.virtual) for d in deps] == [
        ("Depends", "libc6", False, False), ("Depends", "libncursesw6", False, False), ("Depends", "libtinfo6", True, False),
        ("Depends", "awk", False, True), ("Recommends", "lm-sensors", False, False), ("Suggests", "strace", False, False),
        ("Conflicts", "oldhtop", False, False)]
    assert pt.parse_rdepends(RDEPS) == ["parrot-apps-basics", "meta-tools"]
    issues = pt.parse_verify(VERIFY)
    assert [(i.path, i.config) for i in issues] == [("/etc/htoprc", True), ("/usr/bin/htop", False), ("/usr/share/doc/htop/x", False)]
    assert "checksum" in issues[0].meaning and issues[1].meaning == "the file is missing" and "mode" in issues[2].meaning
    assert pt.parse_audit(nl("The following packages are only half configured:", " foo  A thing", " bar  Another")) == ["foo", "bar"]
    rows = pt.parse_removed(nl("ii |bash|5.2|1500|shell", "rc |isc-dhcp-server|4.4|2000|DHCP server", "rc |old|1|abc|x"))
    assert [(r.name, r.status, r.size_kb) for r in rows] == [("isc-dhcp-server", "config-files", 2000), ("old", "config-files", 0)]


def test_package_names_are_validated_before_any_command_runs(tmp_path):
    t = make(tmp_path, {})
    for bad in ("--help", "a;b", "x y", "../etc", ""):
        with pytest.raises(Exception):
            t.files(bad)
        with pytest.raises(Exception):
            t.changelog_local(bad)


def test_files_dependencies_verify_and_changelog(tmp_path):
    t = make(tmp_path, {"dpkg -L": nl("/.", "/usr/bin/htop"), "apt-cache depends": DEPENDS, "apt-cache rdepends": RDEPS, "dpkg --verify": VERIFY})
    assert t.files("htop") == ["/usr/bin/htop"] and len(t.dependencies("htop")) == 7
    assert t.reverse_dependencies("htop") == ["parrot-apps-basics", "meta-tools"]
    assert len(t.verify("htop")) == 3
    assert t.changelog_local("htop").startswith("htop (3.4.1-5)") and t.changelog_local("nothing") is None
    assert pt.PackageTools(FakeApt(), lambda a, t: SimpleNamespace(ok=False, stdout=""), which=lambda n: None).files("htop") == []     # tool missing: empty, not a crash


def test_dependency_tree_is_bounded_and_marks_repeats(tmp_path):
    graph = {"pkg-a": ["pkg-b", "pkg-c"], "pkg-b": ["pkg-c", "pkg-a"], "pkg-c": []}

    def run(argv, t):
        if argv[0] == "apt-cache":
            return SimpleNamespace(ok=True, stdout=nl(argv[-1], *[f"  Depends: {d}" for d in graph.get(argv[-1], [])]))
        return SimpleNamespace(ok=True, stdout="ii ")
    t = pt.PackageTools(FakeApt(), run, tmp_path, tmp_path, which=lambda n: "/x/" + n)
    tree = t.dependency_tree("pkg-a", depth=3)
    assert [c.name for c in tree.children] == ["pkg-b", "pkg-c"] and tree.installed is True
    b = tree.children[0]
    assert [c.name for c in b.children] == ["pkg-c", "pkg-a"] and b.children[1].repeated                      # the cycle is shown once, not followed
    small = t.dependency_tree("pkg-a", depth=3, max_nodes=2)
    assert len(small.children) <= 2


def test_cache_info_and_broken(tmp_path):
    t = make(tmp_path, {"dpkg --audit": nl(" foo  half configured")})
    ci = t.cache_info()
    assert (ci.files, ci.total_bytes) == (2, 400) and ci.largest[0] == ("b_1_amd64.deb", 300)
    audit, fix = t.broken()
    assert audit == ["foo"] and fix is not None and t._apt.calls == ["fix-broken"]
    assert t.orphans().kind == "autoremove" and t.upgradable().kind == "upgrade"
