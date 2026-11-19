import csv
import hashlib
import io
import json
from urllib.parse import urlparse

import pytest

from wifi_center.security.input_validation import ValidationError
from wifi_center.services import osint_service as osv
from wifi_center.services.osint_catalog import CATALOG, CATEGORIES, INPUT_TYPES, by_slug


@pytest.fixture
def osint(controller):
    return controller.osint


# ---------------- catalog integrity ----------------
def test_catalog_is_complete_and_well_formed():
    slugs = [r.slug for r in CATALOG]
    assert len(slugs) == len(set(slugs)) >= 50
    covered = {c for r in CATALOG for c in r.categories}
    assert covered == set(CATEGORIES)                         # every required category has resources
    for r in CATALOG:
        osv.validate_template(r.url_template) if r.supports_term else None
        u = urlparse(r.url_template)
        assert u.scheme == "https" and u.hostname and not u.username, r.slug
        assert set(r.input_types) <= set(INPUT_TYPES) and r.categories and r.description, r.slug
        if r.supports_term:
            assert r.url_template.count("{term}") + r.url_template.count("{term_md5}") == 1, r.slug
            assert "{term" not in u.netloc, r.slug
        else:
            assert "{" not in r.url_template, r.slug


def test_catalog_seeded_and_idempotent(controller):
    n = controller.db.query_one("SELECT COUNT(*) n FROM osint_resources")["n"]
    assert n == len(CATALOG)
    controller.osint.set_favorite("github", True)
    controller.osint.ensure_catalog()                        # re-seeding keeps user state, adds no duplicates
    assert controller.db.query_one("SELECT COUNT(*) n FROM osint_resources")["n"] == n
    assert controller.osint.get("github")["favorite"] == 1


# ---------------- term detection / validation ----------------
@pytest.mark.parametrize("term,kind", [
    ("alice_99", "username"), ("@alice", "username"), ("alice@example.com", "email"), ("example.com", "domain"),
    ("sub.example.co.uk", "domain"), ("203.0.113.9", "ip"), ("2001:db8::1", "ip"),
    ("https://example.com/a.png", "url"), ("Acme Corp Ltd", "text"), ("a b", "text")])
def test_detect_type(term, kind):
    assert osv.detect_type(term) == kind


def test_validate_term_rules():
    assert osv.validate_term("@Alice.Smith-1", "username") == "Alice.Smith-1"
    for bad in ("../etc/passwd", "a/b", "a b", "x" * 65, "alice?admin=1", "a#b", "a%2fb"):
        with pytest.raises(ValidationError):
            osv.validate_term(bad, "username")
    assert osv.validate_term("Example.COM.", "domain") == "example.com"
    for bad in ("999.1.1.1", "exa mple.com", "example.com/path", "-bad.com"):
        with pytest.raises(ValidationError):
            osv.validate_term(bad, "domain")
    for bad in ("not-an-ip", "1.2.3", "1.2.3.4/24"):
        with pytest.raises(ValidationError):
            osv.validate_term(bad, "ip")
    for bad in ("a@b", "a b@c.com", "@x.com", "x" * 300 + "@a.com"):
        with pytest.raises(ValidationError):
            osv.validate_term(bad, "email")
    for bad in ("ftp://x.com/a", "javascript:alert(1)", "https://user:pw@x.com/", "http:///nohost"):
        with pytest.raises(ValidationError):
            osv.validate_term(bad, "url")
    with pytest.raises(ValidationError):
        osv.validate_term("   ", "text")
    with pytest.raises(ValidationError):
        osv.validate_term("bad\x00text", "text")
    with pytest.raises(ValidationError):
        osv.validate_term("x" * 201, "text")


# ---------------- URL building ----------------
def test_build_url_encodes_and_pins_host():
    assert osv.build_url(by_slug("github"), "alice") == "https://github.com/alice"
    assert osv.build_url(by_slug("ddg"), "john smith & co") == "https://duckduckgo.com/?q=john%20smith%20%26%20co"
    assert osv.build_url(by_slug("ipinfo"), "2001:db8::1") == "https://ipinfo.io/2001:db8::1"
    md5 = hashlib.md5(b"alice@example.com").hexdigest()
    assert osv.build_url(by_slug("gravatar"), "Alice@Example.com") == f"https://gravatar.com/{md5}"
    assert osv.build_url(by_slug("email-google"), "a@b.com") == "https://www.google.com/search?q=%22a%40b.com%22"
    assert osv.build_url(by_slug("whatsmyname"), "anything at all") == "https://whatsmyname.app/"   # no term support


@pytest.mark.parametrize("evil", ["evil.com/@x", "a@evil.com", "x\\@evil.com", "//evil.com", "alice/../../x",
                                  "alice?next=https://evil.com", "alice#@evil.com"])
def test_term_can_never_redirect_the_link(evil):
    for slug in ("github", "reddit", "hackernews", "x"):
        try:
            url = osv.build_url(by_slug(slug), evil, "username")
        except ValidationError:
            continue
        assert urlparse(url).hostname == urlparse(by_slug(slug).url_template.replace("{term}", "x")).hostname


def test_every_catalog_template_builds_for_a_sample_of_each_input_type():
    samples = {"username": "alice", "email": "alice@example.com", "domain": "example.com", "ip": "203.0.113.7",
               "url": "https://example.com/pic.png", "text": "Acme Corp"}
    for r in CATALOG:
        host = urlparse(r.url_template.replace("{term_md5}", "x").replace("{term}", "x")).hostname
        for t in r.input_types:
            url = osv.build_url(r, samples[t], t)
            assert urlparse(url).hostname == host and url.startswith("https://"), (r.slug, t, url)


def test_build_url_rejects_wrong_input_type():
    with pytest.raises(ValidationError, match="works with"):
        osv.build_url(by_slug("hibp"), "203.0.113.7", "ip")
    with pytest.raises(ValidationError):
        osv.build_url(by_slug("tineye"), "alice", "username")
    assert osv.build_url(by_slug("tineye"), "https://example.com/a.png").startswith("https://tineye.com/search?url=https%3A")


# ---------------- custom resources ----------------
def test_custom_resources_are_validated(osint):
    slug = osint.add_custom("My Lookup", "https://lookup.example.org/search?q={term}", ["Domain research"], ["domain"], "x")
    assert slug == "custom-my-lookup" and osint.get(slug)["builtin"] == 0
    assert osv.build_url(osint.get(slug), "example.com", "domain") == "https://lookup.example.org/search?q=example.com"
    with pytest.raises(ValidationError, match="already exists"):
        osint.add_custom("My Lookup", "https://lookup.example.org/?q={term}", [], [])
    for bad in ("http://example.org/?q={term}", "https://localhost/?q={term}", "https://127.0.0.1/?q={term}",
                "https://10.0.0.5/?q={term}", "https://user:pw@example.org/?q={term}", "https://example.org:8443/?q={term}",
                "https://example.org/?q=fixed", "https://example.org/?q={term}&r={term}", "https://{term}.example.org/",
                "https://example.org/?q={term}{other}", "https://printer.local/?q={term}", "javascript:{term}"):
        with pytest.raises(ValidationError):
            osint.add_custom("Bad", bad, [], [])
    osint.remove_custom(slug)
    assert osint.get(slug) is None
    osint.remove_custom("github")                            # built-in resources cannot be removed
    assert osint.get("github") is not None


# ---------------- filtering ----------------
def test_filtering_by_category_input_search_and_favorites(osint):
    users = osint.resources(category="Username research")
    assert {"github", "knowem"} <= {r["slug"] for r in users}
    ips = osint.resources(input_type="ip")
    assert "ipinfo" in {r["slug"] for r in ips} and "github" not in {r["slug"] for r in ips}
    assert "ddg" in {r["slug"] for r in ips}                 # 'text'-capable engines accept any term type
    assert [r["slug"] for r in osint.resources(query="gravatar")] == ["gravatar"]
    assert osint.resources(favorites=True) == []
    osint.set_favorite("crtsh", True)
    assert [r["slug"] for r in osint.resources(favorites=True)] == ["crtsh"]


# ---------------- availability ----------------
def test_availability_contacts_only_the_front_page(osint, monkeypatch):
    seen = []

    class Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_open(req, timeout=0):
        seen.append((req.full_url, req.get_method()))
        if "github.com" in req.full_url:
            raise __import__("urllib.error", fromlist=["x"]).HTTPError(req.full_url, 403, "no", {}, None)
        if "gitlab.com" in req.full_url:
            raise __import__("urllib.error", fromlist=["x"]).HTTPError(req.full_url, 503, "down", {}, None)
        if "reddit.com" in req.full_url:
            raise OSError("dns failure")
        return Resp()

    monkeypatch.setattr("urllib.request.urlopen", fake_open)
    out = osint.check_availability(["github", "gitlab", "reddit", "keybase", "nope"])
    assert out == {"github": "reachable", "gitlab": "unavailable", "reddit": "unavailable", "keybase": "reachable"}
    assert all(m == "HEAD" and u.endswith("/") and u.count("/") == 3 for u, m in seen)   # root only: never the term
    assert osint.get("github")["availability"] == "reachable" and osint.get("github")["checked_at"]


# ---------------- records ----------------
def test_records_upsert_and_enum(controller):
    o, pid = controller.osint, controller.projects.create("Case 1", "investigation")
    o.set_result(pid, "alice", "github", "possible", "https://github.com/alice")
    o.set_result(pid, "alice", "github", "confirmed", notes="matches photo")
    o.set_result(pid, "alice", "gitlab", "none")
    assert o.results_for(pid, "alice") == {"github": "confirmed", "gitlab": "none"}
    recs = o.records(pid)
    assert len(recs) == 2 and {r["result"] for r in recs} == {"confirmed", "none"}
    gh = next(r for r in recs if r["slug"] == "github")
    assert gh["url"] == "https://github.com/alice" and gh["notes"] == "matches photo" and gh["recorded_at"]
    assert o.terms(pid) == ["alice"]
    for bad in ("found", "yes", ""):
        with pytest.raises(ValidationError):
            o.set_result(pid, "alice", "github", bad)
    with pytest.raises(ValidationError):
        o.set_result(pid, "alice", "no-such-resource", "none")
    assert set(osv.RESULTS) == set(osv.RESULT_LABELS) and len(osv.RESULTS) == 5


# ---------------- export ----------------
def test_export_formats(controller):
    ps, o = controller.projects, controller.osint
    pid = ps.create("Case <1>", "investigation")
    o.set_result(pid, "=cmd", "github", "possible", "https://github.com/x")
    ps.add_reference(pid, "https://example.com/found")
    ps.add_note(pid, "<script>alert(1)</script> observed")
    data = json.loads(o.export_investigation(pid, "json", ps))
    assert data["project"] == "Case <1>" and data["records"][0]["result"] == "possible" and data["exported_at"]
    assert data["saved_urls"][0]["url"] == "https://example.com/found" and data["notes"][0]["created_at"]
    rows = list(csv.reader(io.StringIO(o.export_investigation(pid, "csv", ps))))
    assert rows[0][0] == "recorded_at" and rows[1][1] == "'=cmd" and rows[1][3] == "Possible match"
    md = o.export_investigation(pid, "md", ps)
    assert "Possible match" in md and "not verified identities" in md
    page = o.export_investigation(pid, "html", ps)
    assert "<script>" not in page and "&lt;script&gt;" in page
    with pytest.raises(ValueError):
        o.export_investigation(pid, "pdf", ps)
    with pytest.raises(ValidationError):
        o.export_investigation(9999, "json", ps)
