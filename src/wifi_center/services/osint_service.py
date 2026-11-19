"""OSINT workspace service: catalog, safe URL building, research records, availability checks and export.

Principles: every URL comes from a vetted public template, the term is validated and URL-encoded, nothing is opened
or contacted without a user action, and a page that loads is never treated as proof that an account or identity
exists. Research results are recorded as confirmed / possible / none / inconclusive / unavailable by the user.
"""
from __future__ import annotations

import csv
import hashlib
import html
import io
import ipaddress
import json
import re
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import quote, urlparse

from ..database.repository import Database
from ..security.input_validation import ValidationError, validate_hostname, validate_ip
from .osint_catalog import CATALOG, CATEGORIES, INPUT_TYPES, Resource, by_slug

RESULTS = ("confirmed", "possible", "none", "inconclusive", "unavailable")
RESULT_LABELS = {"confirmed": "Confirmed result", "possible": "Possible match", "none": "No result",
                 "inconclusive": "Inconclusive", "unavailable": "Resource unavailable"}
_USERNAME = re.compile(r"^[A-Za-z0-9._\-]{1,64}$")
_EMAIL = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~\-]{1,64}@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$")
USER_AGENT = "WIFI-Center availability check"


# ---------------------------------------------------------------- terms
def detect_type(term: str) -> str:
    t = term.strip()
    if re.match(r"^https?://", t, re.I):
        return "url"
    if _EMAIL.match(t):
        return "email"
    try:
        ipaddress.ip_address(t)
        return "ip"
    except ValueError:
        pass
    if "." in t and re.fullmatch(r"[A-Za-z0-9\-.]+\.[A-Za-z]{2,}", t):
        return "domain"
    if _USERNAME.match(t.lstrip("@")):
        return "username"
    return "text"


def validate_term(term: str, kind: str) -> str:
    t = term.strip()
    if not t:
        raise ValidationError("enter a search term")
    if any(ord(c) < 32 for c in t):
        raise ValidationError("the term contains control characters")
    if kind == "username":
        t = t.lstrip("@")
        if not _USERNAME.match(t):
            raise ValidationError("usernames may only contain letters, digits, '.', '_' and '-' (max 64)")
        return t
    if kind == "email":
        if len(t) > 254 or not _EMAIL.match(t):
            raise ValidationError("not a valid e-mail address")
        return t
    if kind == "domain":
        return validate_hostname(t.lower().rstrip("."))
    if kind == "ip":
        return validate_ip(t)
    if kind == "url":
        u = urlparse(t)
        if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password or len(t) > 2000:
            raise ValidationError("enter a plain http(s) URL without credentials")
        return t
    if kind == "text":
        if len(t) > 200:
            raise ValidationError("search text is limited to 200 characters")
        return t
    raise ValidationError(f"unknown input type: {kind}")


def site_home(resource: Resource | dict) -> str:
    """The resource's home page (scheme + host of its template), for opening it without a search term."""
    r = _as_resource(resource)
    u = urlparse(r.url_template.replace("{term_md5}", "x").replace("{term}", "x"))
    if u.scheme != "https" or not u.hostname:
        raise ValidationError("this resource has no valid https address")
    return f"https://{u.netloc}/"


def build_url(resource: Resource | dict, term: str, kind: str | None = None) -> str:
    """The URL to open for `term` on `resource`; raises ValidationError if the pairing is not allowed."""
    r = _as_resource(resource)
    if not r.supports_term:
        return r.url_template
    kind = kind or detect_type(term)
    if "text" not in r.input_types and kind not in r.input_types:
        raise ValidationError(f"{r.name} works with {', '.join(r.input_types)} terms, not {kind}")
    clean = validate_term(term, kind)
    safe = ":" if kind == "ip" else ""
    url = r.url_template.replace("{term_md5}", hashlib.md5(clean.lower().encode()).hexdigest()) \
                        .replace("{term}", quote(clean, safe=safe))
    a, b = urlparse(url), urlparse(r.url_template.replace("{term_md5}", "x").replace("{term}", "x"))
    if a.scheme != "https" or a.hostname != b.hostname:      # the term must never change where the link goes
        raise ValidationError("refusing to build a link that leaves the resource's site")
    return url


def _as_resource(r: Resource | dict) -> Resource:
    if isinstance(r, Resource):
        return r
    return Resource(r["slug"], r["name"], tuple(r["categories"]), tuple(r["input_types"]), r["url_template"],
                    r["description"] or "", bool(r["needs_account"]), bool(r["supports_term"]), r["source"])


def validate_template(url_template: str) -> None:
    u = urlparse(url_template)
    if u.scheme != "https" or not u.hostname or u.username or u.password or u.port:
        raise ValidationError("resource URLs must be plain https URLs on a public host")
    host = u.hostname
    if host == "localhost" or host.endswith((".local", ".internal", ".lan")):
        raise ValidationError("local hosts are not allowed")
    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_global:
            raise ValidationError("private or local addresses are not allowed")
    except ValueError:
        validate_hostname(host)
    if url_template.count("{term}") + url_template.count("{term_md5}") != 1 or "{term" in (u.netloc or ""):
        raise ValidationError("the URL must contain {term} exactly once, after the host name")
    leftover = url_template.replace("{term_md5}", "").replace("{term}", "")
    if "{" in leftover or "}" in leftover:
        raise ValidationError("only {term} is allowed as a placeholder")


# ---------------------------------------------------------------- service
class OsintService:
    def __init__(self, db: Database) -> None:
        self._db = db
        self.ensure_catalog()

    # ---- catalog ----
    def ensure_catalog(self) -> None:
        with self._db.transaction() as c:
            for r in CATALOG:
                c.execute(
                    "INSERT INTO osint_resources(slug, name, category, categories, input_types, url_template, "
                    "description, needs_account, supports_term, source, builtin) VALUES (?,?,?,?,?,?,?,?,?,?,1) "
                    "ON CONFLICT(slug) DO UPDATE SET name=excluded.name, category=excluded.category, "
                    "categories=excluded.categories, input_types=excluded.input_types, "
                    "url_template=excluded.url_template, description=excluded.description, "
                    "needs_account=excluded.needs_account, supports_term=excluded.supports_term, "
                    "source=excluded.source, builtin=1",
                    (r.slug, r.name, r.categories[0], "|".join(r.categories), "|".join(r.input_types), r.url_template,
                     r.description, int(r.needs_account), int(r.supports_term), r.source))

    @staticmethod
    def _row(r) -> dict:
        d = dict(r)
        d["categories"] = [x for x in (d["categories"] or d["category"]).split("|") if x]
        d["input_types"] = [x for x in (d["input_types"] or "text").split("|") if x]
        return d

    def resources(self, category: str | None = None, input_type: str | None = None, query: str = "",
                  favorites: bool = False) -> list[dict]:
        out = []
        q = query.strip().lower()
        for r in self._db.query("SELECT * FROM osint_resources ORDER BY name COLLATE NOCASE"):
            d = self._row(r)
            if category and category not in d["categories"]:
                continue
            explicit = bool(input_type) and input_type in d["input_types"]
            general = "text" in d["input_types"] and (input_type == "text" or "Search engines" in d["categories"])
            if input_type and not (explicit or general):
                continue
            if favorites and not d["favorite"]:
                continue
            if q and q not in d["name"].lower() and q not in (d["description"] or "").lower() \
                    and q not in d["url_template"].lower():
                continue
            d["_rank"] = 1 if (input_type and "Search engines" in d["categories"]) else 0   # purpose-built tools first
            out.append(d)
        out.sort(key=lambda d: (d["_rank"], d["name"].lower()))
        return out

    def get(self, slug: str) -> dict | None:
        r = self._db.query_one("SELECT * FROM osint_resources WHERE slug = ?", (slug,))
        return self._row(r) if r else None

    def set_favorite(self, slug: str, on: bool) -> None:
        self._db.execute("UPDATE osint_resources SET favorite = ? WHERE slug = ?", (int(on), slug))

    def add_custom(self, name: str, url_template: str, categories: list[str], input_types: list[str],
                   description: str = "") -> str:
        name = name.strip()
        if not name or len(name) > 80:
            raise ValidationError("name must be 1-80 characters")
        validate_template(url_template.strip())
        cats = [c for c in categories if c in CATEGORIES] or [CATEGORIES[5]]
        types = [t for t in input_types if t in INPUT_TYPES] or ["text"]
        slug = "custom-" + re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
        if self._db.query_one("SELECT 1 FROM osint_resources WHERE slug=?", (slug,)):
            raise ValidationError("a resource with that name already exists")
        self._db.execute(
            "INSERT INTO osint_resources(slug, name, category, categories, input_types, url_template, description, "
            "needs_account, supports_term, source, builtin) VALUES (?,?,?,?,?,?,?,0,1,'custom',0)",
            (slug, name, cats[0], "|".join(cats), "|".join(types), url_template.strip(), description))
        return slug

    def remove_custom(self, slug: str) -> None:
        self._db.execute("DELETE FROM osint_resources WHERE slug = ? AND builtin = 0", (slug,))

    # ---- availability (explicit user action; only the site's front page is requested, never the term) ----
    @staticmethod
    def check_one(url_template: str, timeout: float = 6.0) -> str:
        u = urlparse(url_template)
        req = urllib.request.Request(f"https://{u.hostname}/", method="HEAD", headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=timeout):
                return "reachable"
        except urllib.error.HTTPError as e:
            return "reachable" if e.code < 500 else "unavailable"   # 401/403/404/405/429: the site answered
        except (urllib.error.URLError, OSError, TimeoutError, ValueError):
            return "unavailable"

    def check_availability(self, slugs: list[str], workers: int = 4) -> dict[str, str]:
        rows = [self.get(s) for s in slugs]
        rows = [r for r in rows if r]
        with ThreadPoolExecutor(max_workers=workers) as ex:
            results = list(ex.map(lambda r: self.check_one(r["url_template"]), rows))
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        out = {}
        with self._db.transaction() as c:
            for r, status in zip(rows, results):
                c.execute("UPDATE osint_resources SET availability=?, checked_at=? WHERE slug=?", (status, now, r["slug"]))
                out[r["slug"]] = status
        return out

    @staticmethod
    def hosts_for(resources: list[dict]) -> list[str]:
        return sorted({urlparse(r["url_template"]).hostname for r in resources})

    # ---- research records ----
    def set_result(self, project_id: int | None, term: str, slug: str, result: str, url: str = "",
                   notes: str | None = None) -> None:
        if result not in RESULTS:
            raise ValidationError(f"result must be one of {RESULTS}")
        res = self._db.query_one("SELECT id FROM osint_resources WHERE slug=?", (slug,))
        if not res:
            raise ValidationError("unknown resource")
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._db.execute(
            "INSERT INTO osint_records(project_id, search_term, resource_id, url, result, notes, recorded_at) "
            "VALUES (?,?,?,?,?,?,?) ON CONFLICT(COALESCE(project_id,0), search_term, COALESCE(resource_id,0)) "
            "DO UPDATE SET result=excluded.result, url=COALESCE(NULLIF(excluded.url,''), url), "
            "notes=COALESCE(excluded.notes, notes), recorded_at=excluded.recorded_at",
            (project_id, term, res["id"], url, result, notes, now))

    def results_for(self, project_id: int | None, term: str) -> dict[str, str]:
        rows = self._db.query(
            "SELECT r.slug, o.result FROM osint_records o JOIN osint_resources r ON r.id=o.resource_id "
            "WHERE COALESCE(o.project_id,0)=? AND o.search_term=?", (project_id or 0, term))
        return {r["slug"]: r["result"] for r in rows}

    def records(self, project_id: int) -> list[dict]:
        return [dict(r) for r in self._db.query(
            "SELECT o.search_term, r.name AS resource, r.slug, o.url, o.result, o.notes, o.recorded_at "
            "FROM osint_records o LEFT JOIN osint_resources r ON r.id=o.resource_id WHERE o.project_id=? "
            "ORDER BY o.recorded_at DESC, o.id DESC", (project_id,))]

    def terms(self, project_id: int) -> list[str]:
        return [r["search_term"] for r in self._db.query(
            "SELECT DISTINCT search_term FROM osint_records WHERE project_id=? ORDER BY search_term", (project_id,))]

    # ---- export ----
    def export_investigation(self, project_id: int, fmt: str, projects) -> str:
        proj = projects.get(project_id)
        if not proj:
            raise ValidationError("unknown project")
        recs = self.records(project_id)
        refs = projects.references(project_id)
        notes = projects.notes(project_id)
        stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        if fmt == "json":
            return json.dumps({"project": proj["name"], "exported_at": stamp, "records": recs,
                               "saved_urls": [{"url": r["url"], "label": r["label"], "added_at": r["added_at"]} for r in refs],
                               "notes": [{"body": n["body"], "created_at": n["created_at"]} for n in notes]}, indent=2)
        if fmt == "csv":
            buf = io.StringIO()
            w = csv.writer(buf, lineterminator="\n")
            w.writerow(["recorded_at", "search_term", "resource", "result", "url", "notes"])
            for r in recs:
                w.writerow([_csv_safe(v) for v in (r["recorded_at"], r["search_term"], r["resource"],
                                                   RESULT_LABELS.get(r["result"], r["result"]), r["url"], r["notes"])])
            return buf.getvalue()
        if fmt in ("md", "html"):
            lines = [f"# OSINT investigation: {proj['name']}", f"_Exported {stamp} (UTC). Results are researcher "
                     "assessments, not verified identities._", "", "## Research records"]
            lines += [f"- {r['recorded_at']} · `{r['search_term']}` · {r['resource']} · "
                      f"**{RESULT_LABELS.get(r['result'], r['result'])}**" + (f" · {r['url']}" if r["url"] else "")
                      + (f" — {r['notes']}" if r["notes"] else "") for r in recs] or ["- none"]
            lines += ["", "## Saved public URLs"] + [f"- {r['url']}" + (f" ({r['label']})" if r["label"] else "")
                                                       for r in refs] or ["- none"]
            lines += ["", "## Notes"] + [f"- {n['created_at']}: {n['body']}" for n in notes] or ["- none"]
            md = "\n".join(lines)
            if fmt == "md":
                return md
            body = "".join(f"<p>{html.escape(l)}</p>" if not l.startswith(("#", "-")) else
                           (f"<h2>{html.escape(l.lstrip('# '))}</h2>" if l.startswith("#") else
                            f"<li>{html.escape(l[2:])}</li>") for l in lines if l)
            return f"<!doctype html><meta charset='utf-8'><title>{html.escape(proj['name'])}</title><body>{body}</body>"
        raise ValueError("format must be json, csv, md or html")


def _csv_safe(v):
    return "'" + v if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r") else v
