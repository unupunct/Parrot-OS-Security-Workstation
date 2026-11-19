"""Built-in OSINT resource catalog: public sites with documented, public search/lookup URLs.

Nothing here is scraped or automated. A resource is just a name, a description and a URL template that the user
opens in their own browser. `{term}` is the URL-encoded search term; `{term_md5}` the MD5 of a lower-cased e-mail
address (the documented Gravatar profile scheme). Categories follow the structure of https://osintframework.com/.
"""
from __future__ import annotations

from dataclasses import dataclass

CATEGORIES = (
    "Username research", "Email research", "Domain research", "IP address research", "Social networks",
    "Public websites", "Search engines", "Image research", "Metadata research", "Public records",
    "Company research", "Infrastructure research",
)
INPUT_TYPES = ("username", "email", "domain", "ip", "url", "text")

U, E, D, I, S, W, X, M, MD, P, C, F = CATEGORIES   # short aliases used in the table below


@dataclass(frozen=True)
class Resource:
    slug: str
    name: str
    categories: tuple[str, ...]
    input_types: tuple[str, ...]
    url_template: str
    description: str
    needs_account: bool = False
    supports_term: bool = True
    source: str = "OSINT Framework"


def _r(slug, name, cats, types, url, desc, account=False, term=True, source="OSINT Framework") -> Resource:
    return Resource(slug, name, tuple(cats), tuple(types), url, desc, account, term, source)


CATALOG: tuple[Resource, ...] = (
    # ---- username / social (profile URL patterns: a hit is only a *possible* match)
    _r("github", "GitHub profile", (U, S), ("username",), "https://github.com/{term}", "Public developer profile and repositories."),
    _r("gitlab", "GitLab profile", (U, S), ("username",), "https://gitlab.com/{term}", "Public GitLab user or group page."),
    _r("reddit", "Reddit user", (U, S), ("username",), "https://www.reddit.com/user/{term}", "Public Reddit profile and comment history."),
    _r("hackernews", "Hacker News user", (U, S), ("username",), "https://news.ycombinator.com/user?id={term}", "Public Hacker News profile."),
    _r("keybase", "Keybase", (U, S), ("username",), "https://keybase.io/{term}", "Public identity proofs linked to a username."),
    _r("x", "X (Twitter) profile", (U, S), ("username",), "https://x.com/{term}", "Public profile; some content needs a login."),
    _r("instagram", "Instagram profile", (U, S), ("username",), "https://www.instagram.com/{term}/", "Public profile page; may require login."),
    _r("tiktok", "TikTok profile", (U, S), ("username",), "https://www.tiktok.com/@{term}", "Public profile page."),
    _r("youtube", "YouTube channel handle", (U, S), ("username",), "https://www.youtube.com/@{term}", "Public channel by handle."),
    _r("twitch", "Twitch channel", (U, S), ("username",), "https://www.twitch.tv/{term}", "Public Twitch channel."),
    _r("medium", "Medium author", (U, S), ("username",), "https://medium.com/@{term}", "Public author page."),
    _r("pinterest", "Pinterest profile", (U, S), ("username",), "https://www.pinterest.com/{term}/", "Public boards and pins."),
    _r("steam", "Steam community profile", (U, S), ("username",), "https://steamcommunity.com/id/{term}", "Public profile by custom URL."),
    _r("dockerhub", "Docker Hub user", (U,), ("username",), "https://hub.docker.com/u/{term}", "Public images and organisations."),
    _r("npm", "npm user", (U,), ("username",), "https://www.npmjs.com/~{term}", "Public packages by a maintainer."),
    _r("pypi", "PyPI user", (U,), ("username",), "https://pypi.org/user/{term}/", "Public projects by a maintainer."),
    _r("knowem", "KnowEm username check", (U,), ("username",), "https://knowem.com/checkusernames.php?u={term}", "Checks a username across many sites in your browser."),
    _r("whatsmyname", "WhatsMyName web app", (U,), ("username",), "https://whatsmyname.app/", "Community dataset of username checks; paste the term there.", term=False),
    # ---- e-mail
    _r("hibp", "Have I Been Pwned", (E,), ("email",), "https://haveibeenpwned.com/account/{term}", "Whether an address appears in publicly known breaches."),
    _r("emailrep", "EmailRep", (E,), ("email",), "https://emailrep.io/{term}", "Reputation and public-profile signals for an address."),
    _r("gravatar", "Gravatar profile", (E, S), ("email",), "https://gravatar.com/{term_md5}", "Public Gravatar profile for the address hash."),
    _r("email-google", "Exact-match web search", (E, X), ("email",), "https://www.google.com/search?q=%22{term}%22", "Pages that mention the exact address."),
    _r("hunter", "Hunter domain search", (E, C), ("domain",), "https://hunter.io/search/{term}", "Public e-mail patterns for a company domain.", account=True),
    # ---- domain
    _r("icann", "ICANN registration lookup", (D,), ("domain",), "https://lookup.icann.org/en/lookup?name={term}", "Official RDAP/WHOIS registration data."),
    _r("crtsh", "crt.sh certificate transparency", (D, F), ("domain",), "https://crt.sh/?q={term}", "Publicly logged certificates and sub-domains."),
    _r("viewdns", "ViewDNS WHOIS", (D,), ("domain",), "https://viewdns.info/whois/?domain={term}", "WHOIS and related DNS tools."),
    _r("wayback", "Wayback Machine", (D, W), ("domain", "url"), "https://web.archive.org/web/*/{term}", "Archived snapshots of a site or page."),
    _r("urlscan-domain", "urlscan.io", (D, W), ("domain",), "https://urlscan.io/search/#domain:{term}", "Public scans of a domain."),
    _r("vt-domain", "VirusTotal domain", (D, F), ("domain",), "https://www.virustotal.com/gui/domain/{term}", "Reputation and passive DNS."),
    _r("securitytrails", "SecurityTrails DNS", (D, F), ("domain",), "https://securitytrails.com/domain/{term}/dns", "Historical DNS data (account for full detail).", account=True),
    _r("builtwith", "BuiltWith technology profile", (D, W), ("domain",), "https://builtwith.com/{term}", "Technologies a public site appears to use."),
    _r("netcraft", "Netcraft site report", (D, F), ("domain",), "https://sitereport.netcraft.com/?url={term}", "Hosting and technology report."),
    _r("mxtoolbox", "MXToolbox MX lookup", (D,), ("domain",), "https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{term}", "Mail-exchange records and mail-security checks."),
    _r("shodan-host", "Shodan hostname search", (D, F), ("domain",), "https://www.shodan.io/search?query=hostname%3A{term}", "Internet-exposed services reporting this hostname.", account=True),
    _r("dnsdumpster", "DNSdumpster", (D, F), ("domain",), "https://dnsdumpster.com/", "DNS recon page; enter the domain there.", term=False),
    # ---- IP
    _r("ipinfo", "IPinfo", (I,), ("ip",), "https://ipinfo.io/{term}", "Geolocation, ASN and network owner."),
    _r("abuseipdb", "AbuseIPDB", (I,), ("ip",), "https://www.abuseipdb.com/check/{term}", "Community abuse reports for an address."),
    _r("shodan-ip", "Shodan host", (I, F), ("ip",), "https://www.shodan.io/host/{term}", "Services seen on a public address.", account=True),
    _r("censys-ip", "Censys host", (I, F), ("ip",), "https://search.censys.io/hosts/{term}", "Services and certificates seen on a public address."),
    _r("greynoise", "GreyNoise", (I,), ("ip",), "https://viz.greynoise.io/ip/{term}", "Whether an address is background internet scanning noise."),
    _r("bgphe-ip", "Hurricane Electric BGP", (I, F), ("ip",), "https://bgp.he.net/ip/{term}", "Routing and ASN information."),
    _r("arin-rdap", "ARIN RDAP", (I,), ("ip",), "https://rdap.arin.net/registry/ip/{term}", "Registry allocation record (redirects to the right RIR)."),
    _r("vt-ip", "VirusTotal IP", (I, F), ("ip",), "https://www.virustotal.com/gui/ip-address/{term}", "Reputation and related files/URLs."),
    _r("ripestat", "RIPEstat", (I, F), ("ip", "domain"), "https://stat.ripe.net/{term}", "Routing, registration and geolocation widgets."),
    _r("urlscan-ip", "urlscan.io by IP", (I, W), ("ip",), "https://urlscan.io/search/#ip:{term}", "Public scans hosted on an address."),
    # ---- search engines
    _r("ddg", "DuckDuckGo", (X,), ("text", "username", "email", "domain", "ip"), "https://duckduckgo.com/?q={term}", "General web search."),
    _r("bing", "Bing", (X,), ("text", "username", "email", "domain", "ip"), "https://www.bing.com/search?q={term}", "General web search."),
    _r("google", "Google", (X,), ("text", "username", "email", "domain", "ip"), "https://www.google.com/search?q={term}", "General web search (supports operators such as site:)."),
    _r("brave", "Brave Search", (X,), ("text", "username", "email", "domain", "ip"), "https://search.brave.com/search?q={term}", "Independent search index."),
    _r("yandex", "Yandex", (X,), ("text", "username", "email", "domain"), "https://yandex.com/search/?text={term}", "Search engine with different coverage."),
    # ---- images
    _r("tineye", "TinEye reverse image search", (M,), ("url",), "https://tineye.com/search?url={term}", "Find other places an image (by URL) appears."),
    _r("lens", "Google Lens by URL", (M,), ("url",), "https://lens.google.com/uploadbyurl?url={term}", "Reverse image search for an image URL."),
    _r("yandex-img", "Yandex image search by URL", (M,), ("url",), "https://yandex.com/images/search?rpt=imageview&url={term}", "Reverse image search for an image URL."),
    # ---- metadata (tools you open and use yourself)
    _r("exiftool", "ExifTool documentation", (MD,), ("text",), "https://exiftool.org/", "Reference for reading and interpreting file metadata.", term=False, source="exiftool.org"),
    _r("metadata2go", "Metadata2Go viewer", (MD,), ("text",), "https://www.metadata2go.com/", "Browser-based metadata viewer (you choose the file).", term=False),
    _r("fotoforensics", "FotoForensics", (MD, M), ("text",), "https://fotoforensics.com/", "Image error-level and metadata analysis (you upload the file).", term=False),
    # ---- public records / company
    _r("courtlistener", "CourtListener", (P,), ("text",), "https://www.courtlistener.com/?q={term}", "US court opinions and dockets."),
    _r("edgar", "SEC EDGAR", (P, C), ("text",), "https://www.sec.gov/edgar/search/#/q={term}", "US public-company filings."),
    _r("opencorporates", "OpenCorporates", (P, C), ("text",), "https://opencorporates.com/companies?q={term}", "Open database of company registrations."),
    _r("companieshouse", "UK Companies House", (P, C), ("text",), "https://find-and-update.company-information.service.gov.uk/search?q={term}", "UK company register."),
    _r("archive-search", "Internet Archive search", (P, W), ("text",), "https://archive.org/search?query={term}", "Books, media and web captures."),
    _r("wikipedia", "Wikipedia", (C, W), ("text",), "https://en.wikipedia.org/w/index.php?search={term}", "Encyclopedic background."),
    _r("wikidata", "Wikidata", (C, W), ("text",), "https://www.wikidata.org/w/index.php?search={term}", "Structured entity data."),
    _r("linkedin-company", "LinkedIn company search", (C, S), ("text",), "https://www.linkedin.com/search/results/companies/?keywords={term}", "Company pages (login required).", account=True),
    # ---- infrastructure
    _r("censys-search", "Censys search", (F,), ("text", "domain", "ip"), "https://search.censys.io/search?resource=hosts&q={term}", "Search internet-wide scan data."),
    _r("bgpview", "BGPView", (F, I), ("ip", "domain", "text"), "https://bgpview.io/search/{term}", "ASN, prefix and network search."),
)


def by_slug(slug: str) -> Resource | None:
    return next((r for r in CATALOG if r.slug == slug), None)
