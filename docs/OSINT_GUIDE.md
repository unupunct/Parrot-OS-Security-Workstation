# OSINT workspace (Phase 5)

Five pages share one workspace: **OSINT Explorer** (any term) and focused **Username**, **Email**, **Domain** and **IP**
research. Layout: categories, saved resources and investigations on the left; the search term and resource list in the
middle; resource details, observations and notes on the right.

## How it works

1. Pick or create an **investigation** (a project of kind "investigation"; it holds your records, saved URLs and notes).
2. Enter a term. The type is detected (or fixed by the page) and validated: usernames may only contain letters, digits
   `. _ -`; e-mail, domain and IP addresses are checked; URLs must be plain http(s) without credentials.
3. **Open** a resource: WIFI Center builds the link from the resource's public URL template and opens it in *your* browser.
   Resources that cannot take a term (for example the WhatsMyName app) open their front page and copy the term to your
   clipboard. Nothing is fetched, scraped or automated by WIFI Center.
4. **Record** what you actually found: *Confirmed result, Possible match, No result, Inconclusive* or *Resource
   unavailable*. Opening a link records *Inconclusive* until you decide. A page that loads is **never** treated as proof
   that an account, person or company exists: many sites return a normal page for unknown names.
5. Save public URLs, write timestamped observations, and **export** the investigation as JSON, CSV, Markdown or HTML.

## Link safety

* The term is URL-encoded and the finished link must still point at the template's own host over https; anything that
  would redirect the link elsewhere (`@`, `//`, `../`, `?next=`) is refused (tested against the whole catalog).
* Custom resources must be public https sites, contain `{term}` exactly once after the host name, and may not use
  credentials, ports, local names or private addresses.

## Availability checks

"Check availability…" is optional and always asks first. It requests only the **home page** of each listed site (a HEAD
request, your IP address is visible to those sites) and **never sends your search term**. A site that answers with a
login wall, 403 or 404 counts as reachable; timeouts, DNS failures and 5xx count as unreachable.

## Catalog

66 built-in resources across the twelve categories of the OSINT Framework structure (username, email, domain, IP, social
networks, public websites, search engines, image, metadata, public records, company and infrastructure research), with source
and "needs an account" noted. Add your own, mark favourites, and find resources from the Ctrl+K palette (which only
navigates; it never opens a site by itself). URL patterns are public and can change: if one stops working, the availability
check or your browser will show it, and you can add a corrected custom resource.

## Not included on purpose

No automated account checking, scraping, credential testing, breach-data downloads or collection of private information.
