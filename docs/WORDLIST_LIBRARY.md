# Wordlist Library and Local Resources (Phase 6)

A local-first library for password-policy test data (Wordlist Library) and for other reference files (Local Resources).
Default folders: `~/WIFI-Center/Resources/Wordlists/` and `~/WIFI-Center/Resources/Local/`; both can be changed on the page
(or in Settings → General) and the change applies immediately. Subfolders act as categories.

## What WIFI Center does and does not do

* It **never downloads, bundles or redistributes** leaked-credential collections, and never follows the mega links or
  torrents some sources publish. For third-party lists you open the source page, decide whether you accept its license,
  obtain the file yourself, and **import** it with its provenance (source URL, license, attribution, date obtained).
  The import dialog needs an explicit acknowledgement before it enables the button.
* Nothing in the library is connected to any cracking, guessing or Wi-Fi attack feature. The lists are inputs for offline
  policy checks such as the blocklist on the Password Auditing page.
* **Nothing is ever deleted automatically.** "Remove from library" only stops tracking (the file stays and shows up under
  "Untracked files"); "Delete file…" is a separate, confirmed action that names the exact path.

## The ten catalog entries

| # | Entry | Kind | License (as verified) |
|---|---|---|---|
| 1 | RockYou wordlist references (GitHub topic) | reference | varies by repository |
| 2 | Probable-Wordlists | reference | CC-BY-SA-4.0 (attribution + share-alike) |
| 3 | SecLists: Passwords | reference | MIT |
| 4 | Probable-Wordlists: WPA-length lists | reference | CC-BY-SA-4.0 |
| 5 | Synthetic weak-pattern set | generated | synthetic |
| 6 | Synthetic keyboard walks and sequences | generated | synthetic |
| 7 | Synthetic compliant passphrases | generated | synthetic |
| 8 | Synthetic username:password pairs | generated | synthetic |
| 9 | Length and character-class ladder | generated | synthetic |
| 10 | Locally supplied resources | local | as supplied |

Licenses for entries 2-4 were read from the GitHub API on 2026-11-19 and the repositories were confirmed to exist; the
topic page in entry 1 aggregates unrelated repositories, so read the license of the one you use. "Check source and license…"
repeats that check on demand (after a confirmation, since it contacts api.github.com) and warns if a declared license no
longer matches the catalog. Reference content derives from real leaked credentials: handle copies as sensitive.

The generated entries are produced locally from invented words and fixed patterns, deterministically for a given seed.
They are test data only: the "compliant passphrases" are not for real use. The weak-pattern set shows why policies need
blocklists: many entries still satisfy typical length and character-class rules.

## Library features

Search, folders as categories, favorites, import (copy-in with an atomic write, `.part` files never appear as real
files), rename, explicit remove/delete, file size, format (by extension and content), line count, SHA-256, duplicate
detection (identical hashes; importing a duplicate is refused unless you insist), storage usage, integrity verification
(unchanged / changed / missing), last-modified time, details panel, a browser for files you dropped into the folder
yourself ("Untracked files", added without moving anything) and a download-and-import history.

File names are restricted to letters, digits, space and `. _ - ( ) +`; folder names likewise; paths cannot leave the
library root; symbolic links are not followed.

## Documentation page

Lists the official documentation and source pages of every integrated tool and WIFI Center's own guides. Nothing opens
until you press Open.
