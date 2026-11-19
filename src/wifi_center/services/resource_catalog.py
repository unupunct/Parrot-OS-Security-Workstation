"""The ten catalog entries of the wordlist library and the generators for the synthetic ones.

Reference entries point at third-party projects. Nothing is downloaded, bundled or redistributed by WIFI Center:
you obtain a copy yourself, from the source, under its license, then import it. Their content derives from real
leaked credentials, so treat copies as sensitive and use them only for authorised offline testing.

Generated entries are produced locally from fixed patterns and invented words: no real credentials are involved.
"""
from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass(frozen=True)
class CatalogEntry:
    id: str
    name: str
    kind: str                      # reference | generated | local
    description: str
    source_url: str = ""
    license: str = ""
    attribution: str = ""
    license_note: str = ""
    repo: str = ""                 # owner/name, enables the explicit "check source" action
    generator: str = ""
    default_count: int = 0


VERIFIED = "License read from the GitHub API on 2026-11-19; re-check before redistributing anything."

CATALOG: tuple[CatalogEntry, ...] = (
    CatalogEntry(
        "rockyou-references", "RockYou wordlist references (GitHub topic)", "reference",
        "Index of GitHub repositories that publish copies of the RockYou list, a real password list from the 2009 "
        "RockYou breach.",
        "https://github.com/topics/rockyou-wordlist", "Varies by repository",
        "Credit the repository you obtained your copy from.",
        "This page aggregates many unrelated repositories, each with its own license and terms. Read the one you use. "
        "The content is real leaked data: obtain it deliberately and handle it as sensitive."),
    CatalogEntry(
        "probable-wordlists", "Probable-Wordlists", "reference",
        "Password wordlists sorted by probability, for testing whether your own passwords are popular.",
        "https://github.com/berzerk0/Probable-Wordlists", "CC-BY-SA-4.0",
        "berzerk0 / Probable-Wordlists, licensed CC BY-SA 4.0 (attribution and share-alike apply).",
        VERIFIED, repo="berzerk0/Probable-Wordlists"),
    CatalogEntry(
        "seclists-passwords", "SecLists: Passwords", "reference",
        "The Passwords section of the SecLists collection (common credentials, leaked lists, default passwords).",
        "https://github.com/danielmiessler/SecLists/tree/master/Passwords", "MIT",
        "Daniel Miessler and SecLists contributors, MIT license.", VERIFIED, repo="danielmiessler/SecLists"),
    CatalogEntry(
        "probable-wpa-length", "Probable-Wordlists: WPA-length lists", "reference",
        "Pointers (mega links and torrents) to WPA-length-filtered probable lists. The page lists links; WIFI Center "
        "never follows them.",
        "https://github.com/berzerk0/Probable-Wordlists/blob/master/Real-Passwords/WPA-Length/"
        "Real-Password-WPA-MegaLinks.md", "CC-BY-SA-4.0",
        "berzerk0 / Probable-Wordlists, licensed CC BY-SA 4.0 (attribution and share-alike apply).",
        VERIFIED + " Wi-Fi password lists are only for offline policy checks, never for attacking networks.",
        repo="berzerk0/Probable-Wordlists"),
    CatalogEntry("synthetic-weak-patterns", "Synthetic weak-pattern set", "generated",
                 "Predictable word + year + suffix patterns (generated locally). Many satisfy length and character-class rules, so only a blocklist or pattern check flags them.",
                 license="Synthetic: no third-party content", generator="weak_patterns", default_count=2000),
    CatalogEntry("synthetic-keyboard-walks", "Synthetic keyboard walks and sequences", "generated",
                 "Keyboard-row walks, digit runs and alphabet runs in several capitalisations (generated locally).",
                 license="Synthetic: no third-party content", generator="keyboard_walks", default_count=1000),
    CatalogEntry("synthetic-strong", "Synthetic compliant passphrases", "generated",
                 "Random multi-word passphrases that should satisfy a typical policy. For tests only: never use these "
                 "as real passwords.", license="Synthetic: no third-party content", generator="strong", default_count=500),
    CatalogEntry("synthetic-userpass", "Synthetic username:password pairs", "generated",
                 "Invented users with weak and strong passwords, in the username:password format the audit page reads.",
                 license="Synthetic: no third-party content", generator="userpass", default_count=500),
    CatalogEntry("synthetic-length-ladder", "Length and character-class ladder", "generated",
                 "Candidates of every length from 4 to 24 characters with each combination of character classes, to "
                 "probe where a policy's thresholds sit.", license="Synthetic: no third-party content",
                 generator="ladder", default_count=0),
    CatalogEntry("local-supplied", "Locally supplied resources", "local",
                 "Your own approved datasets, internal blocklists and test files. Import them with their source and "
                 "license so the library can track them.", license="As supplied by you"),
)


def entry(entry_id: str) -> CatalogEntry | None:
    return next((e for e in CATALOG if e.id == entry_id), None)


# ------------------------------------------------------------------ generators
_WORDS = ("amber", "birch", "cobalt", "delta", "ember", "fjord", "garnet", "harbor", "indigo", "juniper", "kestrel",
          "lantern", "meadow", "nimbus", "onyx", "pebble", "quartz", "raven", "saffron", "tundra", "umber", "velvet",
          "willow", "xenon", "yarrow", "zephyr", "copper", "falcon", "glacier", "horizon", "island", "jasmine",
          "kitten", "lagoon", "marble", "nectar", "orchid", "puzzle", "quiver", "rocket", "silver", "thunder",
          "violet", "walnut", "anchor", "bridge", "candle", "dragon", "engine", "forest", "garden", "hammer",
          "iceberg", "jungle", "kernel", "ladder", "mirror", "needle", "ocean", "planet", "rabbit", "shadow",
          "temple", "voyage")
_SEASONS = ("spring", "summer", "autumn", "winter")
_SUFFIXES = ("", "1", "123", "!", "2024", "2025", "01", "#1", "007")
_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "abcdefghijklmnopqrstuvwxyz")


def weak_patterns(count: int, seed: int) -> list[str]:
    """Every word x capitalisation x suffix x optional year, shuffled by `seed`; `count` of them (0 = all)."""
    space = {form(base) + suffix + year
             for base in _WORDS + _SEASONS for form in (str.lower, str.capitalize, str.upper)
             for suffix in _SUFFIXES for year in ("", "2019", "2021", "2023", "2024", "2025")}
    items = sorted(space)
    random.Random(seed).shuffle(items)
    return items[:count] if count else items


def keyboard_walks(count: int, seed: int) -> list[str]:
    rng = random.Random(seed)
    cands: set[str] = set()
    for row in _ROWS:
        for length in range(6, min(len(row), 12) + 1):
            for start in range(len(row) - length + 1):
                s = row[start:start + length]
                for variant in (s, s[::-1], s.capitalize(), s + "!", s.capitalize() + "1"):
                    cands.add(variant)
    items = sorted(cands)
    rng.shuffle(items)
    return items[:count] if count else items


def strong(count: int, seed: int) -> list[str]:
    rng = random.Random(seed)
    out = []
    for _ in range(count):
        words = [rng.choice(_WORDS).capitalize() for _ in range(4)]
        out.append("-".join(words) + f"-{rng.randrange(10, 99)}" + rng.choice("!@#$%^&*"))
    return out


def userpass(count: int, seed: int) -> list[str]:
    rng = random.Random(seed)
    weak = weak_patterns(max(count, 50), seed + 1)
    strong_pw = strong(max(count, 50), seed + 2)
    out = []
    for i in range(1, count + 1):
        pw = rng.choice(weak) if rng.random() < 0.6 else rng.choice(strong_pw)
        out.append(f"user{i:04d}:{pw}")
    return out


def ladder(count: int, seed: int) -> list[str]:
    """Deterministic: one candidate per (length, class set). `count` and `seed` are ignored."""
    sets = {"l": "abcdefghjkmnpqrstuvwxyz", "u": "ABCDEFGHJKMNPQRSTUVWXYZ", "d": "2346789", "s": "!@#$%^&*"}
    out = []
    for length in range(4, 25):
        for mask in range(1, 16):
            classes = [c for i, c in enumerate("luds") if mask >> i & 1]
            if length < len(classes):
                continue
            chars = []
            for i in range(length):                      # cycle classes and walk each alphabet: no runs, no sequences
                alphabet = sets[classes[i % len(classes)]]
                chars.append(alphabet[(i * 5 + length) % len(alphabet)])
            out.append("".join(chars))
    return out


GENERATORS = {"weak_patterns": weak_patterns, "keyboard_walks": keyboard_walks, "strong": strong,
              "userpass": userpass, "ladder": ladder}


def generate(entry_id: str, count: int | None = None, seed: int = 20260101) -> list[str]:
    e = entry(entry_id)
    if not e or not e.generator:
        raise ValueError("this catalog entry has no generator")
    return GENERATORS[e.generator](count if count is not None else e.default_count, seed)
