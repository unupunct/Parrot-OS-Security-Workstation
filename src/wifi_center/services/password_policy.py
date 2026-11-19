"""Offline password-policy evaluation. Nothing is cracked, guessed or contacted.

Input is a list of candidate passwords you are authorised to evaluate (typically synthetic test data or an
approved dataset). Results identify entries by line number/username only; password text is never stored,
logged or put in reports.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

MAX_LINES = 200_000
MAX_BLOCKLIST = 5_000_000
SEQUENCES = ("abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl", "zxcvbnm")

RULES = {
    "too_short": "shorter than the minimum length",
    "too_long": "longer than the maximum length",
    "few_classes": "does not use enough character classes",
    "repeats": "contains a long run of one repeated character",
    "sequence": "contains a keyboard or alphabetic/numeric sequence",
    "contains_username": "contains the user name",
    "blocklisted": "matches an entry of the supplied blocklist",
    "whitespace_edge": "starts or ends with whitespace",
}


@dataclass(frozen=True)
class Policy:
    min_length: int = 12
    max_length: int = 128
    min_classes: int = 3
    max_repeat: int = 3
    forbid_sequences: bool = True
    forbid_username: bool = True


@dataclass
class EntryResult:
    label: str                       # "line 12" or the user name; never the password
    violations: list[str]

    @property
    def passed(self) -> bool:
        return not self.violations


@dataclass
class AuditReport:
    policy: Policy
    total: int = 0
    passed: int = 0
    by_rule: Counter = field(default_factory=Counter)
    results: list[EntryResult] = field(default_factory=list)
    truncated: bool = False
    blocklist_size: int = 0

    @property
    def failed(self) -> int:
        return self.total - self.passed


def char_classes(pw: str) -> int:
    return sum(bool(re.search(p, pw)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9\s]"))


def has_sequence(pw: str, length: int = 4) -> bool:
    low = pw.lower()
    for seq in SEQUENCES:
        for s in (seq, seq[::-1]):
            for i in range(len(s) - length + 1):
                if s[i:i + length] in low:
                    return True
    return False


def has_repeat(pw: str, limit: int) -> bool:
    return re.search(r"(.)\1{%d,}" % limit, pw) is not None


def evaluate(pw: str, policy: Policy, username: str | None = None, blocklist: frozenset[str] | set[str] | None = None
             ) -> list[str]:
    v = []
    if len(pw) < policy.min_length:
        v.append("too_short")
    if len(pw) > policy.max_length:
        v.append("too_long")
    if char_classes(pw) < policy.min_classes:
        v.append("few_classes")
    if has_repeat(pw, policy.max_repeat):
        v.append("repeats")
    if policy.forbid_sequences and has_sequence(pw):
        v.append("sequence")
    if policy.forbid_username and username and len(username) >= 3 and username.lower() in pw.lower():
        v.append("contains_username")
    if blocklist:
        low = pw.lower()
        if low in blocklist or low.rstrip("0123456789!@#$%^&*") in blocklist:
            v.append("blocklisted")
    if pw != pw.strip():
        v.append("whitespace_edge")
    return v


def load_blocklist(path: Path) -> set[str]:
    out: set[str] = set()
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            w = line.rstrip("\r\n").lower()
            if w:
                out.add(w)
            if len(out) >= MAX_BLOCKLIST:
                break
    return out


def parse_entries(text: str, userpass: bool = False) -> list[tuple[str, str | None, str]]:
    """-> [(label, username, password)] from 'password' or 'username:password' lines."""
    out = []
    for n, line in enumerate(text.splitlines(), start=1):
        line = line.rstrip("\r\n")
        if not line:
            continue
        if userpass and ":" in line:
            user, pw = line.split(":", 1)
            out.append((user or f"line {n}", user or None, pw))
        else:
            out.append((f"line {n}", None, line))
    return out


def audit(entries: Iterable[tuple[str, str | None, str]], policy: Policy,
          blocklist: set[str] | None = None) -> AuditReport:
    rep = AuditReport(policy, blocklist_size=len(blocklist or ()))
    for label, user, pw in entries:
        if rep.total >= MAX_LINES:
            rep.truncated = True
            break
        viol = evaluate(pw, policy, user, blocklist)
        rep.total += 1
        rep.passed += not viol
        rep.by_rule.update(viol)
        rep.results.append(EntryResult(label, viol))   # note: no password text is kept
    return rep


def summary_text(rep: AuditReport) -> str:
    lines = [f"{rep.total} entries evaluated: {rep.passed} met the policy, {rep.failed} did not.",
             f"Policy: min length {rep.policy.min_length}, {rep.policy.min_classes} character classes, "
             f"max repeat {rep.policy.max_repeat}."]
    for rule, n in rep.by_rule.most_common():
        lines.append(f"- {n} {RULES.get(rule, rule)}")
    if rep.blocklist_size:
        lines.append(f"Blocklist entries used: {rep.blocklist_size}")
    return "\n".join(lines)
