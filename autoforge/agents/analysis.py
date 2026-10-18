"""Deterministic brief analysis helpers used by the mock provider and by validators."""
from __future__ import annotations

import re

FLAG_INJECT_FAILURE = "[[inject-failure]]"
FLAG_UNFIXABLE = "[[unfixable]]"
FLAG_PATH_ATTACK = "[[policy-violation]]"

_STOP = {"a", "an", "the", "secure", "simple", "basic", "new", "and", "or", "with", "for", "of", "to", "in",
         "that", "their", "its", "all", "any", "some", "multiple", "various", "user", "users", "different"}
_LEAD = re.compile(r"(?:with|including|includes|manage|manages|managing|track|tracks|tracking|handles?|supports?|has)\s+([^.\n]+)", re.I)
_RESERVED = {"order", "group", "table", "index", "select", "where", "key", "default", "check", "values", "id"}


def _singular(word: str) -> str:
    if word.endswith("ies") and len(word) > 4:
        return word[:-3] + "y"
    if word.endswith("sses") or word.endswith("ss"):
        return word.rstrip("es") if word.endswith("sses") else word
    if word.endswith("s") and len(word) > 3 and not word.endswith("us") and not word.endswith("ing"):
        return word[:-1]
    return word


def extract_entities(brief: str, limit: int = 4) -> list[str]:
    """Heuristic noun extraction. Falls back to a single generic 'item' entity."""
    text = brief.replace(FLAG_INJECT_FAILURE, "").replace(FLAG_UNFIXABLE, "").replace(FLAG_PATH_ATTACK, "")
    m = _LEAD.search(text)
    names: list[str] = []
    if m:
        chunk = re.sub(r"\band\b", ",", m.group(1))
        for part in chunk.split(","):
            words = [w for w in re.findall(r"[A-Za-z]+", part.lower()) if w not in _STOP]
            if not words:
                continue
            name = _singular(words[-1])
            if name in _RESERVED:
                name = name + "_record"
            if name and name not in names and len(name) >= 3:
                names.append(name)
    return (names or ["item"])[:limit]


def flags(brief: str) -> dict[str, bool]:
    return {
        "inject_failure": FLAG_INJECT_FAILURE in brief,
        "unfixable": FLAG_UNFIXABLE in brief,
        "path_attack": FLAG_PATH_ATTACK in brief,
    }


def slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return s or "project"
