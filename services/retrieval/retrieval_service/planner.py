"""S0 Level 1: deterministic question classification (Requirement 24).

No LLM, no I/O, no clock, no randomness: identical input gives an identical
skeleton (same identifiers, intents and order). Level 2 lives elsewhere.
"""
import re
from dataclasses import asdict, dataclass, field

MAX_QUESTION_CHARS = 10_000
DEFAULT_TOP_K_TOTAL = 4
INTENTS = ("cve_lookup", "code_reachability", "cloud_exposure", "remediation", "blast_radius", "general")


class InvalidQuestion(ValueError):
    """Empty, whitespace-only, over-length or non-string question. No Plan is created."""

    code = "invalid_question"


@dataclass(frozen=True)
class ExactId:
    kind: str    # cve, ghsa, purl, arn, repo, path, symbol, cwe
    value: str   # text exactly as written in the question
    start: int
    end: int


@dataclass(frozen=True)
class RetrievalUnit:
    cwe: str
    root_cause: str
    vulnerable_snippet: str
    k: int


@dataclass(frozen=True)
class PlanSkeleton:
    question: str
    exact_ids: tuple
    intents: tuple
    retrieval_units: tuple
    covered: bool           # every part of the question is an identifier or known intent word
    confident: bool         # exactly one non-general intent and covered: Level 2 can be skipped
    top_k_total: int = DEFAULT_TOP_K_TOTAL

    @property
    def needs_level2(self) -> bool:
        return not self.confident

    def to_dict(self) -> dict:
        return asdict(self)


# Identifier patterns, applied in this order. Earlier kinds claim their span first.
_HOSTS = r"(?:github\.com|gitlab\.com|bitbucket\.org)"
_PATTERNS = (
    ("arn", re.compile(r"\barn:aws[\w-]*:[\w-]+:[\w-]*:\d*:[^\s,;\"'<>()\[\]`]+")),
    ("purl", re.compile(r"\bpkg:[A-Za-z][\w.+-]*/[^\s,;\"'<>()\[\]`]+")),
    ("cve", re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)),
    ("ghsa", re.compile(r"\bGHSA(?:-[a-z0-9]{4}){3}\b", re.I)),
    ("cwe", re.compile(r"\bCWE-\d{1,5}\b", re.I)),
    ("repo", re.compile(r"\b" + _HOSTS + r"/[\w.-]+/[\w.-]+|(?<=\brepo )[\w.-]+/[\w.-]+|"
                        r"(?<=\brepository )[\w.-]+/[\w.-]+|(?<=\bin repo )[\w.-]+/[\w.-]+", re.I)),
    ("path", re.compile(r"(?<![\w/.:-])(?:~|\.{1,2})?/?[\w.@-]+(?:/[\w.@-]+)+\.[A-Za-z0-9]{1,8}\b"
                        r"|(?<![\w/.:-])[\w-]+\.(?:go|py|ts|tsx|js|jsx|java|rs|rb|c|h|cc|cpp|cs|php|tf|yaml|yml|json|toml|sql)\b")),
    ("symbol", re.compile(r"`([A-Za-z_][\w.]*)(?:\(\))?`|\b([A-Za-z_][\w.]*)\(\)"
                          r"|(?<=\bfunction )[A-Za-z_]\w*|(?<=\bmethod )[A-Za-z_]\w*|(?<=\bsymbol )[A-Za-z_]\w*")),
)
_TRAIL = ".,;:!?"

# Keyword rules. Order here is the canonical intent order.
_INTENT_WORDS = {
    "cve_lookup": {"cve", "cves", "cwe", "vulnerability", "vulnerabilities", "advisory", "advisories",
                   "ghsa", "cvss", "epss", "kev", "details", "describe", "explain", "lookup", "severity"},
    "code_reachability": {"reachable", "reachability", "reach", "reaches", "calls", "call", "called",
                          "caller", "callers", "imports", "imported", "uses", "used", "invoke", "invokes",
                          "exploitable"},
    "cloud_exposure": {"exposed", "exposure", "internet", "public", "publicly", "externally", "bucket",
                       "iam", "ec2", "s3", "lambda", "cloud", "aws", "ingress", "facing"},
    "remediation": {"fix", "fixes", "fixed", "remediate", "remediation", "patch", "patches", "patched",
                    "upgrade", "update", "mitigate", "mitigation", "resolve"},
    "blast_radius": {"blast", "radius", "impact", "impacts", "affected", "affects", "downstream",
                     "impacted", "affect"},
}
_PHRASES = {"blast radius": "blast_radius", "attack path": "cloud_exposure", "security group": "cloud_exposure"}
# Identifier kinds that imply an intent only when no keyword rule fired.
_ID_INTENT = {"cve": "cve_lookup", "ghsa": "cve_lookup", "cwe": "cve_lookup", "arn": "cloud_exposure"}
_FILLER = {"a", "an", "the", "of", "in", "on", "for", "to", "is", "are", "it", "this", "that", "and", "or",
           "what", "which", "how", "where", "who", "show", "me", "tell", "about", "does", "do", "can", "be",
           "with", "by", "from", "at", "my", "our", "any", "all", "there", "if", "i", "we", "please", "get",
           "give", "list", "find", "repo", "repository", "function", "method", "symbol", "file", "package",
           "resource", "named", "called", "id", "s"}
_KNOWN_WORDS = _FILLER.union(*_INTENT_WORDS.values())
for _p in _PHRASES:
    _KNOWN_WORDS.update(_p.split())

_WORD = re.compile(r"[A-Za-z0-9_]+")
_ROOT_CAUSE = re.compile(r"root[ -]cause\s*(?:[:\-]|is)\s*(.+?)(?=\n\s*\n|vulnerable[ -](?:code|snippet)|```|$)",
                         re.I | re.S)
_SNIPPET_FENCE = re.compile(r"```[^\n]*\n(.*?)```", re.S)
_SNIPPET_LABEL = re.compile(r"vulnerable[ -](?:code|snippet)\s*:\s*(.+?)(?=\n\s*\n|root[ -]cause|$)", re.I | re.S)


def validate_question(question) -> str:
    if not isinstance(question, str):
        raise InvalidQuestion("invalid question: must be a string")
    if not question.strip():
        raise InvalidQuestion("invalid question: empty or whitespace only")
    if len(question) > MAX_QUESTION_CHARS:
        raise InvalidQuestion(f"invalid question: longer than {MAX_QUESTION_CHARS} characters")
    return question


def extract_ids(question: str) -> list[ExactId]:
    claimed: list[tuple[int, int]] = []
    found: list[ExactId] = []

    def free(s: int, e: int) -> bool:
        return all(e <= a or s >= b for a, b in claimed)

    for kind, rx in _PATTERNS:
        for m in rx.finditer(question):
            s, e = m.span()
            if kind == "symbol" and (m.lastindex or 0):
                s, e = m.span(m.lastindex)
            raw = question[s:e]
            stripped = raw.rstrip(_TRAIL)
            e -= len(raw) - len(stripped)
            if not stripped or not free(s, e):
                continue
            claimed.append((s, e))
            found.append(ExactId(kind, question[s:e], s, e))
    found.sort(key=lambda i: (i.start, i.end))
    seen, out = set(), []
    for i in found:  # keep first occurrence of each (kind, value)
        if (i.kind, i.value) not in seen:
            seen.add((i.kind, i.value))
            out.append(i)
    return out


def _masked(question: str, ids: list[ExactId]) -> str:
    chars = list(question)
    for i in extract_spans(question, ids):
        for p in range(i[0], i[1]):
            chars[p] = " "
    return "".join(chars)


def extract_spans(question: str, ids: list[ExactId]) -> list[tuple[int, int]]:
    """Spans of every identifier occurrence, including repeats of a deduplicated value."""
    spans = [(i.start, i.end) for i in ids]
    for i in ids:
        for m in re.finditer(re.escape(i.value), question):
            spans.append(m.span())
    return spans


def classify_intents(question: str, ids: list[ExactId]) -> tuple:
    lowered = question.lower()
    hit = set()
    for phrase, intent in _PHRASES.items():
        if phrase in lowered:
            hit.add(intent)
    words = set(_WORD.findall(_masked(lowered, [ExactId(i.kind, i.value.lower(), i.start, i.end) for i in ids])))
    for intent, vocab in _INTENT_WORDS.items():
        if words & vocab:
            hit.add(intent)
    if not hit:
        for i in ids:
            if i.kind in _ID_INTENT:
                hit.add(_ID_INTENT[i.kind])
    ordered = tuple(x for x in INTENTS if x in hit and x != "general")
    return ordered or ("general",)


def _is_covered(question: str, ids: list[ExactId]) -> bool:
    if not ids:
        return False
    residual = _WORD.findall(_masked(question, ids).lower())
    return all(w in _KNOWN_WORDS for w in residual)


def _units(question: str, ids: list[ExactId], top_k_total: int) -> tuple:
    cwes: list[str] = []
    for i in ids:
        if i.kind == "cwe" and i.value not in cwes:
            cwes.append(i.value)
    if not cwes:
        return ()
    cause = _ROOT_CAUSE.search(question)
    snip = _SNIPPET_FENCE.search(question) or _SNIPPET_LABEL.search(question)
    cause_text = cause.group(1).strip() if cause else ""
    snippet_text = snip.group(1).strip() if snip else ""
    n = len(cwes)
    base, rem = divmod(top_k_total, n)
    # Supplied text applies to a single named CWE only; with several it is ambiguous, so left for Level 2.
    one = n == 1
    return tuple(RetrievalUnit(c, cause_text if one else "", snippet_text if one else "",
                               max(1, base + (1 if idx < rem else 0)))
                 for idx, c in enumerate(cwes))


def classify(question, top_k_total: int = DEFAULT_TOP_K_TOTAL) -> PlanSkeleton:
    validate_question(question)
    ids = extract_ids(question)
    intents = classify_intents(question, ids)
    covered = _is_covered(question, ids)
    single = len(intents) == 1 and intents[0] != "general"
    return PlanSkeleton(question, tuple(ids), intents, _units(question, ids, top_k_total),
                        covered, covered and single, top_k_total)


_GRAPHS = {"cve_lookup": ("cve",), "code_reachability": ("code",), "cloud_exposure": ("unified",),
           "remediation": ("cve", "unified"), "blast_radius": ("code", "unified"), "general": ()}


def level1_plan(sk: PlanSkeleton) -> dict:
    """Plan recorded when Level 2 is skipped: level 1, round 0."""
    graphs = []
    for it in sk.intents:
        graphs += [g for g in _GRAPHS[it] if g not in graphs]
    facets = ["identifier"]
    if any(i in sk.intents for i in ("code_reachability", "blast_radius", "cloud_exposure")):
        facets.append("structural")
    facets.append("evidence")
    return {
        "question": sk.question,
        "exact_ids": [{"kind": i.kind, "value": i.value} for i in sk.exact_ids],
        "intents": list(sk.intents),
        "scope": {"graphs": graphs,
                  "repos": [i.value for i in sk.exact_ids if i.kind == "repo"],
                  "revisions": []},
        "facets": facets,
        "retrieval_units": [asdict(u) for u in sk.retrieval_units],
        "top_k_total": sk.top_k_total,
        "level": 1,
        "round": 0,
    }


def plan_handler(req: dict, stores) -> dict:
    """/v1/plan. Level 1 only: returns the Plan when Level 2 is skipped, else the skeleton."""
    top_k = req.get("top_k_total", DEFAULT_TOP_K_TOTAL)
    if not isinstance(top_k, int) or isinstance(top_k, bool) or top_k < 1:
        top_k = DEFAULT_TOP_K_TOTAL
    sk = classify(req.get("question"), top_k)
    skel = {"exact_ids": [{"kind": i.kind, "value": i.value} for i in sk.exact_ids],
            "intents": list(sk.intents), "covered": sk.covered, "confident": sk.confident,
            "retrieval_units": [asdict(u) for u in sk.retrieval_units]}
    if sk.needs_level2:
        return {"plan": None, "skeleton": skel, "needs_level2": True, "llm_calls": 0}
    return {"plan": level1_plan(sk), "skeleton": skel, "needs_level2": False, "llm_calls": 0}
