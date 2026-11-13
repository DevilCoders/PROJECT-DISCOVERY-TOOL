"""Every regex PDT runs over untrusted content must stay linear.

Scanned repositories are untrusted input. A pattern with catastrophic backtracking lets
one crafted line stall a worker indefinitely (the 0.1.0 redactor took 9 s on 2,000
characters of ``tokentoken...``). This test runs every compiled pattern in the package
against adversarial inputs and fails on any pattern whose cost grows faster than linearly.

Patterns are found in module and class attributes, inside containers and in the
analyzers' rule objects (dataclasses), and as string literals passed to ``re`` functions
inside function bodies. Inputs are generic adversarial texts plus witnesses built from
each pattern's own structure: the text before a repeated part followed by that part many
times, alone and repeated, which is the input shape that makes nested or overlapping
quantifiers backtrack. Each input is timed at growing sizes, so an exponential pattern
fails on a few dozen characters instead of hanging the suite.
"""
from __future__ import annotations

import ast
import dataclasses
import gc
import importlib
import pkgutil
import re
import time
from pathlib import Path

import project_discovery

# Witness and generic inputs grow through these sizes; the tiny ones stop exponential
# patterns before a large input could hang the test.
SMALL_SIZES = (16, 20, 24, 28, 32, 36, 40, 48, 64, 96)
SMALL_LIMIT_SECONDS = 0.1
MEDIUM, LARGE = 4_000, 16_000
# Linear patterns grow about 4x from MEDIUM to LARGE; quadratic ones about 16x.
GROWTH_LIMIT = 10.0
# Below this, timings are too small for a growth ratio to mean anything: one scheduler
# preemption on a shared runner (a few milliseconds) made linear patterns that finish in
# microseconds read x13. A quadratic pattern takes seconds on LARGE characters.
GROWTH_FLOOR_SECONDS = 0.02
ABSOLUTE_LIMIT_SECONDS = 0.75
# Patterns applied only with .match() at positions chosen by the caller; scanning them
# from every start position is not how PDT uses them.
MATCH_ONLY = {
    "project_discovery.analyzers.environment.network._LITERAL_REST": (
        "matched once per quote kind by _literal_spans"
    ),
    # clean_source matches these at each opener; an unterminated quote marks its kind
    # failed for the rest of the line, and an unterminated verbatim string ends the scan.
    "project_discovery.intelligence.model.lexical._QUOTED": "matched at quote openers by clean_source",
    "project_discovery.intelligence.model.lexical._VERBATIM": "matched after @\" openers by clean_source",
    "project_discovery.intelligence.model.lexical._ARROW_AFTER": (
        "matched once after the closing parenthesis of a `const x = (` candidate"
    ),
    "project_discovery.analyzers.domains.frontend._STRING_AT": (
        "matched once at the value position of a `selector:`/`path:` key"
    ),
    "project_discovery.analyzers.domains.hdl._INSTANCE_NAME": (
        "matched once after a statement's type name (and its #(...) parameters)"
    ),
    "project_discovery.analyzers.environment.configuration._DIRECTIVE": "matched once per line by _directive_keys",
    # After one regex-literal candidate fails to close on a line, clean_source treats the
    # line's later candidates as divisions, so each line is scanned once.
    "project_discovery.intelligence.model.lexical._REGEX_LITERAL": "matched at regex-literal candidates",
    "project_discovery.analyzers.security.taint_lexical._LEADING_LOOKBEHIND": (
        "matched at the start of PDT's own rule patterns, never on scanned content"
    ),
}
_RE_FUNCTIONS = {"compile", "search", "match", "fullmatch", "finditer", "findall", "sub", "subn", "split"}


def _patterns() -> list[tuple[str, re.Pattern[str]]]:
    found: list[tuple[str, re.Pattern[str]]] = []
    seen: set[int] = set()

    def collect(value, origin: str, depth: int = 0) -> None:
        if id(value) in seen or depth > 5:
            return
        seen.add(id(value))
        if isinstance(value, re.Pattern):
            if isinstance(value.pattern, str):
                found.append((origin, value))
        elif isinstance(value, dict):
            for item in value.values():
                collect(item, origin, depth + 1)
        elif isinstance(value, (list, tuple, set, frozenset)):
            for item in value:
                collect(item, origin, depth + 1)
        elif dataclasses.is_dataclass(value) and not isinstance(value, type):
            # Rule objects (the lexical taint Rules and Sink records, token formats).
            for item in dataclasses.fields(value):
                collect(getattr(value, item.name, None), f"{origin}.{item.name}", depth + 1)
        elif (not isinstance(value, type) and type(value).__module__.startswith("project_discovery.")
              and hasattr(value, "__dict__")):
            # Rule helpers such as the secure-code call patterns hold compiled parts.
            for name, item in vars(value).items():
                collect(item, f"{origin}.{name}", depth + 1)

    for info in pkgutil.walk_packages(project_discovery.__path__, "project_discovery."):
        module = importlib.import_module(info.name)
        for name, value in vars(module).items():
            if isinstance(value, type) and value.__module__ == module.__name__:
                for attribute, item in vars(value).items():
                    collect(item, f"{info.name}.{name}.{attribute}")
            else:
                collect(value, f"{info.name}.{name}")
        found.extend(_inline_patterns(module, info.name))
    return found


def _flags(node: ast.AST | None) -> int | None:
    """re.I | re.M style flag expressions; None when the value is not a constant."""
    if node is None:
        return 0
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "re":
        value = getattr(re, node.attr, None)
        return int(value) if isinstance(value, (int, re.RegexFlag)) else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left, right = _flags(node.left), _flags(node.right)
        return None if left is None or right is None else left | right
    return None


def _inline_patterns(module, name: str) -> list[tuple[str, re.Pattern[str]]]:
    """String-literal patterns passed to re functions inside function bodies."""
    path = getattr(module, "__file__", None)
    if not path or not path.endswith(".py"):
        return []
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    found = []
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        for node in ast.walk(function):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "re"
                    and node.func.attr in _RE_FUNCTIONS and node.args):
                continue
            source = node.args[0]
            if not (isinstance(source, ast.Constant) and isinstance(source.value, str)):
                continue
            # compile(p, flags), search(p, s, flags), sub(p, r, s, count, flags), ...
            position = {"compile": 1, "sub": 4, "subn": 4, "split": 3}.get(node.func.attr, 2)
            keyword = next((item.value for item in node.keywords if item.arg == "flags"), None)
            flags = _flags(keyword if keyword is not None else (node.args[position] if len(node.args) > position else None))
            if flags is None:
                continue
            # match() and fullmatch() try one position, so they are timed that way.
            kind = "inline match" if node.func.attr in {"match", "fullmatch"} else "inline"
            try:
                found.append((f"{name}:{node.lineno} ({kind})", re.compile(source.value, flags)))
            except re.error:
                continue
    return found


# --------------------------------------------------------------------------- inputs


def _generic_units() -> list[tuple[str, str, str]]:
    """(lead, unit, suffix): the text is lead + unit repeated + suffix."""
    units = []
    for word in ("token", "password", "secret", "phone", "email", "name", "import", "select"):
        units += [("", word, ""), ("", word + "_", ""), ("", word + " ", "")]
    units += [
        ("", "a.", "@x"), ("", "a.", "@1"), ("", "a-", ""), ("", "a:", "@"), ("", "a@", ""),
        ("", "a", "@"), ("", "a", "://"), ("", "x://", ""), ("", "0.", ""), ("", "ff:", ""),
        ("x = '", "\\'", ""), ('"', "a", ""), ("", "[](", ""), ("", "](", ""), ("", "[", ""),
        ("# a", " ", "b"), ("password", " ", "x"), ("password:", " ", "x"),
        ("", " ", "x"), ("", "\t", "x"), ("", "(", ""), ("", "<", ""), ("", "{", ""), ("", "=", ""),
        ("", "-", ""), ("", "#", ""), ("", "/", ""), ("", "\\", ""), ("", "${", ""), ("", "a, ", ""),
        ("eyJ", "a", ""), ("", "ghp_", ""), ("", "aA0", ""), ("", 'a="', ""), ("", "\n", "x"),
        ('"', "\\", ""), ("'", "\\", ""), ("", "a\n", ""), ("", " a\n", ""), ("", "a;\n", ""),
    ]
    return units


def _text(lead: str, unit: str, suffix: str, size: int) -> str:
    return lead + unit * max(1, (size - len(lead) - len(suffix)) // max(1, len(unit))) + suffix


def _witness_units(pattern: re.Pattern[str]) -> list[tuple[str, str, str]]:
    """Backtracking witnesses from the pattern's structure.

    For each repeated part: the text before it followed by that part repeated (one long
    attempt), and the two together repeated (an attempt from every start position).
    """
    try:
        from re import _constants as c
        from re import _parser
    except ImportError:  # pragma: no cover - private modules of CPython 3.11+
        return []
    try:
        tree = _parser.parse(pattern.pattern, pattern.flags)
    except Exception:
        return []
    repeats = {c.MAX_REPEAT, c.MIN_REPEAT, getattr(c, "POSSESSIVE_REPEAT", c.MAX_REPEAT)}

    def member(character: str, items) -> bool:
        code = ord(character)
        for op, value in items:
            if op is c.LITERAL and value == code:
                return True
            if op is c.RANGE and value[0] <= code <= value[1]:
                return True
            if op is c.CATEGORY:
                name = str(value)
                tests = {
                    "CATEGORY_DIGIT": character.isdigit(), "CATEGORY_NOT_DIGIT": not character.isdigit(),
                    "CATEGORY_SPACE": character.isspace(), "CATEGORY_NOT_SPACE": not character.isspace(),
                    "CATEGORY_WORD": character.isalnum() or character == "_",
                    "CATEGORY_NOT_WORD": not (character.isalnum() or character == "_"),
                }
                if tests.get(name, False):
                    return True
        return False

    def one(op, value) -> str:
        if op is c.LITERAL:
            return chr(value)
        if op is c.NOT_LITERAL:
            return "a" if value != ord("a") else "b"
        if op is c.ANY:
            return "a"
        if op is c.IN:
            negated = bool(value) and value[0][0] is c.NEGATE
            items = value[1:] if negated else value
            for candidate in "a x1_-.:/\"'\\(=,;\n":
                if member(candidate, items) != negated:
                    return candidate
            return ""
        if op in repeats:
            low, _, sub = value
            return text_of(sub) * min(max(low, 1), 64)
        if op is c.SUBPATTERN:
            return text_of(value[-1])
        if op is getattr(c, "ATOMIC_GROUP", None):
            return text_of(value)
        if op is c.BRANCH:
            return text_of(value[1][0])
        if op is c.GROUPREF_EXISTS:
            return text_of(value[1])
        return ""  # anchors, lookarounds, back-references

    def text_of(items) -> str:
        return "".join(one(op, value) for op, value in items)

    pairs: list[tuple[str, str]] = []

    def walk(items, before: str) -> str:
        text = before
        for op, value in items:
            if op in repeats:
                pump = text_of(value[2])
                if pump and len(pairs) < 12:
                    pairs.append((text, pump))
                walk(value[2], text)
                text += one(op, value)
            elif op is c.SUBPATTERN:
                text = walk(value[-1], text)
            elif op is getattr(c, "ATOMIC_GROUP", None):
                text = walk(value, text)
            elif op is c.BRANCH:
                for alternative in value[1]:
                    walk(alternative, text)
                text += text_of(value[1][0])
            else:
                text += one(op, value)
        return text

    walk(tree, "")
    units = []
    for before, pump in pairs:
        units.append((before, pump, ""))
        if before:
            units.append(("", before + pump, ""))
    return units


def _scan(origin: str, pattern: re.Pattern[str], text: str) -> float:
    # The collector is off while timing. Thousands of match objects trigger full collections
    # of the whole imported package's heap in the larger runs only, which made linear patterns
    # such as [^\n] look ten times slower on macOS runners, run after run.
    enabled = gc.isenabled()
    gc.disable()
    try:
        started = time.perf_counter()
        if origin in MATCH_ONLY or origin.endswith("(inline match)"):
            pattern.match(text)
        else:
            for _ in pattern.finditer(text):
                pass
        return time.perf_counter() - started
    finally:
        if enabled:
            gc.enable()


def _slow(origin: str, pattern: re.Pattern[str], lead: str, unit: str, suffix: str) -> str | None:
    """Why this input makes the pattern super-linear, or None."""
    for size in SMALL_SIZES:
        elapsed = _scan(origin, pattern, _text(lead, unit, suffix, size))
        if elapsed > SMALL_LIMIT_SECONDS:
            elapsed = min(elapsed, _scan(origin, pattern, _text(lead, unit, suffix, size)))
            if elapsed > SMALL_LIMIT_SECONDS:
                return f"{elapsed:.2f}s on {size} characters (exponential)"
    def slow(medium: float, large: float) -> bool:
        return large > ABSOLUTE_LIMIT_SECONDS or (large > GROWTH_FLOOR_SECONDS and large > GROWTH_LIMIT * medium)

    medium = _scan(origin, pattern, _text(lead, unit, suffix, MEDIUM))
    large = _scan(origin, pattern, _text(lead, unit, suffix, LARGE))
    # Millisecond timings are noisy (a collection or a scheduling hiccup on a busy runner), so
    # a suspicious pair is measured again, keeping the fastest run, and judged after each.
    for _ in range(3):
        if not slow(medium, large):
            return None
        medium = min(medium, _scan(origin, pattern, _text(lead, unit, suffix, MEDIUM)))
        large = min(large, _scan(origin, pattern, _text(lead, unit, suffix, LARGE)))
    if not slow(medium, large):
        return None
    return f"{large:.3f}s on {LARGE:,} characters, x{large / max(medium, 1e-9):.0f} from {MEDIUM:,}"


def test_every_package_regex_is_linear_on_adversarial_input():
    patterns = _patterns()
    assert len(patterns) > 600  # the collector must see the rule objects and inline patterns
    assert any(origin.endswith(("(inline)", "(inline match)")) for origin, _ in patterns)
    assert any(".assignment" in origin for origin, _ in patterns)  # lexical Rules dataclasses
    generic = _generic_units()
    slow = []
    for origin, pattern in patterns:
        for lead, unit, suffix in generic + _witness_units(pattern):
            reason = _slow(origin, pattern, lead, unit, suffix)
            if reason:
                sample = (lead + unit * 3)[:24]
                slow.append(f"{origin}: {reason} on {sample!r}... /{pattern.pattern[:80]}/")
                break
    assert not slow, "super-linear regexes:\n" + "\n".join(slow)


def test_witnesses_reproduce_known_backtracking_shapes():
    # The generated witnesses must include the inputs that exposed real defects.
    xxe = re.compile(r"setFeature\s*\([^;\n]*(?:entities)[^;\n]*true")
    texts = {lead + unit * 3 for lead, unit, _ in _witness_units(xxe)}
    assert any("setFeature (" in text and "entities" not in text for text in texts)
    listing = re.compile(r"(?<![\w$.])(?P<names>[A-Za-z_]\w*+(?:[ \t]*+,[ \t]*+[A-Za-z_]\w*+)*+)[ \t]*+=")
    assert any(unit.strip() == ", a" or unit == " , a" or unit.endswith(",a") or "," in unit
               for _, unit, _ in _witness_units(listing))


def test_literal_spans_matches_reference_regex_semantics():
    # The linear scanner must yield exactly what the original single regex produced.
    from project_discovery.analyzers.environment.network import _literal_spans

    reference = re.compile(r"""(["'`])((?:\\.|(?!\1)[^\\\r\n])*)\1""")
    samples = [
        "x = 'a' + \"b\" + `c`",
        "don't use 'example.com' here",
        "'\\'' and \"\\\"\" and 'unterminated",
        "\"a 'b' c\" 'd \"e\" f'",
        "'\\'\\'\\'\\'",
        "`multi ${x} \\` tick`",
        "nothing quoted",
        "\"\" '' ``",
        "'a\\\\' 'b'",
    ]
    for line in samples:
        expected = [(match.start(2), match.end(2)) for match in reference.finditer(line)]
        assert _literal_spans(line) == expected, line
