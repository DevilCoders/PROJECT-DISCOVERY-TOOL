"""Every module-level regex PDT runs over untrusted content must stay linear.

Scanned repositories are untrusted input. A pattern with catastrophic backtracking lets
one crafted line stall a worker indefinitely (the 0.1.0 redactor took 9 s on 2,000
characters of ``tokentoken...``). This test runs every compiled pattern found in the
package against adversarial inputs and fails on any pattern that takes too long.
"""
from __future__ import annotations

import importlib
import pkgutil
import re
import time

import project_discovery

SIZE = 48_000
# Linear patterns finish in a few milliseconds at this size; quadratic ones take seconds.
LIMIT_SECONDS = 0.75
# Patterns applied only with .match() at positions chosen by the caller; scanning them
# from every start position is not how PDT uses them.
MATCH_ONLY = {
    "project_discovery.analyzers.network_analyzer._LITERAL_REST": (
        "matched once per quote kind by _literal_spans"
    ),
    # clean_source matches these at each opener; an unterminated quote marks its kind
    # failed for the rest of the line, and an unterminated verbatim string ends the scan.
    "project_discovery.code_model.lexical._QUOTED": "matched at quote openers by clean_source",
    "project_discovery.code_model.lexical._VERBATIM": "matched after @\" openers by clean_source",
    "project_discovery.code_model.lexical._ARROW_AFTER": (
        "matched once after the closing parenthesis of a `const x = (` candidate"
    ),
    "project_discovery.analyzers.frontend_analyzer._STRING_AT": (
        "matched once at the value position of a `selector:`/`path:` key"
    ),
    "project_discovery.analyzers.hdl_analyzer._INSTANCE_NAME": (
        "matched once after a statement's type name (and its #(...) parameters)"
    ),
}


def _patterns() -> list[tuple[str, re.Pattern[str]]]:
    found: list[tuple[str, re.Pattern[str]]] = []
    seen: set[int] = set()

    def collect(value, origin: str, depth: int = 0) -> None:
        if id(value) in seen or depth > 4:
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

    for info in pkgutil.walk_packages(project_discovery.__path__, "project_discovery."):
        module = importlib.import_module(info.name)
        for name, value in vars(module).items():
            if isinstance(value, type) and value.__module__ == module.__name__:
                for item in vars(value).values():
                    collect(item, f"{info.name}.{name}")
            else:
                collect(value, f"{info.name}.{name}")
    return found


def _inputs() -> list[str]:
    def repeat(unit: str, suffix: str = "") -> str:
        return unit * (SIZE // len(unit)) + suffix

    texts = []
    for word in ("token", "password", "secret", "phone", "email", "name", "import", "select"):
        texts += [repeat(word), repeat(word + "_"), repeat(word + " ")]
    texts += [
        repeat("a.", "@x"), repeat("a.", "@1"), repeat("a-"), repeat("a:", "@"), repeat("a@"),
        repeat("a", "@"), repeat("a", "://"), repeat("x://"), repeat("0."), repeat("ff:"),
        "x = '" + repeat("\\'"), '"' + repeat("a"), repeat("[]("), repeat("]("), repeat("["),
        "# a" + repeat(" ", "b"), "password" + repeat(" ", "x"), "password:" + repeat(" ", "x"),
        repeat(" ", "x"), repeat("\t", "x"), repeat("("), repeat("<"), repeat("{"), repeat("="),
        repeat("-"), repeat("#"), repeat("/"), repeat("\\"), repeat("${"), repeat("a, "),
        "eyJ" + repeat("a"), repeat("ghp_"), repeat("aA0"), repeat("a=\""),
    ]
    return texts


def _scan(origin: str, pattern: re.Pattern[str], text: str) -> None:
    if origin in MATCH_ONLY:
        pattern.match(text)
        return
    for _ in pattern.finditer(text):
        pass


def test_every_package_regex_is_linear_on_adversarial_input():
    patterns = _patterns()
    assert len(patterns) > 200  # the collector must see the analyzers' patterns
    texts = _inputs()
    slow = []
    for origin, pattern in patterns:
        for text in texts:
            started = time.perf_counter()
            _scan(origin, pattern, text)
            elapsed = time.perf_counter() - started
            if elapsed > LIMIT_SECONDS:
                # Confirm once to rule out a scheduling hiccup on a busy CI runner.
                started = time.perf_counter()
                _scan(origin, pattern, text)
                elapsed = min(elapsed, time.perf_counter() - started)
            if elapsed > LIMIT_SECONDS:
                slow.append(f"{origin}: {elapsed:.2f}s on {text[:16]!r}... /{pattern.pattern[:80]}/")
                break
    assert not slow, "super-linear regexes:\n" + "\n".join(slow)


def test_literal_spans_matches_reference_regex_semantics():
    # The linear scanner must yield exactly what the original single regex produced.
    from project_discovery.analyzers.network_analyzer import _literal_spans

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
