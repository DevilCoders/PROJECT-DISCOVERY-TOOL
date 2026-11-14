"""Elaboration of HDL parameters and generate constructs, for the design hierarchy.

Synthesis elaborates a design top-down: each instance's parameters (Verilog ``#(.N(8))``,
VHDL ``generic map (N => 8)``) override the child's defaults, generate loops repeat their
bodies and generate conditions keep one branch. The analyzer records, per design unit, the
parameter defaults and, per instance inside a generate construct or with overrides, the
constructs around it; the code index evaluates them here.

Everything is bounded: expressions are at most 400 characters and nest at most 64 levels,
values stay within 62 bits, a loop is followed for at most 65,536 iterations, and a top
level is elaborated through at most 200,000 instance sites. Whatever cannot be evaluated
(an unknown parameter, a function call, a loop beyond the bound) keeps the lexical count,
and the site is reported as not elaborated.
"""
from __future__ import annotations

import re

MAX_EXPRESSION = 400
MAX_NESTING = 64
MAX_ITERATIONS = 65_536
LIMIT = 1 << 62

# Tokens start at a non-space character (whitespace is skipped in code, which keeps an
# unanchored search linear). Sized literals are written without inner spaces (8'hFF).
_VERILOG_TOKEN = re.compile(
    r"(?P<number>\d[\d_]*+(?:'[sS]?[bBoOdDhH][0-9a-fA-FxXzZ_?]++|\.\d++)?|'[sS]?[bBoOdDhH][0-9a-fA-FxXzZ_?]++)"
    r"|(?P<name>\$?[A-Za-z_][\w$]*+)"
    r"|(?P<op>\*\*|<<<|>>>|<<|>>|<=|>=|===|!==|==|!=|&&|\|\||~&|~\||~\^|\^~|[-+*/%<>!~&|^?:(),])"
)
_VHDL_TOKEN = re.compile(
    r"(?P<number>\d[\d_]*+(?:#[0-9a-fA-F_]++#|\.\d++)?)"
    r"|(?P<name>[A-Za-z][\w]*+)"
    r"|(?P<op>\*\*|/=|<=|>=|=>|[-+*/<>=&(),])"
)
_VHDL_WORD_OPERATORS = frozenset({"and", "or", "xor", "nand", "nor", "xnor", "mod", "rem", "abs", "not"})


class _Unknown(Exception):
    """The expression names something unknown or uses what the evaluator does not model."""


def _verilog_number(text: str) -> int:
    text = text.replace("_", "").replace(" ", "")
    if "'" not in text:
        if "." in text:
            raise _Unknown("real number")
        return int(text)
    _size, _, rest = text.partition("'")
    rest = rest.lstrip("sS")
    base = {"b": 2, "o": 8, "d": 10, "h": 16}[rest[0].lower()]
    digits = rest[1:]
    if any(char in "xXzZ?" for char in digits):
        raise _Unknown("x or z digits")
    return int(digits, base)


def _vhdl_number(text: str) -> int:
    text = text.replace("_", "")
    if "#" in text:
        base, digits, _ = text.split("#")
        return int(digits, int(base))
    if "." in text:
        raise _Unknown("real number")
    return int(text)


def _tokens(expression: str, language: str) -> list[tuple[str, str]]:
    if len(expression) > MAX_EXPRESSION:
        raise _Unknown("expression too long")
    pattern = _VHDL_TOKEN if language == "vhdl" else _VERILOG_TOKEN
    tokens, position = [], 0
    text = expression.rstrip()
    while position < len(text):
        while text[position].isspace():
            position += 1
        match = pattern.match(text, position)
        if match is None or match.end() == position:
            raise _Unknown(f"unexpected text {text[position:position + 12]!r}")
        position = match.end()
        kind = match.lastgroup
        value = match.group(kind)
        if language == "vhdl" and kind == "name" and value.lower() in _VHDL_WORD_OPERATORS:
            kind, value = "op", value.lower()
        tokens.append((kind, value))
    return tokens


class _Parser:
    """A precedence-climbing evaluator for integer constant expressions."""

    _VERILOG_BINARY = {
        "||": 1, "&&": 2, "|": 3, "~|": 3, "^": 4, "~^": 4, "^~": 4, "&": 5, "~&": 5,
        "==": 6, "!=": 6, "===": 6, "!==": 6, "<": 7, "<=": 7, ">": 7, ">=": 7,
        "<<": 8, ">>": 8, "<<<": 8, ">>>": 8, "+": 9, "-": 9, "*": 10, "/": 10, "%": 10, "**": 11,
    }
    _VHDL_BINARY = {
        "or": 1, "nor": 1, "xor": 1, "xnor": 1, "and": 1, "nand": 1,
        "=": 2, "/=": 2, "<": 2, "<=": 2, ">": 2, ">=": 2,
        "+": 3, "-": 3, "*": 4, "/": 4, "mod": 4, "rem": 4, "**": 5,
    }

    def __init__(self, tokens, env: dict[str, int], language: str) -> None:
        self.tokens, self.env, self.language, self.position = tokens, env, language, 0
        self.binary = self._VHDL_BINARY if language == "vhdl" else self._VERILOG_BINARY

    def peek(self):
        return self.tokens[self.position] if self.position < len(self.tokens) else (None, None)

    def take(self):
        token = self.peek()
        self.position += 1
        return token

    def expect(self, value: str) -> None:
        if self.take()[1] != value:
            raise _Unknown(f"expected {value!r}")

    def parse(self) -> int:
        value = self.ternary(0)
        if self.position != len(self.tokens):
            raise _Unknown("trailing text")
        return value

    def ternary(self, depth: int) -> int:
        condition = self.binary_expression(0, depth)
        if self.language != "vhdl" and self.peek()[1] == "?":
            self.take()
            then = self.ternary(depth + 1)
            self.expect(":")
            otherwise = self.ternary(depth + 1)
            return then if condition else otherwise
        return condition

    def binary_expression(self, minimum: int, depth: int) -> int:
        if depth > MAX_NESTING:
            raise _Unknown("nested too deeply")
        left = self.unary(depth)
        while True:
            kind, operator = self.peek()
            precedence = self.binary.get(operator) if kind == "op" else None
            if precedence is None or precedence < minimum:
                return left
            self.take()
            # ``**`` is right-associative; everything else associates to the left.
            right = self.binary_expression(precedence if operator == "**" else precedence + 1, depth + 1)
            left = _check(_apply(operator, left, right))

    def unary(self, depth: int) -> int:
        kind, value = self.peek()
        if kind == "op" and value in {"-", "+", "!", "~", "not", "abs"}:
            self.take()
            operand = self.unary(depth + 1)
            return _check({"-": -operand, "+": operand, "!": int(not operand), "~": ~operand,
                           "not": int(not operand), "abs": abs(operand)}[value])
        return self.primary(depth)

    def primary(self, depth: int) -> int:
        kind, value = self.take()
        if kind == "number":
            return _check(_vhdl_number(value) if self.language == "vhdl" else _verilog_number(value))
        if kind == "name":
            if value in {"$clog2", "$floor", "$ceil"} or (self.language == "vhdl" and value.lower() in {"log2", "clog2"}):
                self.expect("(")
                argument = self.ternary(depth + 1)
                self.expect(")")
                if value in {"$floor", "$ceil"}:
                    return argument
                return max(0, (argument - 1).bit_length()) if argument > 0 else 0
            key = value.lower() if self.language == "vhdl" else value
            if key in self.env:
                return self.env[key]
            if self.language == "vhdl" and key in {"true", "false"}:
                return int(key == "true")
            raise _Unknown(f"unknown name {value}")
        if value == "(":
            inner = self.ternary(depth + 1)
            self.expect(")")
            return inner
        raise _Unknown(f"unexpected {value!r}")


def _apply(operator: str, left: int, right: int) -> int:
    if operator in {"/", "%", "mod", "rem"} and right == 0:
        raise _Unknown("division by zero")
    if operator == "**":
        if right < 0 or right > 64 or abs(left) > LIMIT:
            raise _Unknown("power out of range")
        return left ** right
    if operator in {"<<", "<<<"}:
        if not 0 <= right <= 62:
            raise _Unknown("shift out of range")
        return left << right
    if operator in {">>", ">>>"}:
        return left >> right if right >= 0 else 0
    return {
        "+": lambda: left + right, "-": lambda: left - right, "*": lambda: left * right,
        "/": lambda: int(left / right), "%": lambda: left - int(left / right) * right,
        "mod": lambda: left % right, "rem": lambda: left - int(left / right) * right,
        "==": lambda: int(left == right), "===": lambda: int(left == right), "=": lambda: int(left == right),
        "!=": lambda: int(left != right), "!==": lambda: int(left != right), "/=": lambda: int(left != right),
        "<": lambda: int(left < right), "<=": lambda: int(left <= right),
        ">": lambda: int(left > right), ">=": lambda: int(left >= right),
        "&&": lambda: int(bool(left) and bool(right)), "||": lambda: int(bool(left) or bool(right)),
        "and": lambda: int(bool(left) and bool(right)), "or": lambda: int(bool(left) or bool(right)),
        "nand": lambda: int(not (left and right)), "nor": lambda: int(not (left or right)),
        "xor": lambda: int(bool(left) != bool(right)), "xnor": lambda: int(bool(left) == bool(right)),
        "&": lambda: left & right, "|": lambda: left | right, "^": lambda: left ^ right,
        "~&": lambda: ~(left & right), "~|": lambda: ~(left | right), "~^": lambda: ~(left ^ right),
        "^~": lambda: ~(left ^ right),
    }[operator]()


def _check(value: int) -> int:
    if abs(value) > LIMIT:
        raise _Unknown("value out of range")
    return value


def _split_top(text: str, separator: str) -> list[str]:
    """``text`` split at ``separator`` outside parentheses and brackets."""
    parts, depth, start = [], 0, 0
    for index, char in enumerate(text):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == separator and depth == 0:
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    return parts


def evaluate(expression: str, env: dict[str, int], language: str = "verilog") -> int | None:
    """The integer value of a constant expression, or None when it cannot be told."""
    try:
        tokens = _tokens(expression, language)
        if not tokens:
            return None
        return _Parser(tokens, env, language).parse()
    except (_Unknown, ValueError, KeyError, RecursionError, OverflowError):
        return None


# -- loops ------------------------------------------------------------------------------------
_STEP = re.compile(
    r"^\s*+(?:(?P<pre>\+\+|--)\s*+(?P<pre_var>[A-Za-z_][\w$]*+)|(?P<var>[A-Za-z_][\w$]*+)\s*+"
    r"(?:(?P<post>\+\+|--)|(?P<op>[-+*/]?=)(?P<value>.+)))$",
    re.S,
)


def verilog_loop_values(variable: str, init: str, condition: str, step: str, env: dict[str, int]) -> list[int] | None:
    """The values a generate-for variable takes, or None when the loop cannot be followed."""
    start = evaluate(init, env)
    if start is None:
        return None
    match = _STEP.match(step)
    if match is None:
        return None
    target = match.group("pre_var") or match.group("var")
    if target != variable:
        return None
    values, value = [], start
    scope = dict(env)
    for _ in range(MAX_ITERATIONS + 1):
        scope[variable] = value
        holds = evaluate(condition, scope)
        if holds is None:
            return None
        if not holds:
            return values
        if len(values) >= MAX_ITERATIONS:
            return None
        values.append(value)
        if match.group("pre") or match.group("post"):
            following = value + (1 if (match.group("pre") or match.group("post")) == "++" else -1)
        else:
            operator, amount = match.group("op"), evaluate(match.group("value"), scope)
            if amount is None:
                return None
            following = {
                "=": amount, "+=": value + amount, "-=": value - amount, "*=": value * amount,
                "/=": int(value / amount) if amount else None,
            }[operator]
            if following is None:
                return None
        if following == value:
            return None  # the loop would not terminate
        value = _check(following)
    return None


def vhdl_range_values(low: str, high: str, direction: str, env: dict[str, int]) -> list[int] | None:
    """The values of a VHDL ``for i in A to B generate`` parameter, or None."""
    first, last = evaluate(low, env, "vhdl"), evaluate(high, env, "vhdl")
    if first is None or last is None:
        return None
    values = range(first, last + 1) if direction == "to" else range(first, last - 1, -1)
    return list(values) if len(values) <= MAX_ITERATIONS else None


# -- elaboration of a design hierarchy ------------------------------------------------------
MAX_SITES = 200_000   # instance sites visited per top-level unit
MAX_DEPTH = 64        # hierarchy depth, also for recursion bounded by generate conditions


class Elaborator:
    """Elaborate top-level units through parameters, overrides and generate constructs.

    ``parameters[unit]`` lists ``(name, default expression, overridable)`` in declaration
    order; ``sites[unit]`` lists ``(child, constructs, overrides, array)`` for each instance
    inside a generate construct, with parameter overrides or an instance-array range;
    ``plain[unit][child]`` counts the other instances. Unit keys are lower-case;
    ``languages[unit]`` is ``verilog`` or ``vhdl``.
    """

    def __init__(self, units: set[str], plain: dict, sites: dict, parameters: dict, languages: dict) -> None:
        self.units, self.plain, self.sites = units, plain, sites
        self.parameters, self.languages = parameters, languages
        self.reasons: dict[str, int] = {}
        self.samples: list[str] = []

    def _note(self, unit: str, reason: str) -> None:
        self.reasons[reason] = self.reasons.get(reason, 0) + 1
        if len(self.samples) < 20:
            self.samples.append(f"{unit}: {reason}")

    def environment(self, unit: str, named: dict[str, int], positional: list[int | None]) -> dict[str, int]:
        """A unit's parameter values: its defaults, with the overrides that could be evaluated."""
        language = self.languages.get(unit, "verilog")
        declared = self.parameters.get(unit, [])
        overridable = [name for name, _expression, can in declared if can]
        given: dict[str, int] = {}
        for index, value in enumerate(positional):
            if index < len(overridable) and value is not None:
                given[overridable[index].lower()] = value
        given.update({name.lower(): value for name, value in named.items() if value is not None})
        env: dict[str, int] = {}
        for name, expression, can in declared:
            key = name.lower() if language == "vhdl" else name
            if can and name.lower() in given:
                env[key] = given[name.lower()]
                continue
            value = evaluate(expression, env, language) if expression else None
            if value is not None:
                env[key] = value
        return env

    def _expand(self, unit: str, constructs: list, env: dict[str, int]) -> list[dict[str, int]] | None:
        """The environments in which a site's instance exists: one per loop iteration."""
        language = self.languages.get(unit, "verilog")
        scopes = [env]
        for construct in constructs:
            kind = construct[0]
            following: list[dict[str, int]] = []
            for scope in scopes:
                if kind == "for":
                    _, variable, init, condition, step = construct
                    values = verilog_loop_values(variable, init, condition, step, scope)
                    if values is None:
                        self._note(unit, f"generate loop not evaluated: for ({init}; {condition}; {step})"[:160])
                        return None
                    following.extend({**scope, variable: value} for value in values)
                elif kind == "range":
                    _, variable, low, high, direction = construct
                    values = vhdl_range_values(low, high, direction, scope)
                    if values is None:
                        self._note(unit, f"generate range not evaluated: {low} {direction} {high}"[:160])
                        return None
                    following.extend({**scope, variable.lower(): value} for value in values)
                elif kind == "if":
                    _, condition, taken = construct
                    holds = evaluate(condition, scope, language)
                    if holds is None:
                        self._note(unit, f"generate condition not evaluated: {condition}"[:160])
                        return None
                    if bool(holds) == bool(taken):
                        following.append(scope)
                else:
                    self._note(unit, f"{kind} generate not elaborated")
                    return None
                if len(following) > MAX_ITERATIONS:
                    self._note(unit, "generate construct beyond the iteration bound")
                    return None
            scopes = following
        return scopes

    def _array_size(self, unit: str, array: str | None, scope: dict[str, int]) -> int:
        """Instances in an instance array ``[msb:lsb]`` (one when there is none or it is unknown)."""
        if not array:
            return 1
        bounds = _split_top(array, ":")
        values = [evaluate(bound, scope, self.languages.get(unit, "verilog")) for bound in bounds]
        if len(values) == 1 and values[0] is not None and values[0] > 0:
            return values[0]  # SystemVerilog ``u [8]``
        if len(values) == 2 and None not in values:
            return abs(values[0] - values[1]) + 1
        self._note(unit, f"instance array not evaluated: [{array}]"[:160])
        return 1

    def _overrides(self, unit: str, overrides, scope: dict[str, int]) -> tuple[dict[str, int], list[int | None]]:
        language = self.languages.get(unit, "verilog")
        if isinstance(overrides, dict):
            return {name: evaluate(expression, scope, language) for name, expression in overrides.items()}, []
        if isinstance(overrides, list):
            return {}, [evaluate(expression, scope, language) for expression in overrides]
        return {}, []

    def top(self, unit: str) -> dict:
        """Elaborated instance count and depth below ``unit``, and whether it is complete."""
        state = {"work": 0, "complete": True}
        memo: dict[tuple, tuple[int, int]] = {}

        def visit(node: str, env: dict[str, int], trail: tuple) -> tuple[int, int]:
            key = (node, tuple(sorted(env.items())))
            if key in memo:
                return memo[key]
            if key in trail or len(trail) >= MAX_DEPTH:
                self._note(node, "recursion that elaboration does not end")
                state["complete"] = False
                return 0, 1
            trail = (*trail, key)
            total, depth = 0, 1
            for child, count in sorted(self.plain.get(node, {}).items()):
                if child not in self.units or count <= 0:
                    continue
                below, child_depth = visit(child, self.environment(child, {}, []), trail)
                total += count * (1 + below)
                depth = max(depth, child_depth + 1)
            for child, constructs, overrides, array in self.sites.get(node, []):
                if child not in self.units:
                    continue
                state["work"] += 1
                scopes = None if state["work"] > MAX_SITES else self._expand(node, constructs, env)
                if scopes is None:
                    if state["work"] > MAX_SITES and state["complete"]:
                        self._note(node, "elaboration budget reached")
                    state["complete"] = False
                    scopes = [env]  # the lexical count: one instance
                for scope in scopes:
                    named, positional = self._overrides(node, overrides, scope)
                    below, child_depth = visit(child, self.environment(child, named, positional), trail)
                    total += self._array_size(node, array, scope) * (1 + below)
                    depth = max(depth, child_depth + 1)
                    state["work"] += 1
                    if state["work"] > MAX_SITES:
                        break
            result = (min(total, 10 ** 12), depth)
            memo[key] = result
            return result

        total, depth = visit(unit, self.environment(unit, {}, []), ())
        return {"instances": total, "depth": depth, "complete": state["complete"]}
