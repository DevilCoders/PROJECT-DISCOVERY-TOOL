"""Elaboration of HDL parameters, overrides and generate constructs."""
import time

from project_discovery.intelligence.hdl_elaboration import (
    Elaborator, evaluate, verilog_loop_values, vhdl_range_values,
)


def test_constant_expressions_in_both_languages():
    cases = [
        ("8'hFF + 1", {}, "verilog", 256), ("'d10 * 2", {}, "verilog", 20), ("N * 2 - 1", {"N": 4}, "verilog", 7),
        ("$clog2(DEPTH)", {"DEPTH": 1024}, "verilog", 10), ("W > 8 ? W / 2 : 0", {"W": 16}, "verilog", 8),
        ("2 ** 10", {}, "verilog", 1024), ("1 << 4 | 1", {}, "verilog", 17), ("-7 % 3", {}, "verilog", -1),
        ("!(A == 2) && 1", {"A": 2}, "verilog", 0), ("16#FF# + n", {"n": 1}, "vhdl", 256),
        ("N mod 3", {"n": 10}, "vhdl", 1), ("not (A = 2) and true", {"a": 2}, "vhdl", 0),
        ("WIDTH / 8 - 1", {"width": 32}, "vhdl", 3),
    ]
    for expression, env, language, expected in cases:
        assert evaluate(expression, env, language) == expected, expression


def test_what_cannot_be_evaluated_is_unknown():
    for expression, env in (
        ("UNKNOWN + 1", {}), ("4'b1x0z", {}), ("N / 0", {"N": 1}), ("1 << 70", {}), ("2 ** 99", {}),
        ("f(3)", {}), ("(1 + 2", {}), ("1.5 * 2", {}), ("x" * 500, {}), ("(" * 200 + "1" + ")" * 200, {}),
    ):
        assert evaluate(expression, env) is None, expression[:40]


def test_loops_are_followed_within_their_bounds():
    assert verilog_loop_values("i", "0", "i < N", "i = i + 1", {"N": 4}) == [0, 1, 2, 3]
    assert verilog_loop_values("i", "1", "i <= 8", "i = i * 2", {}) == [1, 2, 4, 8]
    assert verilog_loop_values("k", "3", "k >= 0", "k--", {}) == [3, 2, 1, 0]
    assert verilog_loop_values("k", "0", "k < 6", "k += 2", {}) == [0, 2, 4]
    assert verilog_loop_values("i", "0", "i < 4", "i = i", {}) is None          # never ends
    assert verilog_loop_values("i", "0", "i < 1000000", "i++", {}) is None      # beyond the bound
    assert verilog_loop_values("i", "0", "i < N", "j = j + 1", {"N": 2}) is None
    assert vhdl_range_values("0", "N - 1", "to", {"n": 3}) == [0, 1, 2]
    assert vhdl_range_values("3", "0", "downto", {}) == [3, 2, 1, 0]
    assert vhdl_range_values("2", "1", "to", {}) == []


def test_elaboration_follows_overrides_loops_conditions_arrays_and_bounded_recursion():
    units = {"top", "lane", "cell", "tree", "loop"}
    plain = {"top": {}, "lane": {}, "tree": {}, "loop": {"loop": 1}}
    parameters = {
        "top": [["LANES", "4", True]], "lane": [["WIDTH", "8", True]], "tree": [["N", "2", True]],
    }
    sites = {
        "top": [
            ("lane", [["for", "i", "0", "i < LANES", "i++"]], {"WIDTH": "8 * (i + 1)"}, None),
            ("tree", [], {"N": "4"}, None),
        ],
        "lane": [("cell", [["for", "b", "0", "b < WIDTH / 8", "b++"]], None, "1:0")],
        "tree": [
            ("tree", [["if", "N > 1", True]], {"N": "N / 2"}, None),
            ("tree", [["if", "N > 1", True]], {"N": "N / 2"}, None),
            ("cell", [["if", "N > 1", False]], None, None),
        ],
    }
    languages = dict.fromkeys(units, "verilog")
    elaborator = Elaborator(units, plain, sites, parameters, languages)
    # 4 lanes with 1, 2, 3 and 4 two-cell arrays (20 cells), and a tree of 4 leaves:
    # tree(4) -> 2 x tree(2) -> 4 x tree(1) -> 4 cells, 11 instances with the top tree.
    assert elaborator.top("top") == {"instances": 4 + 20 + 11, "depth": 5, "complete": True}
    unbounded = elaborator.top("loop")
    assert unbounded["complete"] is False
    assert "recursion that elaboration does not end" in elaborator.reasons


def test_unknown_values_keep_the_written_count_and_are_reported():
    units = {"top", "cell"}
    sites = {"top": [("cell", [["for", "i", "0", "i < MISSING", "i++"]], None, None)]}
    elaborator = Elaborator(units, {"top": {}}, sites, {}, {"top": "verilog", "cell": "verilog"})
    assert elaborator.top("top") == {"instances": 1, "depth": 2, "complete": False}
    assert any("generate loop not evaluated" in reason for reason in elaborator.reasons)


def test_wide_hierarchies_stay_bounded():
    # A balanced tree of 2**20 leaves: memoized by (unit, parameters), so fast.
    units = {"tree", "cell"}
    sites = {"tree": [
        ("tree", [["if", "N > 1", True]], {"N": "N - 1"}, None),
        ("tree", [["if", "N > 1", True]], {"N": "N - 1"}, None),
        ("cell", [["if", "N > 1", False]], None, None),
    ]}
    elaborator = Elaborator(units, {"tree": {}}, sites, {"tree": [["N", "20", True]]}, dict.fromkeys(units, "verilog"))
    started = time.perf_counter()
    result = elaborator.top("tree")
    assert time.perf_counter() - started < 2
    # Below tree(N): T(1) = 1 cell and T(N) = 2 * (1 + T(N - 1)), so T(N) = 3 * 2 ** (N - 1) - 2.
    assert result == {"instances": 3 * 2 ** 19 - 2, "depth": 21, "complete": True}
