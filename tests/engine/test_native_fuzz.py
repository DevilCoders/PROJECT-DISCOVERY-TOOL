"""Differential fuzzing of the native FFI boundaries against their Python references.

Each native entry point gets seeded random input and is compared with the portable code it
stands in for: the C byte counter with ``bytes.count``, the C++ signature matcher with
``signatures.python_match_rule``, and the Rust walker with the Python ``os.scandir`` walk.
Malformed arguments must raise, never crash. The runs are bounded so they belong in every
suite: ``PDT_FUZZ_ITERATIONS`` raises the effort and ``PDT_FUZZ_SEED`` replays a run. CI
also runs them against builds with AddressSanitizer and UndefinedBehaviorSanitizer.
"""
from __future__ import annotations

import array
import os
import random
import sys
from pathlib import Path

import pytest

from project_discovery.engine import native
from project_discovery.inventory import scanner, signatures

ITERATIONS = int(os.environ.get("PDT_FUZZ_ITERATIONS", "600"))
SEED = os.environ.get("PDT_FUZZ_SEED", "20261113")
needs_c = pytest.mark.skipif(not native.native_available(), reason="the C extension is not built")
needs_cpp = pytest.mark.skipif(not native.signature_backend_available(), reason="the C++ classifier is not built")
needs_rust = pytest.mark.skipif(not native.rust_walker_available(), reason="the Rust walker is not built")

# Around the SIMD paths' 16-, 32- and 64-byte blocks and page boundaries.
_EDGE_LENGTHS = (0, 1, 2, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257,
                 4095, 4096, 4097, 65535, 65536, 65537)


def _rng(name: str) -> random.Random:
    return random.Random(f"{SEED}:{name}")


def _data(rng: random.Random, length: int) -> bytes:
    data = rng.randbytes(length)
    kind = rng.randrange(3)
    if kind == 1:  # a few distinct values, so the needle comes in long runs
        alphabet = bytes(rng.sample(range(256), rng.randrange(1, 4)))
        data = data.translate(bytes(alphabet[value % len(alphabet)] for value in range(256)))
    elif kind == 2:
        data = bytes(length)
    return data


def _views(rng: random.Random, data: bytes):
    """The same bytes as each contiguous buffer the readers hand over, at odd alignments."""
    before, after = rng.randbytes(rng.randrange(8)), rng.randbytes(rng.randrange(8))
    padded = before + data + after
    window = slice(len(before), len(before) + len(data))
    return (data, bytearray(data), memoryview(padded)[window], memoryview(bytearray(padded))[window],
            array.array("B", data))


@needs_c
def test_the_c_byte_counter_matches_python_on_random_buffers():
    rng = _rng("count_byte")
    count = native._native.count_byte
    for iteration in range(ITERATIONS):
        length = rng.choice(_EDGE_LENGTHS) if iteration % 2 else rng.randrange(1 << rng.randrange(1, 19))
        data = _data(rng, length)
        needle = data[rng.randrange(length)] if length and rng.random() < 0.5 else rng.randrange(256)
        expected = data.count(bytes((needle,)))
        for view in _views(rng, data):
            assert count(view, needle) == expected, (SEED, iteration, length, type(view).__name__, needle)


@needs_c
def test_the_c_byte_counter_rejects_malformed_arguments():
    count = native._native.count_byte
    for arguments, error in (
        ((b"abc",), TypeError),
        ((b"abc", 1, 2), TypeError),
        ((object(), 1), TypeError),
        (("text", 1), TypeError),  # str exposes no buffer
        ((b"abc", -1), ValueError),
        ((b"abc", 256), ValueError),
        ((b"abc", 1 << 70), OverflowError),
        ((b"abc", "a"), TypeError),
        ((b"abc", 1.5), TypeError),
        ((memoryview(b"abcdef")[::2], 97), BufferError),  # strided: not contiguous
    ):
        with pytest.raises(error):
            count(*arguments)
    with pytest.raises(ValueError):
        native.count_byte(b"", True)  # the wrapper refuses booleans before the extension
    assert count(memoryview(b"")[0:0], 0) == 0


def _sample(rng: random.Random) -> bytes:
    """A random sample with one rule's magic bytes planted, sometimes corrupted or cut short."""
    sample = bytearray(rng.randbytes(rng.choice((1, 2, 4, 16, 64, 600, 1100, signatures.SAMPLE_BYTES))))
    rule = rng.choice(signatures.RULES)
    for offset, data in rule.tests:
        if offset + len(data) <= len(sample):
            sample[offset:offset + len(data)] = data
    if rng.random() < 0.3:
        sample[rng.randrange(len(sample))] ^= 1 << rng.randrange(8)
    if rng.random() < 0.2:
        del sample[rng.randrange(len(sample)):]
    return bytes(sample)


@needs_cpp
def test_the_cpp_signature_matcher_matches_python_on_random_samples():
    rng = _rng("match_rule")
    matched = 0
    for iteration in range(ITERATIONS * 4):
        sample = _sample(rng)
        start = rng.randrange(len(signatures.RULES) + 2) if rng.random() < 0.3 else 0
        expected = signatures.python_match_rule(sample, start)
        for view in (sample, bytearray(sample), memoryview(sample)):
            assert native.match_signature_rule(view, start) == expected, (SEED, iteration, sample[:16], start)
        if start == 0:
            label = native.detect_signature(sample)
            assert label == (None if expected is None else signatures.RULES[expected].kind.label), (SEED, iteration)
        matched += expected is not None
    assert matched > ITERATIONS  # the planted magic bytes make most samples match something


@needs_cpp
def test_the_cpp_signature_matcher_rejects_malformed_arguments():
    cpp = native._native_cpp
    for call, error in (
        (lambda: cpp.match_rule(b"x", -1), ValueError),
        (lambda: cpp.match_rule(b"x", 1 << 80), OverflowError),
        (lambda: cpp.match_rule(object()), TypeError),
        (lambda: cpp.match_rule("text"), TypeError),
        (lambda: cpp.match_rule(memoryview(b"\x7fELF\x02\x01")[::2]), BufferError),
        (lambda: cpp.detect_signature(12), TypeError),
        (lambda: cpp.detect_signature(), TypeError),
    ):
        with pytest.raises(error):
            call()
    assert cpp.match_rule(b"\x7fELF", len(signatures.RULES) + 10**6) is None
    assert cpp.match_rule(b"") is None and cpp.detect_signature(b"") is None


_NAME_PARTS = ("a", "B", "z9", "_", "-", ".", " ", "é", "Ä", "日本", "ß", "Ω", "x" * 40, "ﬁ", "İ")


def _name(rng: random.Random) -> str:
    name = "".join(rng.choice(_NAME_PARTS) for _ in range(rng.randrange(1, 5))).strip(" .")
    return name or "n"


def _tree(rng: random.Random, root: Path) -> None:
    directories = [root]
    for _ in range(rng.randrange(20, 80)):
        parent = rng.choice(directories)
        name = _name(rng) + rng.choice(("", ".py", ".txt", ".zip", ".json", ""))
        target = parent / name
        if os.path.lexists(target):
            continue
        roll = rng.random()
        try:
            if roll < 0.3 and len(target.parts) - len(root.parts) < 6:
                target.mkdir()
                directories.append(target)
            elif roll < 0.38 and os.name != "nt":
                os.symlink(rng.choice(("missing", "..", name, str(root / "elsewhere"))), target)
            else:
                target.write_bytes(rng.randbytes(rng.randrange(0, 300)))
        except OSError:
            continue  # a name this filesystem refuses (length, normalization clash)


def _walk(root: Path) -> tuple:
    files, directories, symlinks, special, stats = scanner.discover_inventory(root)
    return ([item.to_dict() for item in files], [item.to_dict() for item in directories],
            [item.to_dict() for item in symlinks], [item.to_dict() for item in special], stats)


def _scan_results(output: Path) -> tuple:
    import json

    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    findings = sorted((item["title"], tuple(item["evidence"]), item["analyzer"]) for item in report["findings"])
    return report["files"], report["directories"], report["symlinks"], findings


def test_a_scan_without_any_native_module_reports_what_a_native_scan_does(tmp_path: Path, monkeypatch):
    from project_discovery.cli import run_scan

    rng = _rng("fallback")
    root = tmp_path / "tree"
    root.mkdir()
    _tree(rng, root)
    (root / "app.py").write_text("import os\nos.system(input())\nKEY = 'AKIAABCDEFGHIJKLMNOP'\n", encoding="utf-8")
    (root / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(64))
    assert run_scan(root, tmp_path / "native", {"json"}, 128, quiet=True, executor="thread") == 0
    # Withdraw the C counter, the C++ classifier and the Rust walker: every path falls back.
    monkeypatch.setattr(native, "_native", None)
    monkeypatch.setattr(native, "_native_cpp", None)
    monkeypatch.setattr(native, "_walker", None)
    monkeypatch.setattr(signatures, "_CPP_CURRENT", False)
    assert not (native.native_available() or native.signature_backend_available() or native.rust_walker_available())
    assert run_scan(root, tmp_path / "python", {"json"}, 128, quiet=True, executor="thread") == 0
    assert _scan_results(tmp_path / "python") == _scan_results(tmp_path / "native")


@needs_rust
@pytest.mark.parametrize("tree", range(4))
def test_the_rust_walker_inventories_random_trees_as_the_python_walk_does(tree, tmp_path: Path, monkeypatch):
    rng = _rng(f"walker:{tree}")
    root = tmp_path / "tree"
    root.mkdir()
    _tree(rng, root)
    rust = _walk(root)
    monkeypatch.setattr(scanner, "native_create_walker", lambda *_arguments, **_options: None)
    python = _walk(root)
    labels = ("files", "directories", "symlinks", "special entries", "counters")
    for label, from_rust, from_python in zip(labels, rust, python, strict=True):
        assert from_rust == from_python, (SEED, tree, label, sys.platform)
    assert rust[0], "the random tree holds files"
