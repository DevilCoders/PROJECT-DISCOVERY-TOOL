"""Static Python AST analysis. Target modules are never imported or executed."""
import ast
import io
from pathlib import Path

MAX_AST_FILE_BYTES = 16 * 1024 * 1024
MAX_SYMBOL_EVIDENCE = 200
from ...core.source_utils import SourceBudgetExceeded, parse_python, read_python_source_bounded
from ...models import FileRecord, Finding
from ..base import Analyzer


class PythonAnalyzer(Analyzer):
    name = "python-ast"
    domains = ("source_structure", "symbol_index", "imports",)
    def supports(self, record: FileRecord) -> bool:
        return (
            record.extension in {".py", ".pyi"}
            and record.error is None
            and record.content_skipped_reason is None
        )
    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        if record.size_bytes > MAX_AST_FILE_BYTES:
            return [Finding(
                "code",
                f"Python AST resource limit: {record.path}",
                f"File size {record.size_bytes:,} bytes exceeds this analyzer's "
                f"{MAX_AST_FILE_BYTES:,}-byte AST budget. Other bounded/streaming "
                "analyzers may still inspect the file.",
                confidence="UNKNOWN",
                evidence=[record.path, f"size: {record.size_bytes} bytes"],
                analyzer=self.name,
                severity="LOW",
            )]
        try:
            source = read_python_source_bounded(
                path, MAX_AST_FILE_BYTES,
                expected_identity=record.analysis_identity,
            )
        except SourceBudgetExceeded as exc:
            return [Finding(
                "code", f"Python AST resource limit: {record.path}", str(exc),
                confidence="UNKNOWN", evidence=[record.path],
                analyzer=self.name, severity="LOW",
            )]
        except (OSError, UnicodeDecodeError, SyntaxError, LookupError) as exc:
            return [Finding(
                "code", f"Python source parse error: {record.path}", str(exc),
                confidence="UNKNOWN", evidence=[record.path], analyzer=self.name,
            )]
        try:
            tree = parse_python(source, filename=record.path)
        except (SyntaxError, RecursionError, MemoryError) as exc:
            return [Finding(
                "code", f"Python source parse error: {record.path}", str(exc),
                confidence="UNKNOWN", evidence=[record.path],
                analyzer=self.name, severity="LOW",
            )]

        classes: list[tuple[str, int]] = []
        functions: list[tuple[str, int]] = []
        imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                classes.append((node.name, node.lineno))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.append((node.name, node.lineno))
            elif isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                imports.add(node.module.split(".")[0])

        # One structure finding and one import finding per module: per-symbol findings
        # made symbol listings the bulk of every report and did not scale.
        symbols = sorted(
            [("class", name, line) for name, line in classes]
            + [("function", name, line) for name, line in functions],
            key=lambda item: (item[2], item[1]),
        )
        detail = (
            f"{sum(1 for _ in io.StringIO(source, newline=None))} lines; {len(classes)} classes; "
            f"{len(functions)} functions; {len(imports)} imports."
        )
        if len(symbols) > MAX_SYMBOL_EVIDENCE:
            detail += (
                f" Evidence lists the first {MAX_SYMBOL_EVIDENCE} declarations; "
                f"{len(symbols) - MAX_SYMBOL_EVIDENCE} more are omitted."
            )
        findings = [Finding(
            "code",
            f"Python module: {record.path}",
            detail,
            evidence=[record.path] + [
                f"{record.path}:{line} ({kind} {name})"
                for kind, name, line in symbols[:MAX_SYMBOL_EVIDENCE]
            ],
            analyzer=self.name,
        )]
        if imports:
            findings.append(Finding(
                "dependency",
                f"Python imports: {record.path}",
                f"{len(imports)} distinct top-level module(s) imported statically.",
                evidence=sorted(imports)[:MAX_SYMBOL_EVIDENCE],
                analyzer=self.name,
            ))
        return findings
