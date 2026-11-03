"""Static Python AST analysis. Target modules are never imported or executed."""
import ast
from pathlib import Path

MAX_AST_FILE_BYTES = 16 * 1024 * 1024
from .base import Analyzer
from ..models import FileRecord, Finding
from ..source_utils import read_python_source

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
            source = read_python_source(path)
            tree = ast.parse(source, filename=record.path)
        except (OSError, UnicodeDecodeError, SyntaxError) as exc:
            return [Finding("code","Python source parse error",str(exc),evidence=[record.path],analyzer=self.name)]
        classes, functions, imports = [], [], set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef): classes.append(node.name)
            elif isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)): functions.append(node.name)
            elif isinstance(node,ast.Import): imports.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node,ast.ImportFrom) and node.module: imports.add(node.module.split(".")[0])
        findings = [Finding("code",f"Python module: {record.path}",
            f"{len(source.splitlines())} lines; {len(classes)} classes; {len(functions)} functions; {len(imports)} imports.",
            evidence=[record.path],analyzer=self.name)]
        findings.extend(Finding("code_structure",f"Class: {name}",f"Declaration in {record.path}",
            evidence=[record.path],analyzer=self.name) for name in classes)
        findings.extend(Finding("code_structure",f"Function: {name}",f"Declaration in {record.path}",
            evidence=[record.path],analyzer=self.name) for name in functions)
        findings.extend(Finding("dependency",f"Python import: {name}",f"Static import in {record.path}",
            evidence=[record.path],analyzer=self.name) for name in sorted(imports))
        return findings
