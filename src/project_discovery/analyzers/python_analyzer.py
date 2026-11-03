"""Static Python AST analysis. Target modules are never imported or executed."""
import ast
from pathlib import Path
from .base import Analyzer
from ..models import FileRecord, Finding

class PythonAnalyzer(Analyzer):
    name = "python-ast"
    domains = ("source_structure", "symbol_index", "imports",)
    def supports(self, record: FileRecord) -> bool:
        return record.extension in {".py",".pyi"} and record.error is None
    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            source = path.read_text(encoding="utf-8")
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
