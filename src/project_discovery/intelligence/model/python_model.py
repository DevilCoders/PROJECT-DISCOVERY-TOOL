"""Python backend of the code model, built from the standard-library ``ast``.

Target modules are parsed, never imported or executed. Call targets are resolved
within the file: names bound by imports become absolute (``pkg.mod.name``) or relative
(``.mod.name``) targets, names defined in the file become ``@Local.name`` targets, and
``self.x()`` / ``cls.x()`` inside a class become ``@Class.x``, and calls on an object
whose class the code states (``repo = Repo(); repo.find()``, annotations, return
annotations, ``self`` attributes; see ``python_types``) resolve to that class's method.
The cross-file index turns these hints into module-qualified call-graph edges.
"""
from __future__ import annotations

import ast
import builtins

from ...core.source_utils import parse_python
from . import Call, FileModel, Import, Symbol
from .python_types import TypeTable

_BUILTINS = frozenset(dir(builtins))


def _dotted(node: ast.AST) -> str:
    """``a.b.c`` for Name/Attribute chains, "" otherwise."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _decorator_name(node: ast.AST) -> str:
    return _dotted(node.func if isinstance(node, ast.Call) else node)


def _exported_names(tree: ast.Module) -> set[str] | None:
    """Names listed in a literal ``__all__``, or None when there is no such list."""
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets
        ) and isinstance(node.value, (ast.List, ast.Tuple)):
            return {
                item.value for item in node.value.elts
                if isinstance(item, ast.Constant) and isinstance(item.value, str)
            }
    return None


class _Builder(ast.NodeVisitor):
    def __init__(self, model: FileModel, tree: ast.Module) -> None:
        self.model = model
        self.scope: list[tuple[str, str]] = []  # (kind, qualified)
        self.aliases: dict[str, str] = {}
        self.local_top_level: set[str] = set()
        self.declared_all = _exported_names(tree)
        self.types = TypeTable(tree)
        self.functions: list = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.local_top_level.add(node.name)

    # -- scopes ---------------------------------------------------------------
    def _qualified(self, name: str) -> str:
        return f"{self.scope[-1][1]}.{name}" if self.scope else name

    def _container(self) -> str:
        return self.scope[-1][1] if self.scope else ""

    def _enclosing_class(self) -> str | None:
        for kind, qualified in reversed(self.scope):
            if kind == "class":
                return qualified
            if kind == "function" and qualified.count(".") == 0:
                return None
        return None

    def _exported(self, name: str) -> bool:
        if self.declared_all is not None and not self.scope:
            return name in self.declared_all
        return not name.startswith("_") or (name.startswith("__") and name.endswith("__"))

    def _caller(self) -> str:
        for kind, qualified in reversed(self.scope):
            if kind == "function":
                return qualified
        return "<module>"

    # -- definitions ----------------------------------------------------------
    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        in_class = bool(self.scope) and self.scope[-1][0] == "class"
        kind = "method" if in_class else "function"
        if in_class and node.name == "__init__":
            kind = "constructor"
        qualified = self._qualified(node.name)
        arguments = node.args
        params = tuple(
            item.arg for item in (
                *arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs,
                *((arguments.vararg,) if arguments.vararg else ()),
                *((arguments.kwarg,) if arguments.kwarg else ()),
            )
        )
        self.model.symbols.append(Symbol(
            kind, node.name, qualified, node.lineno, node.end_lineno or node.lineno,
            self._container(), self._exported(node.name),
            is_async=isinstance(node, ast.AsyncFunctionDef),
            decorators=tuple(filter(None, map(_decorator_name, node.decorator_list))),
            params=params,
        ))
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in (*arguments.defaults, *filter(None, arguments.kw_defaults)):
            self.visit(default)
        self.scope.append(("function", qualified))
        self.functions.append(node)
        for statement in node.body:
            self.visit(statement)
        self.functions.pop()
        self.scope.pop()

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        qualified = self._qualified(node.name)
        self.model.symbols.append(Symbol(
            "class", node.name, qualified, node.lineno, node.end_lineno or node.lineno,
            self._container(), self._exported(node.name),
            decorators=tuple(filter(None, map(_decorator_name, node.decorator_list))),
            params=tuple(filter(None, map(_dotted, node.bases))),
        ))
        for item in (*node.decorator_list, *node.bases, *node.keywords):
            self.visit(item)
        self.scope.append(("class", qualified))
        for statement in node.body:
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        self.model.symbols.append(Symbol(
                            "field", target.id, f"{qualified}.{target.id}", statement.lineno,
                            statement.end_lineno or statement.lineno, qualified,
                            not target.id.startswith("_"),
                        ))
            self.visit(statement)
        self.scope.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        if not self.scope:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.model.symbols.append(Symbol(
                        "constant" if target.id.isupper() else "variable", target.id, target.id,
                        node.lineno, node.end_lineno or node.lineno, "", self._exported(target.id),
                    ))
        self.generic_visit(node)

    # -- imports --------------------------------------------------------------
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.model.imports.append(Import(alias.name, node.lineno))
            if alias.asname:
                self.aliases[alias.asname] = alias.name
            else:
                top = alias.name.split(".", 1)[0]
                self.aliases[top] = top

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        base = ("." * node.level) + (node.module or "")
        names = tuple(alias.name for alias in node.names)
        self.model.imports.append(Import(node.module or "", node.lineno, names, node.level))
        for alias in node.names:
            if alias.name == "*":
                continue
            joiner = "" if base.endswith(".") or not base else "."
            self.aliases[alias.asname or alias.name] = f"{base}{joiner}{alias.name}"

    # -- calls and references ---------------------------------------------------
    def _target(self, func: ast.AST) -> tuple[str, str, str]:
        """(callee, receiver, target) for a call's function expression."""
        if isinstance(func, ast.Name):
            name = func.id
            if name in self.aliases:
                return name, "", self.aliases[name]
            if name in self.local_top_level:
                return name, "", f"@{name}"
            if name in _BUILTINS:
                return name, "", f"builtins.{name}"
            return name, "", ""
        if isinstance(func, ast.Attribute):
            receiver = _dotted(func.value)
            if receiver in {"self", "cls"}:
                owner = self._enclosing_class()
                return func.attr, receiver, f"@{owner}.{func.attr}" if owner else ""
            head, _, rest = receiver.partition(".")
            if head in self.aliases:
                resolved = self.aliases[head] + (f".{rest}" if rest else "")
                return func.attr, receiver, f"{resolved}.{func.attr}"
            if head in self.local_top_level:
                return func.attr, receiver, f"@{receiver}.{func.attr}"
            return func.attr, receiver or "<expression>", self._typed(func) or ""
        return "<dynamic>", "", ""

    def _typed(self, func: ast.Attribute) -> str | None:
        """``Ref.method`` when the receiver's class is known from the code."""
        owner = self._enclosing_class()
        owner = owner if owner in self.types.classes else None
        scope = self.types.scope(self.functions[-1], owner) if self.functions else self.types.module_scope
        return self.types.method_target(func.value, func.attr, scope, owner)

    def visit_Call(self, node: ast.Call) -> None:
        callee, receiver, target = self._target(node.func)
        self.model.calls.append(Call(self._caller(), callee, receiver, target, node.lineno))
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load):
            self.model.references.add(node.id)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.ctx, ast.Load):
            self.model.references.add(node.attr)
        self.generic_visit(node)


def build_python_model(path: str, source: str) -> FileModel:
    tree = parse_python(source, filename=path)
    model = FileModel(path, "Python", "python-ast", source, tree=tree)
    builder = _Builder(model, tree)
    builder.visit(tree)
    model.types = builder.types
    return model
