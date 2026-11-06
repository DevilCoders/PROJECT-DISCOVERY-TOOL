"""Class types of Python names, taken from what the code states.

The code model and the taint engine use these types to resolve calls on objects:
``repo = Repository(); repo.find(name)`` calls ``Repository.find``. A name gets a type
from a constructor call, an annotation (``x: Repo``, ``def f(repo: Repo)``,
``Optional[Repo]``, ``Repo | None`` or a quoted forward reference), a function's return
annotation, ``with Repo() as repo``, or an attribute of ``self`` assigned in any method.

The inference is flow-insensitive and conservative. A name assigned two different
classes, or assigned anything whose class is unknown (other than ``None``), gets no
type. Only classes defined in the module, and capitalized names imported into it, are
types. A type is a reference: ``@Name`` for a class of this module, or the import path
(``pkg.mod.Name`` or the relative ``.mod.Name``) for an imported one.
"""
from __future__ import annotations

import ast

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_WRAPPERS = frozenset({"Optional", "Annotated", "Final", "ClassVar", "Type", "type"})
_UNKNOWN = object()


def _imports(body: list):
    """Import statements anywhere in ``body``; only statement lists are visited."""
    for statement in body:
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            yield statement
            continue
        for name in ("body", "orelse", "finalbody"):
            inner = getattr(statement, name, None)
            if isinstance(inner, list):
                yield from _imports(inner)
        for handler in getattr(statement, "handlers", None) or ():
            yield from _imports(handler.body)
        for case in getattr(statement, "cases", None) or ():
            yield from _imports(case.body)


def module_aliases(tree: ast.Module) -> dict[str, str]:
    """Local name -> import path, for every import in the module."""
    aliases: dict[str, str] = {}
    for node in _imports(tree.body):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    top = alias.name.split(".", 1)[0]
                    aliases[top] = top
        elif isinstance(node, ast.ImportFrom):
            base = "." * node.level + (node.module or "")
            joiner = "" if base.endswith(".") or not base else "."
            for alias in node.names:
                if alias.name != "*":
                    aliases[alias.asname or alias.name] = f"{base}{joiner}{alias.name}"
    return aliases


def _dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _is_none(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _statements(body: list):
    """The statements of a function body in source order, without nested definitions."""
    for statement in body:
        if isinstance(statement, (*_FUNCTIONS, ast.ClassDef)):
            continue
        yield statement
        for name in ("body", "orelse", "finalbody"):
            inner = getattr(statement, name, None)
            if isinstance(inner, list):
                yield from _statements(inner)
        for handler in getattr(statement, "handlers", None) or ():
            yield from _statements(handler.body)
        for case in getattr(statement, "cases", None) or ():
            yield from _statements(case.body)


class TypeTable:
    def __init__(self, tree: ast.Module, aliases: dict[str, str] | None = None) -> None:
        self.aliases = module_aliases(tree) if aliases is None else aliases
        self.classes = {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}
        self.returns: dict[str, str] = {}
        self._scopes: dict[tuple[int, str | None], dict[str, str]] = {}
        for node in tree.body:
            if isinstance(node, _FUNCTIONS) and node.returns is not None:
                self._note_return(node.name, node.returns)
            elif isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, _FUNCTIONS) and item.returns is not None:
                        self._note_return(f"{node.name}.{item.name}", item.returns)
        self._attributes_by_class: dict[str, dict[str, str]] = {}
        self.module_scope = self._bindings(tree.body, {}, None)[0]

    def _note_return(self, key: str, annotation: ast.AST) -> None:
        reference = self.reference(annotation)
        if reference is not None:
            self.returns[key] = reference

    # -- references ------------------------------------------------------------
    def reference(self, node: ast.AST | None) -> str | None:
        """The class an annotation or callee expression names, if any."""
        if node is None:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            try:
                node = ast.parse(node.value, mode="eval").body
            except SyntaxError:
                return None
        if isinstance(node, ast.Subscript) and _dotted(node.value).rpartition(".")[2] in _WRAPPERS:
            inner = node.slice
            return self.reference(inner.elts[0] if isinstance(inner, ast.Tuple) and inner.elts else inner)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            if _is_none(node.right):
                return self.reference(node.left)
            if _is_none(node.left):
                return self.reference(node.right)
            return None
        dotted = _dotted(node)
        if not dotted:
            return None
        head, _, rest = dotted.partition(".")
        if not rest and head in self.classes:
            return f"@{head}"
        if head in self.aliases and dotted.rpartition(".")[2][:1].isupper():
            return self.aliases[head] + (f".{rest}" if rest else "")
        return None

    def value_type(self, node: ast.AST | None, scope: dict[str, str], owner: str | None):
        """The class of an expression's value; ``_UNKNOWN`` when it cannot be told."""
        if node is None or _is_none(node):
            return None
        if isinstance(node, ast.Call):
            constructor = self.reference(node.func)
            if constructor is not None:
                return constructor
            name = _dotted(node.func)
            if name in self.returns:
                return self.returns[name]
            if isinstance(node.func, ast.Attribute):
                receiver = self.value_type(node.func.value, scope, owner)
                if isinstance(receiver, str) and receiver.startswith("@"):
                    return self.returns.get(f"{receiver[1:]}.{node.func.attr}", _UNKNOWN)
            return _UNKNOWN
        if isinstance(node, ast.Name):
            return scope.get(node.id, _UNKNOWN)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "self" and owner:
            return self.attributes(owner).get(node.attr, _UNKNOWN)
        if isinstance(node, (ast.BoolOp, ast.IfExp)):
            # ``store or Store()`` and ``a if c else b``: one class across the alternatives.
            options = node.values if isinstance(node, ast.BoolOp) else (node.body, node.orelse)
            found = {self.value_type(option, scope, owner) for option in options} - {None}
            return found.pop() if len(found) == 1 else _UNKNOWN
        return _UNKNOWN

    # -- scopes ----------------------------------------------------------------
    def scope(self, function: ast.FunctionDef | ast.AsyncFunctionDef, owner: str | None = None) -> dict[str, str]:
        """Names of ``function`` with a single known class: parameters, locals and the
        module-level names the function does not bind itself."""
        key = (id(function), owner)
        if key in self._scopes:
            return self._scopes[key]
        scope: dict[str, str] = {}
        arguments = function.args
        parameters = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs,
                      *filter(None, (arguments.vararg, arguments.kwarg))]
        for argument in parameters:
            reference = self.reference(argument.annotation) if argument.annotation is not None else None
            if reference is not None:
                scope[argument.arg] = reference
        scope, bound = self._bindings(function.body, scope, owner)
        bound.update(argument.arg for argument in parameters)
        for name, reference in getattr(self, "module_scope", {}).items():
            if name not in bound:
                scope.setdefault(name, reference)
        self._scopes[key] = scope
        return scope

    def _bindings(self, body: list, scope: dict[str, str], owner: str | None) -> tuple[dict[str, str], set[str]]:
        """Types assigned in ``body`` (in source order), and every name it binds."""
        dropped: set[str] = set()
        bound: set[str] = set()

        def assign(name: str, value) -> None:
            bound.add(name)
            if name in dropped or value is None:
                return
            if value is _UNKNOWN or (name in scope and scope[name] != value):
                scope.pop(name, None)
                dropped.add(name)
                return
            scope[name] = value

        for statement in _statements(body):
            if isinstance(statement, ast.Assign):
                value = self.value_type(statement.value, scope, owner)
                for target in statement.targets:
                    if isinstance(target, ast.Name):
                        assign(target.id, value)
                    elif isinstance(target, (ast.Tuple, ast.List)):
                        for element in target.elts:
                            if isinstance(element, ast.Name):
                                assign(element.id, _UNKNOWN)
            elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
                assign(statement.target.id, self.reference(statement.annotation)
                       or self.value_type(statement.value, scope, owner))
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                for item in statement.items:
                    if isinstance(item.optional_vars, ast.Name):
                        context = item.context_expr
                        constructor = self.reference(context.func) if isinstance(context, ast.Call) else None
                        assign(item.optional_vars.id, constructor or _UNKNOWN)
            elif isinstance(statement, (ast.For, ast.AsyncFor)):
                for name in ast.walk(statement.target):
                    if isinstance(name, ast.Name):
                        assign(name.id, _UNKNOWN)
        return scope, bound

    def attributes(self, owner: str) -> dict[str, str]:
        """``self.x`` attributes of a class of this module, computed on first use."""
        if owner not in self._attributes_by_class:
            cls = self.classes.get(owner)
            self._attributes_by_class[owner] = {}  # a cycle through attributes sees none
            if cls is not None:
                self._attributes_by_class[owner] = self._attributes(cls)
        return self._attributes_by_class[owner]

    def _attributes(self, cls: ast.ClassDef) -> dict[str, str]:
        """``self.x`` attributes that every method assigns the same known class."""
        found: dict[str, str] = {}
        dropped: set[str] = set()

        def assign(name: str, value) -> None:
            if name in dropped or value is None:
                return
            if value is _UNKNOWN or (name in found and found[name] != value):
                found.pop(name, None)
                dropped.add(name)
                return
            found[name] = value

        for item in cls.body:
            if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                reference = self.reference(item.annotation)
                if reference is not None:
                    found[item.target.id] = reference
        for method in (item for item in cls.body if isinstance(item, _FUNCTIONS)):
            scope = self.scope(method, None)
            for statement in _statements(method.body):
                targets = statement.targets if isinstance(statement, ast.Assign) else (
                    [statement.target] if isinstance(statement, ast.AnnAssign) else [])
                for target in targets:
                    if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) \
                            and target.value.id == "self":
                        if isinstance(statement, ast.AnnAssign):
                            assign(target.attr, self.reference(statement.annotation)
                                   or self.value_type(statement.value, scope, None))
                        else:
                            assign(target.attr, self.value_type(statement.value, scope, None))
        return found

    # -- resolution ------------------------------------------------------------
    def method_target(self, receiver: ast.AST, method: str, scope: dict[str, str], owner: str | None) -> str | None:
        """``Ref.method`` for a call ``receiver.method(...)`` whose receiver has a known class."""
        value = self.value_type(receiver, scope, owner)
        return f"{value}.{method}" if isinstance(value, str) else None
