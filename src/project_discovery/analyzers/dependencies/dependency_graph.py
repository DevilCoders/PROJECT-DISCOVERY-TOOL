"""The dependency graph a lockfile records, and the path to each package through it.

Lockfile parsers record, where the format states them, the dependencies of each resolved
package (by exact version where the format resolves one, by name otherwise) and the project's
direct dependencies. From these, the shortest path from a direct dependency to a package says
how a vulnerable package entered the project: ``express@4.17.1 > body-parser@1.19.0 >
qs@6.7.0``. When a lockfile does not name the project's direct dependencies, the packages that
nothing else depends on are taken as the starting points.
"""
from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping

Node = tuple[str, str]  # (name, version)
MAX_GRAPH_EDGES = 2_000_000
MAX_PATH_LENGTH = 200


class DependencyGraph:
    """The parent of each package on a shortest path from a direct dependency."""

    def __init__(self, packages: Iterable[Node], edges: Mapping[Node, Iterable[Node]], direct: Iterable[str],
                 *, direct_known: bool, edges_known: bool, truncated: bool = False) -> None:
        self.direct = frozenset(direct)
        self.direct_known = direct_known
        self.edges_known = edges_known
        self.truncated = truncated
        nodes = set(packages)
        by_name: dict[str, list[str]] = {}
        for name, version in sorted(nodes):
            by_name.setdefault(name, []).append(version)
        resolved: dict[Node, list[Node]] = {}
        for parent, children in edges.items():
            targets = resolved.setdefault(parent, [])
            for name, version in children:
                if version and (name, version) in nodes:
                    targets.append((name, version))
                else:
                    # Named without a resolved version (or with one the lockfile lists under
                    # another spelling): every locked version of that name.
                    targets.extend((name, candidate) for candidate in by_name.get(name, ()))
        if direct_known:
            roots = [(name, version) for name in sorted(self.direct) for version in by_name.get(name, ())]
        else:
            depended_on = {child for children in resolved.values() for child in children}
            roots = sorted(node for node in nodes if node not in depended_on)
        self.parents: dict[Node, Node | None] = {}
        queue = deque()
        for root in roots:
            if root not in self.parents:
                self.parents[root] = None
                queue.append(root)
        while queue:
            node = queue.popleft()
            for child in resolved.get(node, ()):
                if child not in self.parents:
                    self.parents[child] = node
                    queue.append(child)

    def is_direct(self, name: str) -> bool | None:
        """Whether the project depends on a package directly; None when the lockfile does not say."""
        return name in self.direct if self.direct_known else None

    def path(self, name: str, version: str) -> list[Node] | None:
        """The packages from a direct dependency (or a package nothing depends on) down to this
        one, both included; None when the graph does not reach it."""
        node: Node | None = (name, version)
        if node not in self.parents:
            return None
        chain: list[Node] = []
        while node is not None and len(chain) < MAX_PATH_LENGTH:
            chain.append(node)
            node = self.parents[node]
        return chain[::-1]

    def describe(self, name: str, version: str) -> list[str]:
        """Evidence lines for a package: whether it is direct, and its dependency path."""
        if not self.edges_known and not self.direct_known:
            return []
        direct = self.is_direct(name)
        path = self.path(name, version) if self.edges_known else None
        lines = []
        if direct:
            lines.append("dependency: direct")
        elif path is not None and len(path) > 1:
            lines.append(f"dependency: transitive, {len(path) - 1} level(s) below {path[0][0]}@{path[0][1]}")
        elif path is not None:
            lines.append("dependency: top level (no other locked package depends on it)")
        elif direct is False:
            lines.append("dependency: transitive" + ("" if self.edges_known else " (the lockfile records no parents)"))
        if path is not None and len(path) > 1:
            lines.append("dependency_path: " + " > ".join(f"{item}@{release}" for item, release in path))
        elif self.edges_known and path is None and not direct:
            lines.append("dependency_path: not reached from a direct dependency in the lockfile's graph"
                         + (" (the graph was truncated)" if self.truncated else ""))
        return lines
