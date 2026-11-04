"""Hardened parsers for untrusted YAML and XML found in analyzed repositories.

A repository under analysis is attacker-controlled input. YAML anchors/aliases can encode
an exponentially large document in a few hundred bytes ("billion laughs"), and XML entity
declarations can do the same. These helpers bound the *expanded* size before any analyzer
traverses the data, and they never resolve external resources.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any
from xml.parsers import expat

MAX_YAML_EXPANDED_NODES = 2_000_000
MAX_YAML_DOCUMENTS = 10_000


class UnsafeDocumentError(ValueError):
    """Raised when a document exceeds an expansion budget or uses forbidden constructs."""


def _check_expansion(root: Any, budget: int) -> int:
    """Return the fully expanded node count of a composed YAML graph, bounded by budget.

    Aliases point at the same node object, so sizes are memoized by identity; a node
    reached again while still on the traversal stack is a recursive alias.
    """
    from yaml.nodes import MappingNode, SequenceNode

    sizes: dict[int, int] = {}
    active: set[int] = set()
    stack: list[tuple[Any, bool]] = [(root, False)]
    while stack:
        node, expanded = stack.pop()
        key = id(node)
        if expanded:
            active.discard(key)
            if isinstance(node, SequenceNode):
                children = node.value
            elif isinstance(node, MappingNode):
                children = [part for pair in node.value for part in pair]
            else:
                children = ()
            total = 1 + sum(sizes[id(child)] for child in children)
            if total > budget:
                raise UnsafeDocumentError(
                    f"YAML alias expansion exceeds the {budget:,}-node budget"
                )
            sizes[key] = total
            continue
        if key in sizes:
            continue
        if key in active:
            raise UnsafeDocumentError("YAML document contains a recursive alias")
        active.add(key)
        stack.append((node, True))
        if isinstance(node, SequenceNode):
            stack.extend((child, False) for child in node.value if id(child) not in sizes)
        elif isinstance(node, MappingNode):
            stack.extend(
                (part, False) for pair in node.value for part in pair if id(part) not in sizes
            )
    return sizes[id(root)]


def safe_yaml_load_all(
    text: str,
    *,
    allow_unknown_tags: bool = False,
    max_expanded_nodes: int = MAX_YAML_EXPANDED_NODES,
) -> list[Any]:
    """Load every YAML document with SafeLoader semantics under an expansion budget.

    allow_unknown_tags constructs plain scalars/lists/maps for custom tags such as
    CloudFormation's ``!Ref``; otherwise unknown tags raise like ``yaml.safe_load``.
    Raises UnsafeDocumentError, or ValueError wrapping a yaml.YAMLError.
    """
    import yaml
    from yaml.nodes import MappingNode, ScalarNode, SequenceNode

    class Loader(yaml.SafeLoader):
        pass

    if allow_unknown_tags:
        def unknown_tag(loader, _suffix, node):
            if isinstance(node, ScalarNode):
                return loader.construct_scalar(node)
            if isinstance(node, SequenceNode):
                return loader.construct_sequence(node)
            if isinstance(node, MappingNode):
                return loader.construct_mapping(node)
            return None
        Loader.add_multi_constructor("!", unknown_tag)

    loader = Loader(text)
    documents: list[Any] = []
    remaining = max_expanded_nodes
    try:
        while loader.check_node():
            if len(documents) >= MAX_YAML_DOCUMENTS:
                raise UnsafeDocumentError(
                    f"YAML stream exceeds the {MAX_YAML_DOCUMENTS:,}-document budget"
                )
            node = loader.get_node()
            if node is None:
                continue
            remaining -= _check_expansion(node, remaining)
            documents.append(loader.construct_document(node))
    except RecursionError as exc:
        raise UnsafeDocumentError("YAML nesting exceeds the parser recursion budget") from exc
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML: {exc}") from exc
    finally:
        loader.dispose()
    return documents


def safe_yaml_load(text: str, **options: Any) -> Any:
    """Load a single YAML document (the first one) like ``yaml.safe_load``."""
    documents = safe_yaml_load_all(text, **options)
    return documents[0] if documents else None


def _forbid_entities(content: str | bytes) -> None:
    parser = expat.ParserCreate()

    def forbid(*_args: Any) -> None:
        raise UnsafeDocumentError("XML entity declarations are not expanded by PDT")

    parser.EntityDeclHandler = forbid
    parser.UnparsedEntityDeclHandler = forbid
    parser.ExternalEntityRefHandler = lambda *_args: forbid()
    try:
        parser.Parse(content, True)
    except expat.ExpatError as exc:
        raise ET.ParseError(str(exc)) from exc


def safe_xml_fromstring(content: str | bytes) -> ET.Element:
    """Parse XML after rejecting DTD entity declarations (billion laughs, XXE).

    Raises UnsafeDocumentError for entity declarations and ET.ParseError when malformed.
    Detection runs inside expat, so alternate encodings such as UTF-16 cannot hide it.
    """
    _forbid_entities(content)
    return ET.fromstring(content)
