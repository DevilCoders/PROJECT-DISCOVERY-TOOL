"""Static accessibility checks for HTML and component-template markup."""
from __future__ import annotations

from collections import defaultdict
from html.parser import HTMLParser
from pathlib import Path

from ...core.limits import AnalyzerLimits
from ...core.source_utils import describe_error, read_text_bounded
from ...models import FileRecord, Finding
from ..base import Analyzer

_MARKUP_EXTENSIONS = {".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte", ".astro"}
_CONTROLS = {"input", "select", "textarea"}


class _AccessibilityParser(HTMLParser):
    def __init__(self, components: bool = False) -> None:
        super().__init__(convert_charrefs=True)
        # JSX, Vue, Svelte and Astro: PascalCase tags are components, not native elements
        # (HTMLParser lowercases names, so <Input> became an unlabelled <input>).
        self.components = components
        self.issues: dict[str, list[int]] = defaultdict(list)
        self.labels: set[str] = set()
        self.controls: list[tuple[int, dict[str, str | None], bool]] = []
        self.stack: list[dict[str, object]] = []

    def _issue(self, code: str) -> None:
        self.issues[code].append(self.getpos()[0])

    def handle_starttag(self, tag: str, attrs_list) -> None:
        if self.components:
            raw = (self.get_starttag_text() or "")[1:].split(None, 1)[0].rstrip("/>")
            if raw[:1].isupper():
                return
        tag = tag.lower()
        attrs = {key.lower(): value for key, value in attrs_list if key}
        if "htmlfor" in attrs and "for" not in attrs:
            attrs["for"] = attrs["htmlfor"]  # JSX spells the label's for attribute htmlFor
        line = self.getpos()[0]
        if tag == "html" and not attrs.get("lang"):
            self._issue("document_language_missing")
        if tag == "img" and "alt" not in attrs:
            self._issue("image_alt_missing")
        if tag == "iframe" and not any(
            attrs.get(key) for key in ("title", "aria-label", "aria-labelledby")
        ):
            self._issue("iframe_title_missing")
        if tag == "label" and attrs.get("for"):
            self.labels.add(str(attrs["for"]))
        if tag in _CONTROLS:
            input_type = str(attrs.get("type") or "").lower()
            if not (tag == "input" and input_type == "hidden"):
                nested_label = any(frame["tag"] == "label" for frame in self.stack)
                self.controls.append((line, attrs, nested_label))
        if tag in {"button", "a", "label"}:
            if tag == "a" and not attrs.get("href"):
                return
            self.stack.append({
                "tag": tag, "attrs": attrs, "line": line, "text": "",
            })
        if tag == "img" and attrs.get("alt"):
            for frame in self.stack:
                frame["text"] = str(frame["text"]) + str(attrs["alt"])

    def handle_startendtag(self, tag: str, attrs) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_data(self, data: str) -> None:
        if data.strip():
            for frame in self.stack:
                frame["text"] = str(frame["text"]) + data.strip()

    def _check_interactive(self, frame: dict[str, object]) -> None:
        tag = str(frame["tag"])
        if tag not in {"button", "a"}:
            return
        attrs = frame["attrs"]
        has_name = (
            bool(attrs.get("aria-label"))
            or bool(attrs.get("aria-labelledby"))
            or bool(attrs.get("title"))
            or bool(str(frame["text"]).strip())
        )
        if not has_name:
            code = "button_name_missing" if tag == "button" else "link_name_missing"
            self.issues[code].append(int(frame["line"]))

    def handle_endtag(self, tag: str) -> None:
        if self.components and tag[:1].isupper():
            return
        tag = tag.lower()
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index]["tag"] == tag:
                self._check_interactive(self.stack[index])
                del self.stack[index:]
                return

    def finish(self) -> dict[str, list[int]]:
        for frame in self.stack:
            self._check_interactive(frame)
        for line, attrs, nested_label in self.controls:
            labelled = (
                nested_label
                or bool(attrs.get("aria-label"))
                or bool(attrs.get("aria-labelledby"))
                or bool(attrs.get("title"))
                or bool(attrs.get("id") and str(attrs["id"]) in self.labels)
            )
            if not labelled:
                self.issues["form_control_label_missing"].append(line)
        return dict(self.issues)


_MAX_MARKUP_BYTES = 16 * 1024 * 1024


class AccessibilityAnalyzer(Analyzer):
    """Find high-signal markup accessibility issues without running frontend code."""

    name = "accessibility-markup"
    limits = AnalyzerLimits(
        _MAX_MARKUP_BYTES,
        "whole",
        outcome="UNKNOWN finding on oversize, growth or read failure",
    )
    domains = ("accessibility",)
    languages = ("HTML", "JavaScript", "TypeScript", "Vue", "Svelte", "Astro")

    def supports(self, record: FileRecord) -> bool:
        return record.error is None and record.extension.lower() in _MARKUP_EXTENSIONS

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            source = read_text_bounded(
                path, _MAX_MARKUP_BYTES,
                expected_identity=record.analysis_identity,
            )
            parser = _AccessibilityParser(components=record.extension.lower() not in {".html", ".htm"})
            parser.feed(source)
            issues = parser.finish()
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            return [Finding(
                "accessibility", f"Markup accessibility scan error: {record.path}",
                describe_error(exc), confidence="UNKNOWN", severity="LOW",
                evidence=[record.path], analyzer=self.name,
            )]

        titles = {
            "document_language_missing": (
                "Document language is not declared",
                "The root html element has no non-empty lang attribute.",
            ),
            "image_alt_missing": (
                "Image has no alt attribute",
                "Provide meaningful alternative text, or an explicit empty alt for decorative imagery.",
            ),
            "iframe_title_missing": (
                "Iframe has no accessible title",
                "Provide a concise title or accessible name describing the embedded content.",
            ),
            "form_control_label_missing": (
                "Form control has no static accessible label",
                "Associate the control with a label element or provide aria-label/aria-labelledby.",
            ),
            "button_name_missing": (
                "Button has no static accessible name",
                "Provide visible text or an accessible name through aria-label/aria-labelledby.",
            ),
            "link_name_missing": (
                "Link has no static accessible name",
                "Provide descriptive link text or an accessible name.",
            ),
        }
        findings = []
        for code, lines in sorted(issues.items()):
            title, detail = titles[code]
            findings.append(Finding(
                "accessibility", f"{title}: {record.path}",
                detail + " Static markup analysis cannot evaluate dynamic rendering, "
                "computed accessible names, CSS visibility or browser accessibility trees.",
                confidence="INFERRED",
                evidence=[f"{record.path}:{line}" for line in sorted(set(lines))[:100]],
                analyzer=self.name,
                severity="MEDIUM",
            ))
        return findings
