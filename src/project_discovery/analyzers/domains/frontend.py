"""Frontend applications: components, routes, state libraries and bundler configuration.

Components are read through the shared code model. React function components (PascalCase
functions that render JSX or call hooks), class components and ``memo``/``forwardRef``
wrappers record the components they render (JSX tags), their props and their hooks.
Vue single-file components, Svelte components and Angular ``@Component`` classes record
template children and selectors. The code index joins children across files into the
component graph (roots, reuse, unused components).

Routes come from React Router (``<Route path>`` and route objects), Vue Router, Angular
``Routes`` and file-system routing (Next.js pages and app routers, Nuxt, SvelteKit,
Remix, Astro). Imports name the framework, state, data-fetching, routing, UI, styling,
form and testing libraries. Bundler and framework configuration (webpack, Vite, Next.js,
Angular, SvelteKit, Nuxt, Rollup, esbuild, Parcel, Turborepo, Nx) is summarized.

Findings: React hooks called conditionally, in loops, in callbacks or after an early
return (rules of hooks), list items rendered without ``key``, effects without a
dependency array, and build configurations that ignore type or lint errors.
"""
from __future__ import annotations

import bisect
import json
import re
from collections import Counter
from pathlib import Path, PurePosixPath

from ...core.limits import AnalyzerLimits, over_limit
from ...core.source_utils import SourceBudgetExceeded, read_text_bounded
from ...intelligence import facts as code_facts
from ...intelligence.model import FUNCTION_KINDS, FileModel, model_for
from ...models import FileRecord, Finding
from ..base import Analyzer, oversize_finding
from ..code.findings import code_finding

_MAX_CONFIG_BYTES = 2 * 1024 * 1024
_SCRIPT_LANGUAGES = frozenset({"JavaScript", "TypeScript", "Vue", "Svelte"})
_PASCAL = re.compile(r"^[A-Z][A-Za-z0-9_$]*+$")
_HOOK_NAME = re.compile(r"^use[A-Z0-9][\w$]*+$")
_HOOK_CALL = re.compile(r"(?<![\w$.])(use[A-Z][\w$]*+)[ \t]*+(?:<[^<>()\n]{0,120}+>)?[ \t]*+\(")
_JSX_TAG = re.compile(r"(?<![\w$.)\]])<([A-Z][\w$]*+(?:\.[A-Z][\w$]*+)?)(?=[\s/>])")
_JSX_PRESENT = re.compile(r"(?<![\w$.)\]])<(?:[A-Za-z][\w$.-]*+|>)")
_CLASS_COMPONENT = re.compile(r"extends[ \t]++(?:React\.)?(?:Pure)?Component\b")
_WRAPPED_COMPONENT = re.compile(
    r"(?<![\w$.])(?:export[ \t]++)?(?:const|let|var)[ \t]++([A-Z][\w$]*+)(?:[ \t]*+:[^=\n]{1,200}+)?[ \t]*+=[ \t]*+"
    r"(?:React\.)?(?:memo|forwardRef|observer|lazy)[ \t]*+(?:<[^<>\n]{0,200}+>)?\("
)
_PROPS_ACCESS = re.compile(r"(?<![\w$.])props\.([A-Za-z_$][\w$]*+)")
_BUILTIN_HOOKS = frozenset({
    "useState", "useEffect", "useContext", "useReducer", "useCallback", "useMemo", "useRef", "useLayoutEffect",
    "useImperativeHandle", "useDebugValue", "useDeferredValue", "useTransition", "useId", "useSyncExternalStore",
    "useInsertionEffect", "useOptimistic", "useActionState", "useFormStatus", "use",
})
_MAP_CALL = re.compile(r"\.(?:map|flatMap)[ \t]*+\(")
_EFFECT_CALL = re.compile(r"(?<![\w$.])(?:React\.)?(?:useEffect|useLayoutEffect)[ \t]*+\(")
_CONTROL_BEFORE = re.compile(r"(?<![\w$])(if|for|while|switch|catch|with)[ \t]*+$")
_FLOW_KEYWORD = re.compile(r"(?<![\w$])(else|do|try|finally)[ \t\r\n]*+$")
_EXPRESSION_BEFORE = re.compile(r"(?:[=(,:?\[{]|&&|\|\||\?\?|(?<![\w$])return)[ \t\r\n]*+$")
_IF = re.compile(r"(?<![\w$.])if[ \t]*+\(")
_RETURN = re.compile(r"(?<![\w$.])return\b")
_STRING_AT = re.compile(r"[ \t\r\n]*+([\"'`])((?:(?!\1)[^\\\n]|\\.){0,300}+)\1")
_PATH_KEY = re.compile(r"(?<![\w$.])path[ \t]*+:")
_ROUTE_ELEMENT = re.compile(r"<Route\b[^>]{0,600}?\bpath[ \t]*+=[ \t]*+[\"']([^\"'\n]{0,200}+)[\"']")
_ROUTER_FACTORY = re.compile(
    r"(?<![\w$.])(?:createBrowserRouter|createHashRouter|createMemoryRouter|useRoutes|createRouter|new[ \t]++VueRouter|"
    r"RouterModule\.for(?:Root|Child)|provideRouter|createRootRoute|createRoute)[ \t]*+\("
)
_ANGULAR_COMPONENT = re.compile(r"@Component[ \t]*+\([ \t\r\n]*+\{")
_ANGULAR_ROUTES = re.compile(r":[ \t]*+Routes[ \t]*+=[ \t]*+\[")
_EXPORT_CLASS = re.compile(r"(?<![\w$])export[ \t]++(?:default[ \t]++)?(?:abstract[ \t]++)?class[ \t]++([A-Za-z_$][\w$]*+)")
_TEMPLATE_BLOCK = re.compile(r"(?is)<template\b[^>]{0,200}+>(.*)</template>")
_TEMPLATE_TAG = re.compile(r"<([A-Z][\w]*+(?:\.[A-Z]\w*+)?|[a-z][a-z0-9]*+(?:-[a-z0-9]++)++)(?=[\s/>])")
_SVELTE_PROP = re.compile(r"(?<![\w$.])export[ \t]++let[ \t]++([A-Za-z_$][\w$]*+)")
_SVELTE_RUNE_PROPS = re.compile(r"let[ \t]*+\{([^{}]{0,600}+)\}[ \t]*+=[ \t]*+\$props[ \t]*+\(")
_VUE_BUILTINS = frozenset({"transition", "transition-group", "keep-alive", "component", "slot", "teleport", "suspense",
                           "router-view", "router-link", "template", "client-only", "nuxt-link", "nuxt-page",
                           "nuxt-layout"})
_LIBRARIES: dict[str, tuple[str, str]] = {
    "react": ("framework", "React"), "react-dom": ("framework", "React"), "next": ("framework", "Next.js"),
    "vue": ("framework", "Vue"), "nuxt": ("framework", "Nuxt"), "#app": ("framework", "Nuxt"),
    "#imports": ("framework", "Nuxt"), "svelte": ("framework", "Svelte"), "@sveltejs/kit": ("framework", "SvelteKit"),
    "$app": ("framework", "SvelteKit"), "@angular/core": ("framework", "Angular"), "solid-js": ("framework", "Solid"),
    "preact": ("framework", "Preact"), "@remix-run/react": ("framework", "Remix"), "astro": ("framework", "Astro"),
    "lit": ("framework", "Lit"), "@builder.io/qwik": ("framework", "Qwik"), "react-native": ("framework", "React Native"),
    "redux": ("state", "Redux"), "@reduxjs/toolkit": ("state", "Redux Toolkit"), "react-redux": ("state", "Redux"),
    "zustand": ("state", "Zustand"), "mobx": ("state", "MobX"), "mobx-react": ("state", "MobX"),
    "mobx-react-lite": ("state", "MobX"), "recoil": ("state", "Recoil"), "jotai": ("state", "Jotai"),
    "valtio": ("state", "Valtio"), "pinia": ("state", "Pinia"), "vuex": ("state", "Vuex"),
    "@ngrx/store": ("state", "NgRx"), "xstate": ("state", "XState"), "effector": ("state", "Effector"),
    "nanostores": ("state", "Nano Stores"), "svelte/store": ("state", "Svelte stores"),
    "@tanstack/react-query": ("data", "TanStack Query"), "react-query": ("data", "React Query"),
    "@tanstack/vue-query": ("data", "TanStack Query"), "swr": ("data", "SWR"), "@apollo/client": ("data", "Apollo Client"),
    "urql": ("data", "urql"), "@trpc/client": ("data", "tRPC"), "@trpc/react-query": ("data", "tRPC"),
    "axios": ("data", "axios"), "graphql-request": ("data", "graphql-request"), "relay-runtime": ("data", "Relay"),
    "react-router": ("routing", "React Router"), "react-router-dom": ("routing", "React Router"),
    "vue-router": ("routing", "Vue Router"), "@angular/router": ("routing", "Angular Router"),
    "@tanstack/react-router": ("routing", "TanStack Router"), "wouter": ("routing", "wouter"),
    "@mui/material": ("ui", "MUI"), "antd": ("ui", "Ant Design"), "@chakra-ui/react": ("ui", "Chakra UI"),
    "@mantine/core": ("ui", "Mantine"), "react-bootstrap": ("ui", "React Bootstrap"), "vuetify": ("ui", "Vuetify"),
    "element-plus": ("ui", "Element Plus"), "@headlessui/react": ("ui", "Headless UI"), "primevue": ("ui", "PrimeVue"),
    "quasar": ("ui", "Quasar"), "@angular/material": ("ui", "Angular Material"), "@shadcn/ui": ("ui", "shadcn/ui"),
    "styled-components": ("styling", "styled-components"), "@emotion/react": ("styling", "Emotion"),
    "@emotion/styled": ("styling", "Emotion"), "@vanilla-extract/css": ("styling", "vanilla-extract"),
    "react-hook-form": ("forms", "React Hook Form"), "formik": ("forms", "Formik"), "zod": ("validation", "Zod"),
    "yup": ("validation", "Yup"), "@testing-library/react": ("testing", "Testing Library"),
    "@testing-library/vue": ("testing", "Testing Library"), "cypress": ("testing", "Cypress"),
    "@playwright/test": ("testing", "Playwright"), "vitest": ("testing", "Vitest"), "enzyme": ("testing", "Enzyme"),
    "@storybook/react": ("tooling", "Storybook"), "i18next": ("i18n", "i18next"), "react-i18next": ("i18n", "i18next"),
    "vue-i18n": ("i18n", "vue-i18n"),
}
_CONFIGS = (
    (re.compile(r"^webpack(?:\.[\w-]{1,40}+)?\.config\.[cm]?[jt]s$"), "webpack"),
    (re.compile(r"^rspack\.config\.[cm]?[jt]s$"), "Rspack"),
    (re.compile(r"^vite\.config\.[cm]?[jt]s$"), "Vite"), (re.compile(r"^vitest\.config\.[cm]?[jt]s$"), "Vitest"),
    (re.compile(r"^rollup\.config\.[cm]?[jt]s$"), "Rollup"), (re.compile(r"^esbuild\.config\.[cm]?[jt]s$"), "esbuild"),
    (re.compile(r"^next\.config\.[cm]?[jt]s$"), "Next.js"), (re.compile(r"^nuxt\.config\.[cm]?[jt]s$"), "Nuxt"),
    (re.compile(r"^svelte\.config\.[cm]?[jt]s$"), "SvelteKit"), (re.compile(r"^astro\.config\.[cm]?[jt]s$"), "Astro"),
    (re.compile(r"^remix\.config\.[cm]?[jt]s$"), "Remix"), (re.compile(r"^gatsby-config\.[cm]?[jt]s$"), "Gatsby"),
    (re.compile(r"^vue\.config\.[cm]?[jt]s$"), "Vue CLI"), (re.compile(r"^angular\.json$"), "Angular"),
    (re.compile(r"^\.parcelrc$"), "Parcel"), (re.compile(r"^turbo\.json$"), "Turborepo"), (re.compile(r"^nx\.json$"), "Nx"),
    (re.compile(r"^tailwind\.config\.[cm]?[jt]s$"), "Tailwind CSS"),
    (re.compile(r"^(?:babel\.config\.[cm]?[jt]s(?:on)?|\.babelrc(?:\.json)?)$"), "Babel"),
    (re.compile(r"^postcss\.config\.[cm]?[jt]s$"), "PostCSS"),
)
_VITE_PLUGINS = re.compile(r"(?<![\w$.])(react|vue|svelte|sveltekit|solid|preact|qwikVite|vueJsx|reactRefresh|"
                           r"legacy|VitePWA|nodePolyfills|checker|tsconfigPaths|remix|tanstackRouter)[ \t]*+\(")
_LOADER = re.compile(r"[\"']([\w@/.-]{1,60}+-loader)[\"']")
_ADAPTER = re.compile(r"[\"'](@sveltejs/adapter-[\w-]{1,40}+)[\"']")


_ARROW_DECLARATION = re.compile(
    r"(?:const|let|var)[ \t]++([A-Za-z_$][\w$]*+)(?:[ \t]*+:[^=\n]{1,200}+)?[ \t]*+=[ \t]*+(?:async[ \t]++)?"
    r"(?:\([^()]{0,400}+\)|[A-Za-z_$][\w$]*+)(?:[ \t]*+:[^=\n]{1,120}+)?[ \t]*+=>[ \t\r\n]*+$"
)
_FUNCTION_KEYWORD = re.compile(r"function\*?[ \t]*+([A-Za-z_$][\w$]*+)?[ \t]*+$")


class _Blocks:
    """Brace structure of a file: which code block encloses an offset."""

    def __init__(self, model: FileModel) -> None:
        self.model = model
        self.opens = sorted(model.braces)
        self.closes = {close: opening for opening, close in model.parens.items()}

    def context(self, offset: int, body_open: int) -> str:
        """'top' directly in the body at ``body_open`` (expression braces aside), 'nested' inside a
        condition, loop or callback, 'other' inside a nested component or hook definition."""
        index = bisect.bisect_left(self.opens, offset) - 1
        steps = 0
        while index >= 0 and steps < 256:
            opening = self.opens[index]
            index -= 1
            steps += 1
            if opening < body_open:
                break
            if self.model.braces.get(opening, -1) < offset:
                continue
            if opening == body_open:
                return "top"
            kind = self.kind(opening)
            if kind != "expression":
                return kind
        return "top"

    def kind(self, opening: int) -> str:
        clean = self.model.clean
        before = clean[max(0, opening - 160):opening].rstrip()
        if before.endswith("=>"):
            declared = _ARROW_DECLARATION.search(clean[max(0, opening - 600):opening])
            if declared and (_PASCAL.match(declared.group(1)) or _HOOK_NAME.match(declared.group(1))):
                return "other"
            return "nested"
        if before.endswith(")"):
            close = clean.rfind(")", 0, opening)
            start = self.closes.get(close)
            if start is None:
                return "nested"
            prefix = clean[max(0, start - 80):start]
            if _CONTROL_BEFORE.search(prefix):
                return "nested"
            function = _FUNCTION_KEYWORD.search(prefix)
            if function and function.group(1) and (_PASCAL.match(function.group(1)) or _HOOK_NAME.match(function.group(1))):
                return "other"
            return "nested"
        if _FLOW_KEYWORD.search(before):
            return "nested"
        if not before or _EXPRESSION_BEFORE.search(before) or before.endswith(">"):
            return "expression"
        return "nested"


def _config_kind(record: FileRecord) -> str | None:
    name = PurePosixPath(record.path.replace("\\", "/")).name
    return next((label for pattern, label in _CONFIGS if pattern.match(name)), None)


def _route_from_path(posix: str) -> tuple[str, str] | None:
    """(framework, URL path) for file-system routed pages."""
    parts = posix.split("/")
    name = parts[-1]
    stem, _, extension = name.rpartition(".")
    if not stem:
        return None

    def url(segments: list[str]) -> str:
        converted = []
        for segment in segments:
            if not segment or (segment.startswith("(") and segment.endswith(")")) or segment.startswith("@"):
                continue  # route groups and parallel slots do not appear in URLs
            segment = re.sub(r"^\[\[?\.\.\.(\w{1,60}+)\]?\]$", r"*\1", segment)
            segment = re.sub(r"^\[(\w{1,60}+)\]$", r":\1", segment)
            segment = re.sub(r"^\$(\w{1,60}+)$", r":\1", segment)
            converted.append(segment)
        return "/" + "/".join(converted)

    for index, part in enumerate(parts[:-1]):
        rest = parts[index + 1:-1]
        if part == "pages" and extension in {"js", "jsx", "ts", "tsx", "vue", "astro", "md", "mdx"} and (
            index == 0 or parts[index - 1] in {"src", "app"} or index <= 2
        ):
            if stem.startswith("_") or stem in {"404", "500"} and extension != "vue":
                return None
            framework = "Nuxt" if extension == "vue" else "Astro" if extension in {"astro", "md", "mdx"} else "Next.js"
            prefix = "/api" if rest[:1] == ["api"] and framework == "Next.js" else ""
            segments = rest[1:] if prefix else rest
            leaf = [] if stem == "index" else [stem]
            return framework, prefix + url(segments + leaf) if prefix else url(segments + leaf)
        if part == "app" and stem in {"page", "route"} and extension in {"js", "jsx", "ts", "tsx", "mdx"}:
            return ("Next.js" if stem == "page" else "Next.js API"), url(rest)
        if part == "routes" and index >= 1 and parts[index - 1] == "src" and stem.startswith("+") and stem in {
            "+page", "+server", "+layout"
        }:
            return ("SvelteKit" if stem != "+server" else "SvelteKit API"), url(rest)
        if part == "routes" and index >= 1 and parts[index - 1] == "app" and extension in {"tsx", "jsx", "ts", "js"}:
            segments = [segment for segment in stem.split(".") if segment != "_index"]
            return "Remix", url([segment for segment in segments if not segment.startswith("_")])
    return None


class FrontendAnalyzer(Analyzer):
    name = "frontend"
    limits = AnalyzerLimits(
        _MAX_CONFIG_BYTES,
        "whole",
        outcome="UNKNOWN finding for a file past the budget",
    )
    version = "1.0.0"
    description = ("Frontend components (React, Vue, Svelte, Angular), component children, hooks, routes, libraries "
                   "and bundler configuration.")
    domains = ("frontend",)
    languages = (*sorted(_SCRIPT_LANGUAGES), "Astro")

    def supports(self, record: FileRecord) -> bool:
        if record.error or record.content_skipped_reason:
            return False
        if record.language in _SCRIPT_LANGUAGES or _config_kind(record):
            return True
        lower = record.path.lower()
        return lower.endswith(".component.html") or (record.language == "Astro")

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        posix = record.path.replace("\\", "/")
        route = _route_from_path(posix)
        if route:
            code_facts.emit_fact("route_file", route[1], framework=route[0])
        kind = _config_kind(record)
        if kind:
            return self._config(path, record, kind)
        if record.language not in _SCRIPT_LANGUAGES:
            return self._template_file(path, record)
        model = model_for(path, record)
        if model is None:
            return []
        self._libraries(model)
        findings: list[Finding] = []
        if record.language == "Vue":
            findings += self._vue(model, posix)
        elif record.language == "Svelte":
            findings += self._svelte(model, posix)
        else:
            findings += self._react(model)
            findings += self._angular(model)
        findings += self._routes(model)
        return findings

    # -- libraries -------------------------------------------------------------------
    @staticmethod
    def _libraries(model: FileModel) -> None:
        seen = set()
        for item in model.imports:
            target = item.target
            package = target if target in _LIBRARIES else "/".join(target.split("/")[:2]) if target.startswith("@") else target.split("/")[0]
            entry = _LIBRARIES.get(target) or _LIBRARIES.get(package)
            if entry and entry[1] not in seen:
                seen.add(entry[1])
                code_facts.emit_fact("frontend_library", entry[1], kind=entry[0])

    # -- React -----------------------------------------------------------------------------
    def _react(self, model: FileModel) -> list[Finding]:
        clean = model.clean
        if not (_JSX_PRESENT.search(clean) or "use" in clean):
            return []
        functions = [symbol for symbol in model.symbols if symbol.body and (
            symbol.kind in FUNCTION_KINDS or symbol.kind == "class")]
        wrapped = {match.group(1): match for match in _WRAPPED_COMPONENT.finditer(clean)}
        components = []
        hooks_violations: list[int] = []
        early_return: list[int] = []
        blocks = _Blocks(model)
        for symbol in functions:
            start, end = symbol.body
            body = clean[start:end]
            name = symbol.name
            is_class = symbol.kind == "class"
            if is_class:
                header = clean[model.line_start(symbol.line):start]
                if not _CLASS_COMPONENT.search(header):
                    continue
            elif symbol.kind == "method" or not (_PASCAL.match(name) or _HOOK_NAME.match(name)):
                continue
            hook_calls = list(_HOOK_CALL.finditer(clean, start, end))
            renders = bool(_JSX_PRESENT.search(body))
            if not is_class and _PASCAL.match(name) and not (renders or hook_calls):
                continue
            children = Counter(tag.group(1) for tag in _JSX_TAG.finditer(clean, start, end))
            props = self._props(model, symbol, body)
            if _PASCAL.match(name) or is_class:
                components.append((name, symbol.line, children, props, sorted({call.group(1) for call in hook_calls})))
            if is_class:
                hook_calls = []  # hooks cannot be used in class components; nothing to place
            for call in hook_calls:
                verdict = blocks.context(call.start(), start)
                if verdict == "nested":
                    hooks_violations.append(model.line_of(call.start()))
                elif verdict == "top" and self._after_early_return(model, blocks, start, call.start()):
                    early_return.append(model.line_of(call.start()))
        for name, match in wrapped.items():
            if any(component[0] == name for component in components):
                continue
            close = model.parens.get(match.end() - 1)
            if close is None:
                continue
            children = Counter(tag.group(1) for tag in _JSX_TAG.finditer(clean, match.end(), close))
            components.append((name, model.line_of(match.start()), children, [], []))
        for name, line, children, props, hooks in components:
            code_facts.emit_fact("component", name, framework="React", line=line, props=props[:20], hooks=hooks[:20])
            for child, count in sorted(children.items())[:200]:
                code_facts.emit_fact("component_child", child, parent=name, count=count)
        for symbol in functions:
            if symbol.kind in FUNCTION_KINDS and _HOOK_NAME.match(symbol.name):
                code_facts.emit_fact("custom_hook", symbol.name, line=symbol.line)
        findings = []
        if components:
            described = "; ".join(
                f"{name}" + (f" (renders {', '.join(sorted(children)[:6])})" if children else "")
                for name, _, children, _, _ in components[:15]
            )
            findings.append(code_finding(model, "frontend", "React components",
                                         f"{len(components)} component(s): {described}.",
                                         [line for _, line, *_ in components], analyzer=self.name, severity="INFO"))
        if hooks_violations or early_return:
            lines = sorted(set(hooks_violations + early_return))
            findings.append(code_finding(
                model, "frontend", "React hook called conditionally",
                "Hooks must run in the same order on every render; calling one inside a condition, loop, nested "
                "function or after an early return makes React mix up component state between renders.",
                lines, analyzer=self.name, severity="MEDIUM",
                recommendation="Call hooks unconditionally at the top level of the component or custom hook.",
            ))
        missing_keys = self._missing_keys(model)
        if missing_keys:
            findings.append(code_finding(
                model, "frontend", "List items rendered without a key",
                "Elements returned from .map() need a stable key; without one React re-creates or mismatches items "
                "(lost input state, wrong animations) when the list changes.", missing_keys, analyzer=self.name,
                recommendation="Add key={item.id} (a stable identifier, not the array index) to the mapped element.",
            ))
        effects = self._effects_without_dependencies(model)
        if effects:
            findings.append(code_finding(
                model, "frontend", "Effect without a dependency array",
                "useEffect without a second argument runs after every render, which repeats subscriptions, requests "
                "or state updates (and can loop).", effects, analyzer=self.name, severity="INFO",
                recommendation="Pass the dependency array the effect needs ([] to run once).",
            ))
        return findings

    @staticmethod
    def _props(model: FileModel, symbol, body: str) -> list[str]:
        start = model.line_start(symbol.line)
        signature = model.clean[start:symbol.body[0]]
        destructured = re.search(r"\([ \t\r\n]*+\{([^{}]{0,800}+)\}", signature)
        names = []
        if destructured:
            for part in destructured.group(1).split(","):
                part = part.strip().lstrip(".").split(":", 1)[0].split("=", 1)[0].strip()
                if re.fullmatch(r"[A-Za-z_$][\w$]*+", part):
                    names.append(part)
        names += [name for name in _PROPS_ACCESS.findall(body) if name not in names]
        return names

    @staticmethod
    def _after_early_return(model: FileModel, blocks: "_Blocks", body_open: int, offset: int) -> bool:
        """Whether an ``if (...) return`` directly in the body precedes ``offset``."""
        clean = model.clean
        for match in _IF.finditer(clean, body_open + 1, offset):
            if blocks.context(match.start(), body_open) != "top":
                continue
            close = model.parens.get(match.end() - 1)
            if close is None or close > offset:
                continue
            position = close + 1
            while position < offset and clean[position] in " \t\r\n":
                position += 1
            if clean.startswith("{", position):
                block_end = model.braces.get(position)
                if block_end is not None and block_end < offset and _RETURN.search(clean, position, block_end):
                    return True
            elif _RETURN.match(clean, position):
                return True
        return False

    @staticmethod
    def _missing_keys(model: FileModel) -> list[int]:
        clean, lines = model.clean, []
        for match in _MAP_CALL.finditer(clean):
            close = model.parens.get(match.end() - 1)
            if close is None:
                continue
            arrow = clean.find("=>", match.end(), close)
            if arrow == -1:
                continue
            position = arrow + 2
            while position < close and clean[position] in " \t\r\n(":
                position += 1
            if clean.startswith("{", position):
                block_end = model.braces.get(position, close)
                returned = _RETURN.search(clean, position, block_end)
                if not returned:
                    continue
                position = returned.end()
                while position < close and clean[position] in " \t\r\n(":
                    position += 1
            if not clean.startswith("<", position) or clean.startswith(("<>", "</"), position):
                continue
            depth, cursor, limit = 0, position + 1, min(close, position + 2000)
            while cursor < limit:
                char = clean[cursor]
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                elif char == ">" and depth == 0:
                    break
                cursor += 1
            attributes = clean[position:cursor]
            if not re.match(r"<[A-Za-z]", attributes):
                continue
            if not re.search(r"(?<![\w$.-])key[ \t]*+=", attributes) and "{...{" not in attributes:
                lines.append(model.line_of(position))
        return lines

    @staticmethod
    def _effects_without_dependencies(model: FileModel) -> list[int]:
        clean, lines = model.clean, []
        for match in _EFFECT_CALL.finditer(clean):
            close = model.parens.get(match.end() - 1)
            if close is None:
                continue
            depth = 0
            for char in clean[match.end():close]:
                if char in "([{":
                    depth += 1
                elif char in ")]}":
                    depth -= 1
                elif char == "," and depth == 0:
                    break
            else:
                lines.append(model.line_of(match.start()))
        return lines

    # -- Angular ---------------------------------------------------------------------------
    def _angular(self, model: FileModel) -> list[Finding]:
        clean, text = model.clean, model.text
        components = []
        for decorator in _ANGULAR_COMPONENT.finditer(clean):
            close = model.braces.get(decorator.end() - 1)
            if close is None:
                continue
            selector = self._property_string(model, "selector", decorator.end(), close)
            template_url = self._property_string(model, "templateUrl", decorator.end(), close)
            declared = _EXPORT_CLASS.search(clean, close)
            name = declared.group(1) if declared else "?"
            inline = re.search(r"(?<![\w$])template[ \t]*+:", clean[decorator.end():close])
            children = Counter()
            if inline:
                literal = _STRING_AT.match(text, decorator.end() + inline.end())
                if literal:
                    children.update(tag for tag in _TEMPLATE_TAG.findall(literal.group(2)) if "-" in tag)
            components.append((name, model.line_of(decorator.start()), selector, template_url, children))
            code_facts.emit_fact("component", name, framework="Angular", selector=selector, line=model.line_of(decorator.start()))
            for child, count in children.items():
                code_facts.emit_fact("component_child", child, parent=name, count=count, selector=1)
        if not components:
            return []
        return [code_finding(
            model, "frontend", "Angular components",
            f"{len(components)} component(s): " + "; ".join(
                f"{name}" + (f" <{selector}>" if selector else "") + (f" template {template}" if template else "")
                for name, _, selector, template, _ in components[:12]) + ".",
            [line for _, line, *_ in components], analyzer=self.name, severity="INFO",
        )]

    @staticmethod
    def _property_string(model: FileModel, key: str, start: int, end: int) -> str:
        match = re.search(rf"(?<![\w$]){key}[ \t]*+:", model.clean[start:end])
        if not match:
            return ""
        literal = _STRING_AT.match(model.text, start + match.end())
        return literal.group(2) if literal else ""

    def _template_file(self, path: Path, record: FileRecord) -> list[Finding]:
        if over_limit(record.size_bytes, _MAX_CONFIG_BYTES):
            return [oversize_finding(self, record, "frontend", "Frontend template", _MAX_CONFIG_BYTES)]
        try:
            text = read_text_bounded(path, _MAX_CONFIG_BYTES, errors="replace", expected_identity=record.analysis_identity)
        except (OSError, SourceBudgetExceeded):
            return []
        tags = Counter(tag for tag in _TEMPLATE_TAG.findall(text) if "-" in tag or _PASCAL.match(tag))
        owner = PurePosixPath(record.path.replace("\\", "/")).name.split(".")[0]
        for tag, count in tags.items():
            code_facts.emit_fact("component_child", tag, parent=f"template:{owner}", count=count, selector=1)
        return []

    # -- Vue and Svelte --------------------------------------------------------------------
    def _single_file(self, model: FileModel, posix: str, framework: str, props: list[str]) -> list[Finding]:
        text = model.text
        template = _TEMPLATE_BLOCK.search(text) if framework == "Vue" else None
        markup = template.group(1) if template else re.sub(r"(?is)<(script|style)\b.*?</\1>", "", text) if framework == "Svelte" else ""
        name = PurePosixPath(posix).stem
        if name.startswith("+") or name in {"index", "page"}:
            # Route files (SvelteKit +page, Nuxt index) are named after their directory.
            name = f"{PurePosixPath(posix).parent.name or 'root'}/{name}"
        children = Counter()
        for tag in _TEMPLATE_TAG.findall(markup):
            if tag in _VUE_BUILTINS:
                continue
            if "-" in tag:
                tag = "".join(part.capitalize() for part in tag.split("-"))
            elif not _PASCAL.match(tag.split(".")[0]):
                continue
            children[tag] += 1
        code_facts.emit_fact("component", name, framework=framework, line=1, props=props[:20])
        for child, count in sorted(children.items())[:200]:
            code_facts.emit_fact("component_child", child, parent=name, count=count)
        return [code_finding(
            model, "frontend", f"{framework} component",
            f"{name}" + (f" with props {', '.join(props[:12])}" if props else "")
            + (f"; renders {', '.join(sorted(children)[:12])}" if children else "") + ".",
            [1], analyzer=self.name, severity="INFO",
        )]

    def _vue(self, model: FileModel, posix: str) -> list[Finding]:
        clean = model.clean
        props: list[str] = []
        define = re.search(r"(?<![\w$.])defineProps[ \t]*+(?:<[ \t\r\n]*+\{([^{}]{0,2000}+)\}[ \t\r\n]*+>)?[ \t]*+\(", clean)
        if define and define.group(1):
            props = re.findall(r"(?<![\w$])([A-Za-z_$][\w$]*+)[ \t]*+\??[ \t]*+:", define.group(1))
        elif define:
            close = model.parens.get(define.end() - 1)
            if close is not None:
                props = re.findall(r"(?<![\w$.])([A-Za-z_$][\w$]*+)[ \t]*+:", clean[define.end():close])
                props += [model.string_value(span) for span in model.strings_between(define.end(), close)]
        else:
            option = re.search(r"(?<![\w$.])props[ \t]*+:[ \t]*+([\[{])", clean)
            if option:
                opening = option.end() - 1
                close = (model.braces if clean[opening] == "{" else {}).get(opening)
                if close is None and clean[opening] == "[":
                    close = clean.find("]", opening)
                if close:
                    props = re.findall(r"(?<![\w$.])([A-Za-z_$][\w$]*+)[ \t]*+:", clean[opening + 1:close]) or [
                        model.string_value(span) for span in model.strings_between(opening, close)]
        return self._single_file(model, posix, "Vue", [prop for prop in props if prop][:40])

    def _svelte(self, model: FileModel, posix: str) -> list[Finding]:
        props = _SVELTE_PROP.findall(model.clean)
        runes = _SVELTE_RUNE_PROPS.search(model.clean)
        if runes:
            props += [part.strip().split("=", 1)[0].split(":", 1)[0].strip() for part in runes.group(1).split(",")
                      if part.strip()]
        return self._single_file(model, posix, "Svelte", [prop for prop in props if prop][:40])

    # -- routes ------------------------------------------------------------------------------
    def _routes(self, model: FileModel) -> list[Finding]:
        clean, text = model.clean, model.text
        paths: list[tuple[str, int]] = []
        for match in _ROUTE_ELEMENT.finditer(text):
            if clean.startswith("<Route", match.start()):
                paths.append((match.group(1), model.line_of(match.start())))
        factories = list(_ROUTER_FACTORY.finditer(clean)) + list(_ANGULAR_ROUTES.finditer(clean))
        regions = []
        for factory in factories:
            opening = factory.end() - 1
            close = model.parens.get(opening) if clean[opening] == "(" else self._bracket_end(clean, opening)
            if close is not None:
                regions.append((opening, close))
        if not regions and not paths and "routes" in clean:
            routes = re.search(r"(?<![\w$.])(?:const|let|var|export[ \t]++const)[ \t]++routes\b[^=\n]{0,200}+=[ \t]*+\[", clean)
            if routes:
                close = self._bracket_end(clean, routes.end() - 1)
                if close is not None:
                    regions.append((routes.end() - 1, close))
        for start, end in regions:
            for key in _PATH_KEY.finditer(clean, start, end):
                literal = _STRING_AT.match(text, key.end())
                if literal:
                    paths.append((literal.group(2), model.line_of(key.start())))
        if not paths:
            return []
        framework = ("Angular Router" if _ANGULAR_ROUTES.search(clean) or "RouterModule" in clean
                     else "Vue Router" if re.search(r"createRouter|VueRouter", clean) else "React Router")
        for route, _ in paths[:500]:
            code_facts.emit_fact("route", route or "/", framework=framework)
        return [code_finding(
            model, "frontend", "Client-side routes",
            f"{len(paths)} {framework} route(s): " + ", ".join(sorted({route or '/' for route, _ in paths})[:20]) + ".",
            [line for _, line in paths], analyzer=self.name, severity="INFO",
        )]

    @staticmethod
    def _bracket_end(clean: str, opening: int) -> int | None:
        depth = 0
        for index in range(opening, min(len(clean), opening + 200_000)):
            char = clean[index]
            if char == "[":
                depth += 1
            elif char == "]":
                depth -= 1
                if depth == 0:
                    return index
        return None

    # -- configuration ------------------------------------------------------------------------
    def _config(self, path: Path, record: FileRecord, kind: str) -> list[Finding]:
        if over_limit(record.size_bytes, _MAX_CONFIG_BYTES):
            return [oversize_finding(self, record, "frontend", "Frontend configuration", _MAX_CONFIG_BYTES)]
        try:
            text = read_text_bounded(path, _MAX_CONFIG_BYTES, errors="replace", expected_identity=record.analysis_identity)
        except (OSError, SourceBudgetExceeded):
            return []
        code_facts.emit_fact("frontend_tool", kind)
        details: list[str] = []
        issues: list[Finding] = []

        def finding(title: str, detail: str, severity: str = "INFO", recommendation: str | None = None) -> Finding:
            return Finding("frontend", f"{title}: {record.path}", detail, confidence="CONFIRMED",
                           evidence=[record.path], analyzer=self.name, severity=severity,
                           recommendation=recommendation)

        if kind in {"webpack", "Rspack"}:
            mode = re.search(r"mode[ \t]*+:[ \t]*+[\"'](\w{1,20}+)[\"']", text)
            devtool = re.search(r"devtool[ \t]*+:[ \t]*+[\"']([\w-]{1,40}+)[\"']", text)
            loaders = sorted(set(_LOADER.findall(text)))
            plugins = sorted(set(re.findall(r"new[ \t]++([A-Z]\w{1,60}?Plugin)\b", text)))
            if mode:
                details.append(f"mode {mode.group(1)}")
            if devtool:
                details.append(f"devtool {devtool.group(1)}")
            if loaders:
                details.append("loaders " + ", ".join(loaders[:12]))
            if plugins:
                details.append("plugins " + ", ".join(plugins[:12]))
            if devtool and "eval" in devtool.group(1) and (mode and mode.group(1) == "production" or "prod" in record.path.lower()):
                issues.append(finding(
                    "eval source maps in a production build", f"devtool {devtool.group(1)} wraps modules in eval(), "
                    "which is slow, ships source code and breaks a strict Content-Security-Policy.", "LOW",
                    "Use devtool: 'source-map' (uploaded privately) or false for production builds.",
                ))
        elif kind == "Vite":
            plugins = sorted(set(_VITE_PLUGINS.findall(text)))
            if plugins:
                details.append("plugins " + ", ".join(plugins))
            if re.search(r"sourcemap[ \t]*+:[ \t]*+true", text):
                details.append("build source maps enabled")
        elif kind == "Next.js":
            output = re.search(r"output[ \t]*+:[ \t]*+[\"'](\w{1,20}+)[\"']", text)
            if output:
                details.append(f"output {output.group(1)}")
            if re.search(r"ignoreBuildErrors[ \t]*+:[ \t]*+true", text):
                issues.append(finding(
                    "Type errors ignored in production builds",
                    "typescript.ignoreBuildErrors is true, so `next build` ships code that fails type checking.", "LOW",
                    "Remove ignoreBuildErrors and fix the type errors (or check types in CI).",
                ))
            if re.search(r"ignoreDuringBuilds[ \t]*+:[ \t]*+true", text):
                issues.append(finding(
                    "Lint errors ignored in production builds",
                    "eslint.ignoreDuringBuilds is true, so lint failures do not stop deployments.", "LOW",
                ))
            if re.search(r"reactStrictMode[ \t]*+:[ \t]*+false", text):
                details.append("React strict mode disabled")
        elif kind == "SvelteKit":
            adapter = _ADAPTER.search(text)
            if adapter:
                details.append(f"adapter {adapter.group(1)}")
        elif kind == "Nuxt":
            if re.search(r"ssr[ \t]*+:[ \t]*+false", text):
                details.append("SSR disabled (single-page app)")
            modules = re.findall(r"[\"'](@nuxt[\w/-]{0,60}+|@pinia/nuxt|@nuxtjs/[\w-]{1,40}+)[\"']", text)
            if modules:
                details.append("modules " + ", ".join(sorted(set(modules))[:12]))
        elif kind == "Angular":
            try:
                data = json.loads(text)
            except ValueError:
                data = {}
            projects = data.get("projects") if isinstance(data, dict) else None
            if isinstance(projects, dict):
                details.append(f"{len(projects)} project(s): {', '.join(sorted(projects)[:10])}")
                for name, project in projects.items():
                    build = (((project or {}).get("architect") or {}).get("build") or {}) if isinstance(project, dict) else {}
                    production = ((build.get("configurations") or {}).get("production") or {}) if isinstance(build, dict) else {}
                    if isinstance(production, dict) and production and not production.get("budgets"):
                        issues.append(finding(
                            "No bundle size budgets", f"Project {name}'s production configuration sets no budgets, so "
                            "bundle size regressions are not caught at build time.", "INFO",
                        ))
                    if isinstance(production, dict) and production.get("sourceMap") is True:
                        details.append(f"{name}: production source maps on")
        elif kind in {"Turborepo", "Nx"}:
            details.append("monorepo task orchestration")
        summary = f"{kind} configuration" + (": " + "; ".join(details) if details else "") + "."
        return [finding(f"{kind} configuration", summary)] + issues
