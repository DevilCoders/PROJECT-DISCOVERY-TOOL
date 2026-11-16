"""Static authentication, authorization and identity-framework discovery."""
from __future__ import annotations

import ast
import io
import re
import tokenize
from pathlib import Path

from ...core.limits import AnalyzerLimits, over_limit
from ...core.source_utils import describe_error, open_verified_binary, parse_python
from ...models import FileRecord, Finding
from ..base import Analyzer

_MAX_IDENTITY_SOURCE_BYTES = 16 * 1024 * 1024
_MAX_IDENTITY_EVIDENCE_LINES = 100
_SOURCE_EXTENSIONS = {
    ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
    ".java", ".kt", ".kts", ".cs", ".fs", ".php", ".rb", ".go", ".rs",
}
_FRAMEWORKS = {
    "jwt": "JWT libraries",
    "jose": "JOSE/JWT libraries",
    "passport": "Passport.js",
    "next-auth": "NextAuth/Auth.js",
    "authlib": "Authlib",
    "oauthlib": "OAuthLib",
    "flask_login": "Flask-Login",
    "django.contrib.auth": "Django Authentication",
    "fastapi.security": "FastAPI Security",
    "passlib": "Passlib",
    "bcrypt": "bcrypt",
    "argon2": "Argon2",
    "spring.security": "Spring Security",
    "org.springframework.security": "Spring Security",
    "shiro": "Apache Shiro",
    "devise": "Devise",
    "pundit": "Pundit",
    "laravel/sanctum": "Laravel Sanctum",
    "laravel/passport": "Laravel Passport",
    "golang.org/x/oauth2": "Go OAuth2",
    "github.com/golang-jwt": "Go JWT",
    "casbin": "Casbin",
}
def _add_location(
    locations: dict[str, set[int]],
    key: str,
    line_number: int,
) -> None:
    """Retain at most the configured number of source lines per evidence category."""
    bucket = locations.setdefault(key, set())
    if len(bucket) < _MAX_IDENTITY_EVIDENCE_LINES:
        bucket.add(line_number)


_PATTERNS = (
    (
        "authentication",
        re.compile(
            r"\b(?:login_required|requires_auth|OAuth2PasswordBearer|HTTPBearer|"
            r"passport\.authenticate|authMiddleware|create_access_token|"
            r"jwt\.(?:encode|decode)|verify_password|check_password|"
            r"PasswordHasher|bcrypt\.hashpw|argon2)\b",
            re.I,
        ),
        "Authentication and credential-verification markers",
        "Authentication-related APIs or decorators are present. This does not establish "
        "correct credential storage, token validation, or session security.",
    ),
    (
        "authorization",
        re.compile(
            r"(?:@(?:PreAuthorize|PostAuthorize|Secured|RolesAllowed|login_required|"
            r"permission_required)|\[\s*Authorize|@UseGuards|@Roles\b|"
            r"\b(?:hasRole|hasAuthority|isAuthenticated|authorize|can\?)\s*\()",
            re.I,
        ),
        "Authorization and access-control markers",
        "Access-control annotations or checks are present. Coverage and enforcement "
        "across every route/resource are not established by this scan.",
    ),
    (
        "session_management",
        re.compile(
            r"\b(?:express-session|cookie-session|SessionMiddleware|"
            r"session_start|HttpSession|AddSession|UseSession)\b",
            re.I,
        ),
        "Session-management markers",
        "Session-related configuration or APIs were observed; cookie flags, rotation, "
        "expiration, and server-side invalidation require separate review.",
    ),
    (
        "oauth_oidc",
        re.compile(
            r"\b(?:openid|OAuth2|OAuthClient|OpenIDConnect|OIDC|"
            r"authorization_code|client_credentials)\b",
            re.I,
        ),
        "OAuth/OIDC protocol markers",
        "OAuth or OpenID Connect references were observed. Provider configuration, "
        "redirect validation, PKCE, scopes, and token lifecycle are not verified.",
    ),
)


_IMPORT_LINE = re.compile(
    r"(?i)^[ \t]*+(?:import|from|using|use|require|include|#include|@import|implementation|compile|api)\b"
    r"|\brequire\s*+\(|\bimport\s*+\(|<(?:dependency|PackageReference)\b|<artifactId>"
)
_FRAMEWORK_WORDS = {
    framework: re.compile(r"(?i)(?<![\w.-])" + re.escape(framework) + r"(?![\w-])") for framework in _FRAMEWORKS
}


def _root_name(node) -> str:
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id.lower() if isinstance(node, ast.Name) else ""

def _python_markers(source: str, relative: str) -> tuple[dict[str, set[int]], dict[str, set[int]]]:
    try:
        tree = parse_python(source, filename=relative)
    except SyntaxError:
        return {}, {}
    frameworks: dict[str, set[int]] = {}
    markers: dict[str, set[int]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                module = alias.name
                framework = _FRAMEWORKS.get(module)
                if framework is None:
                    framework = _FRAMEWORKS.get(module.split(".", 1)[0])
                if framework:
                    _add_location(frameworks, framework, node.lineno)
        elif isinstance(node, ast.ImportFrom) and node.module:
            module = node.module
            framework = _FRAMEWORKS.get(module)
            if framework is None:
                framework = _FRAMEWORKS.get(module.split(".", 1)[0])
            if framework:
                _add_location(frameworks, framework, node.lineno)
        elif isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else (
                func.id if isinstance(func, ast.Name) else ""
            )
            lowered = name.lower()
            # encode/decode are authentication markers only on a JWT library
            # (jwt.decode), not on every bytes or string.
            token_call = lowered in {"decode", "encode"} and isinstance(func, ast.Attribute) and (
                _root_name(func.value) in {"jwt", "jose", "jws", "jwe", "pyjwt"}
            )
            if token_call or lowered in {
                "login_required", "requires_auth", "create_access_token",
                "verify_password", "check_password", "hashpw",
                "oauth2passwordbearer", "httpbearer",
            }:
                category = (
                    "authorization" if lowered in {"login_required", "requires_auth"}
                    else "authentication"
                )
                _add_location(markers, category, node.lineno)
    return frameworks, markers


class IdentityIntelligenceAnalyzer(Analyzer):
    """Inventory auth frameworks and access-control markers without validating credentials."""

    name = "identity-intelligence"
    limits = AnalyzerLimits(
        _MAX_IDENTITY_SOURCE_BYTES,
        "whole",
        {"evidence_lines": _MAX_IDENTITY_EVIDENCE_LINES},
        outcome="UNKNOWN finding on oversize, growth, read or AST resource failure",
    )
    domains = ("authentication", "authorization")
    languages = (
        "Python", "JavaScript", "TypeScript", "Java", "Kotlin", "C#",
        "F#", "PHP", "Ruby", "Go", "Rust",
    )

    def supports(self, record: FileRecord) -> bool:
        return record.error is None and record.extension in _SOURCE_EXTENSIONS

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        if over_limit(record.size_bytes, _MAX_IDENTITY_SOURCE_BYTES):
            return [Finding(
                "identity", f"Identity analysis resource limit: {record.path}",
                f"File size {record.size_bytes:,} bytes exceeds the identity analyzer's "
                f"{_MAX_IDENTITY_SOURCE_BYTES:,}-byte content budget. This is not a clean result.",
                confidence="UNKNOWN", evidence=[record.path],
                analyzer=self.name, severity="LOW",
            )]
        try:
            with open_verified_binary(path, record.analysis_identity) as stream:
                raw_source = stream.read(_MAX_IDENTITY_SOURCE_BYTES + 1)
            if len(raw_source) > _MAX_IDENTITY_SOURCE_BYTES:
                return [Finding(
                    "identity", f"Identity analysis resource limit: {record.path}",
                    f"Content grew beyond the {_MAX_IDENTITY_SOURCE_BYTES:,}-byte identity "
                    "analyzer budget while being read. This is not a clean result.",
                    confidence="UNKNOWN",
                    evidence=[record.path, f"read_limit: {_MAX_IDENTITY_SOURCE_BYTES} bytes"],
                    analyzer=self.name, severity="LOW",
                )]
            if record.extension in {".py", ".pyi"}:
                encoding, _ = tokenize.detect_encoding(io.BytesIO(raw_source).readline)
                source = raw_source.decode(encoding)
            else:
                source = raw_source.decode("utf-8")
        except (OSError, UnicodeDecodeError, SyntaxError, LookupError) as exc:
            return [Finding(
                "identity", f"Identity analysis unavailable: {record.path}",
                describe_error(exc),
                confidence="UNKNOWN", severity="LOW", evidence=[record.path], analyzer=self.name,
            )]
        frameworks: dict[str, set[int]] = {}
        markers: dict[str, set[int]] = {}
        is_python = record.extension in {".py", ".pyi"}
        if is_python:
            try:
                frameworks, markers = _python_markers(source, record.path)
            except (RecursionError, MemoryError) as exc:
                return [Finding(
                    "identity", f"Identity AST resource limit: {record.path}",
                    f"{type(exc).__name__}: Python identity parsing could not complete within "
                    "available interpreter resources.",
                    confidence="UNKNOWN", evidence=[record.path],
                    analyzer=self.name, severity="LOW",
                )]

        # Iterate without materializing source.splitlines(); retain only bounded
        # representative locations for each marker/framework family.
        for line_number, line in enumerate(io.StringIO(source, newline=None), 1):
            if not is_python and _IMPORT_LINE.search(line):
                # Whole names on import, require, use and include lines: a substring such as
                # "Jose" in a person's name or "passport" in a field is not a library.
                for framework, package in _FRAMEWORKS.items():
                    if _FRAMEWORK_WORDS[framework].search(line):
                        _add_location(frameworks, package, line_number)
            for category, pattern, _, _ in _PATTERNS:
                if pattern.search(line):
                    _add_location(markers, category, line_number)

        findings = []
        if frameworks:
            names = sorted(frameworks)
            evidence = [
                f"{record.path}:{line} ({name})"
                for name, locations in frameworks.items() for line in sorted(locations)
            ]
            findings.append(Finding(
                "authentication",
                f"Identity framework references: {record.path}",
                "Observed identity/authentication libraries: " + ", ".join(names)
                + ". Import presence does not prove that authentication is enabled or correct.",
                confidence="CONFIRMED" if is_python else "INFERRED", evidence=evidence[:100], analyzer=self.name,
            ))
        metadata = {category: (title, detail) for category, _, title, detail in _PATTERNS}
        for category, locations in sorted(markers.items()):
            title, detail = metadata.get(category, (
                category.replace("_", " ").title() + " markers",
                "Identity-related source markers were observed; their effectiveness is not verified.",
            ))
            findings.append(Finding(
                category,
                f"{title}: {record.path}",
                detail,
                confidence="INFERRED",
                evidence=[f"{record.path}:{line}" for line in sorted(locations)[:100]],
                analyzer=self.name,
            ))
        return findings
