"""Static authentication, authorization and identity-framework discovery."""
from __future__ import annotations

import ast
import re
from pathlib import Path

from .base import Analyzer
from ..models import FileRecord, Finding
from ..source_utils import read_python_source


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


def _python_markers(source: str, relative: str) -> tuple[dict[str, set[int]], dict[str, set[int]]]:
    try:
        tree = ast.parse(source, filename=relative)
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
                    frameworks.setdefault(framework, set()).add(node.lineno)
        elif isinstance(node, ast.ImportFrom) and node.module:
            module = node.module
            framework = _FRAMEWORKS.get(module)
            if framework is None:
                framework = _FRAMEWORKS.get(module.split(".", 1)[0])
            if framework:
                frameworks.setdefault(framework, set()).add(node.lineno)
        elif isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else (
                func.id if isinstance(func, ast.Name) else ""
            )
            lowered = name.lower()
            if lowered in {
                "login_required", "requires_auth", "create_access_token",
                "verify_password", "check_password", "hashpw", "decode",
                "encode", "oauth2passwordbearer", "httpbearer",
            }:
                category = (
                    "authorization" if lowered in {"login_required", "requires_auth"}
                    else "authentication"
                )
                markers.setdefault(category, set()).add(node.lineno)
    return frameworks, markers


class IdentityIntelligenceAnalyzer(Analyzer):
    """Inventory auth frameworks and access-control markers without validating credentials."""

    name = "identity-intelligence"
    domains = ("authentication", "authorization")
    languages = (
        "Python", "JavaScript", "TypeScript", "Java", "Kotlin", "C#",
        "F#", "PHP", "Ruby", "Go", "Rust",
    )

    def supports(self, record: FileRecord) -> bool:
        return record.error is None and record.extension in _SOURCE_EXTENSIONS

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            source = (
                read_python_source(path)
                if record.extension in {".py", ".pyi"}
                else path.read_text(encoding="utf-8")
            )
        except (OSError, UnicodeDecodeError) as exc:
            return [Finding(
                "identity", f"Identity analysis unavailable: {record.path}",
                f"{type(exc).__name__}: {exc}", confidence="UNKNOWN",
                evidence=[record.path], analyzer=self.name,
            )]
        frameworks: dict[str, set[int]] = {}
        markers: dict[str, set[int]] = {}
        if record.extension in {".py", ".pyi"}:
            frameworks, markers = _python_markers(source, record.path)
        else:
            lines = source.splitlines()
            for framework, package in _FRAMEWORKS.items():
                locations = {
                    number for number, line in enumerate(lines, 1)
                    if package.lower() in line.lower() or framework.lower() in line.lower()
                }
                if locations:
                    frameworks[package] = locations
        for category, pattern, _, _ in _PATTERNS:
            locations = {
                number for number, line in enumerate(source.splitlines(), 1)
                if pattern.search(line)
            }
            if locations:
                markers.setdefault(category, set()).update(locations)

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
                confidence="CONFIRMED", evidence=evidence[:100], analyzer=self.name,
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
