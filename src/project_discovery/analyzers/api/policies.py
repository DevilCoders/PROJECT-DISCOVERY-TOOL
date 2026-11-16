"""API policy declarations: authentication and authorization, API versioning, rate limits and
request validation, where code declares them.

Each declaration is reported with its category, framework, scope and detail: the scope is where it
applies as written (``global`` middleware or settings, a ``router`` or route group, a ``class``
such as a controller or view, a ``route``, a ``model`` or schema that validates input), the
detail what it says (the guard or role, the rate, the version, the validator). Exemptions
(``@AllowAnonymous``, ``skip_before_action``, ``@SkipThrottle``) are declarations too. Nothing is
executed: a declaration is evidence that a policy is configured, not that it is enforced on every
route. Forms ordinary code also uses count only in files that import the framework.
"""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

from ...core.limits import AnalyzerLimits, over_limit
from ...core.source_utils import SourceBudgetExceeded, read_text_bounded
from ...intelligence import facts as code_facts
from ...models import FileRecord, Finding
from ..base import Analyzer
from .rpc import _Lines

MAX_POLICY_BYTES = 16 * 1024 * 1024
MAX_POLICY_FACTS = 1000
MAX_POLICY_EVIDENCE = 100

_PY = frozenset({".py"})
_JS = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"})
_JVM = frozenset({".java", ".kt", ".kts", ".scala", ".groovy"})
_CS = frozenset({".cs"})
_GO = frozenset({".go"})
_RUBY = frozenset({".rb"})
_PHP = frozenset({".php"})
_ELIXIR = frozenset({".ex", ".exs"})
_RUST = frozenset({".rs"})
_CODE = _PY | _JS | _JVM | _CS | _GO | _RUBY | _PHP | _ELIXIR | _RUST
_ALL = _CODE

_DETAIL = r"(?P<detail>[^\"'`\n]{1,120})"
_Q = r"[\"'`]"

# Imports that must be present before forms ordinary code also uses count.
_DRF = re.compile(r"\brest_framework\b|REST_FRAMEWORK")
_FASTAPI = re.compile(r"\bfastapi\b")
_FLASK_LIMITER = re.compile(r"\bflask_limiter\b|\bslowapi\b")
_DJANGO_RATELIMIT = re.compile(r"\bdjango_ratelimit\b|\bratelimit\.decorators\b")
_MARSHMALLOW = re.compile(r"\bmarshmallow\b")
_PYDANTIC = re.compile(r"\bpydantic\b")
_EXPRESS_RATE = re.compile(r"express-rate-limit|express-slow-down")
_NEST_THROTTLER = re.compile(r"@nestjs/throttler")
_EXPRESS_VALIDATOR = re.compile(r"express-validator")
_CLASS_VALIDATOR = re.compile(r"class-validator")
_JOI = re.compile(r"\bjoi\b|\bJoi\b")
_ZOD = re.compile(r"\bzod\b")
_YUP = re.compile(r"\byup\b")
_BEAN_VALIDATION = re.compile(r"\b(?:javax|jakarta)\.validation\b")
_RESILIENCE4J = re.compile(r"resilience4j")
_DATA_ANNOTATIONS = re.compile(r"System\.ComponentModel\.DataAnnotations")
_FLUENT = re.compile(r"\bFluentValidation\b")
_GO_RATE = re.compile(r"golang\.org/x/time/rate")
_GO_VALIDATOR = re.compile(r"go-playground/validator|github\.com/gin-gonic/gin")
_SYMFONY_ASSERT = re.compile(r"Symfony\\\\?Component\\\\?Validator")
_RACK_ATTACK = re.compile(r"Rack::Attack")
_RUST_VALIDATOR = re.compile(r"\bvalidator\b|\bgarde\b")

# (category, framework, scope, pattern with an optional "detail" group, extensions, import)
_POLICIES = (
    # -- authentication and authorization: Python
    ("auth", "Django/Flask-Login", "route", re.compile(r"@(?:\w{1,40}\.)?login_required\b"), _PY, None),
    ("auth", "Django", "route", re.compile(r"@permission_required\s*+\(\s*+[\"'](?P<detail>[^\"'\n]{1,120})[\"']"), _PY, None),
    ("auth", "Django", "route", re.compile(r"@user_passes_test\b"), _PY, None),
    ("auth", "Django", "class", re.compile(r"\b(?P<detail>LoginRequiredMixin|PermissionRequiredMixin|UserPassesTestMixin)\b"),
     _PY, None),
    ("auth", "Django REST framework", "class", re.compile(
        r"\b(?:permission|authentication)_classes\s*+=\s*+[\[(](?P<detail>[^\])\n]{1,200})[\])]"), _PY, _DRF),
    ("auth", "Django REST framework", "global", re.compile(
        r"[\"']DEFAULT_(?:PERMISSION|AUTHENTICATION)_CLASSES[\"']\s*+:\s*+[\[(](?P<detail>[^\])]{1,300})[\])]"), _PY, None),
    ("auth", "Flask-JWT-Extended", "route", re.compile(r"@jwt_required\b(?:\((?P<detail>[^)\n]{0,100})\))?"), _PY, None),
    ("auth", "FastAPI", "route", re.compile(
        r"\b(?:Depends|Security)\s*+\(\s*+(?P<detail>[\w.]{0,60}(?:current|auth|token|verify|permission|api_key|principal)"
        r"\w{0,60})\s*+[,)]", re.I), _PY, _FASTAPI),
    ("auth", "FastAPI", "global", re.compile(r"\b(?P<detail>OAuth2PasswordBearer|OAuth2AuthorizationCodeBearer|HTTPBearer|"
                                             r"HTTPBasic|APIKeyHeader|APIKeyQuery|APIKeyCookie)\s*+\("), _PY, _FASTAPI),
    # JavaScript and TypeScript
    ("auth", "Passport", "route", re.compile(r"\bpassport\.authenticate\s*+\(\s*+" + _Q + r"(?P<detail>[\w-]{1,60})" + _Q),
     _JS, None),
    ("auth", "Express", "global", re.compile(
        r"\b(?:app|router|server)\.use\s*+\(\s*+(?:" + _Q + r"[^\"'`\n]{0,200}" + _Q + r"\s*+,\s*+)?"
        r"(?P<detail>passport\.(?:initialize|session|authenticate)|(?:express)?[jJ]wt|\w{0,40}(?:[Aa]uth|[Jj]wt)\w{0,40})\b"),
     _JS, None),
    ("auth", "NestJS", "route", re.compile(r"@UseGuards\s*+\((?P<detail>[^\n]{1,200}?)\)[ \t]*+(?=\r?\n|$)"), _JS, None),
    ("auth", "NestJS", "route", re.compile(r"@Roles\s*+\((?P<detail>[^)\n]{1,200})\)"), _JS, None),
    ("auth", "NestJS", "global", re.compile(r"\bprovide\s*+:\s*+APP_GUARD\b"), _JS, None),
    ("auth", "Fastify", "route", re.compile(
        r"\b(?:onRequest|preHandler)\s*+:\s*+\[?\s*+(?P<detail>[\w.]{0,60}(?:authenticate|[Aa]uth|[Jj]wt)\w{0,40})"), _JS, None),
    ("auth", "Hono/Koa", "global", re.compile(r"\.use\s*+\([^)\n]{0,200}?\b(?P<detail>jwt|bearerAuth|basicAuth|koaJwt)\s*+\("),
     _JS, None),
    # Java, Kotlin, Scala
    ("auth", "Spring Security", "route", re.compile(r"@(?:PreAuthorize|PostAuthorize)\s*+\(\s*+\"(?P<detail>[^\"\n]{1,200})\""),
     _JVM, None),
    ("auth", "Spring Security/JAX-RS", "route", re.compile(
        r"@(?:Secured|RolesAllowed)\s*+\(\s*+\{?\s*+\"(?P<detail>[^\"\n]{1,120})\""), _JVM, None),
    ("auth", "Spring Security", "global", re.compile(
        r"\.requestMatchers\s*+\(\s*+\"(?P<path>[^\"\n]{1,200})\"[^)\n]{0,200}\)\s*+\.(?P<detail>permitAll|authenticated|"
        r"hasRole|hasAnyRole|hasAuthority|hasAnyAuthority|denyAll|anonymous)\b"), _JVM, None),
    ("auth", "Spring Security", "global", re.compile(
        r"\.(?P<detail>authorizeHttpRequests|authorizeRequests|oauth2ResourceServer|oauth2Login|httpBasic|formLogin)\s*+\("),
     _JVM, None),
    ("auth", "JAX-RS/Quarkus/Micronaut", "route", re.compile(r"@(?P<detail>PermitAll|DenyAll|Authenticated)\b"), _JVM, None),
    # C#
    ("auth", "ASP.NET Core", "route", re.compile(r"\[Authorize\b(?:\s*+\((?P<detail>[^)\]\n]{0,200})\))?"), _CS, None),
    ("auth", "ASP.NET Core", "exemption", re.compile(r"\[(?P<detail>AllowAnonymous)\b"), _CS, None),
    ("auth", "ASP.NET Core", "global", re.compile(
        r"\.(?P<detail>UseAuthentication|UseAuthorization|AddAuthentication|AddAuthorization|AddJwtBearer)\s*+\("), _CS, None),
    ("auth", "ASP.NET Core", "route", re.compile(r"\.RequireAuthorization\s*+\((?P<detail>[^)\n]{0,200})\)"), _CS, None),
    ("auth", "ASP.NET Core", "exemption", re.compile(r"\.(?P<detail>AllowAnonymous)\s*+\(\s*+\)"), _CS, None),
    # Go
    ("auth", "Go middleware", "router", re.compile(
        r"\.Use\s*+\(\s*+(?P<detail>(?:\w{1,60}\.)?\w{0,60}(?:[Aa]uth|JWT|Jwt|jwt)[\w.]{0,60})"), _GO, None),
    ("auth", "chi jwtauth", "router", re.compile(r"\bjwtauth\.(?P<detail>Verifier|Authenticator)\s*+\("), _GO, None),
    # Ruby
    ("auth", "Rails", "class", re.compile(
        r"\bbefore_action\s++:(?P<detail>authenticate\w{0,60}!?|require_\w{1,60}|authorize\w{0,60}!?|ensure_\w{0,60}!?)"), _RUBY,
     None),
    ("auth", "Rails", "exemption", re.compile(r"\bskip_before_action\s++:(?P<detail>authenticate\w{0,60}!?|require_\w{1,60})"),
     _RUBY, None),
    ("auth", "CanCanCan/Pundit", "class", re.compile(r"\b(?P<detail>load_and_authorize_resource|authorize_resource|"
                                                     r"after_action\s++:verify_authorized)\b"), _RUBY, None),
    # PHP
    ("auth", "Laravel", "route", re.compile(
        r"->middleware\s*+\(\s*+\[?\s*+[\"'](?P<detail>auth(?::[\w,-]{1,60})?|can:[^\"'\n]{1,80}|verified|abilities:[^\"'\n]{1,80})[\"']"),
     _PHP, None),
    ("auth", "Laravel", "router", re.compile(
        r"\bRoute::middleware\s*+\(\s*+\[?\s*+[\"'](?P<detail>auth(?::[\w,-]{1,60})?|can:[^\"'\n]{1,80})[\"']"), _PHP, None),
    ("auth", "Symfony", "route", re.compile(r"#\[IsGranted\s*+\(\s*+[\"'](?P<detail>[^\"'\n]{1,120})[\"']"), _PHP, None),
    # Elixir, Rust
    ("auth", "Phoenix", "router", re.compile(
        r"\bplug\s++:(?P<detail>require_authenticated_\w{1,60}|ensure_authenticated\w{0,40}|authenticate\w{0,40}|"
        r"fetch_current_\w{1,60})"), _ELIXIR, None),
    ("auth", "actix/axum/tower", "router", re.compile(
        r"\b(?P<detail>HttpAuthentication::bearer|HttpAuthentication::basic|RequireAuthorizationLayer|ValidateRequestHeaderLayer"
        r"::bearer)\s*+\("), _RUST, None),
    # -- versioning
    ("versioning", "ASP.NET API Versioning", "class", re.compile(r"\[ApiVersion\s*+\(\s*+\"(?P<detail>[^\"\n]{1,40})\""), _CS,
     None),
    ("versioning", "ASP.NET API Versioning", "route", re.compile(r"\[MapToApiVersion\s*+\(\s*+\"(?P<detail>[^\"\n]{1,40})\""),
     _CS, None),
    ("versioning", "ASP.NET API Versioning", "global", re.compile(r"\.(?P<detail>AddApiVersioning)\s*+\("), _CS, None),
    ("versioning", "NestJS", "global", re.compile(
        r"\.enableVersioning\s*+\((?:[^)]{0,300}?type\s*+:\s*+VersioningType\.(?P<detail>URI|HEADER|MEDIA_TYPE|CUSTOM))?"), _JS,
     None),
    ("versioning", "NestJS", "route", re.compile(r"@Version\s*+\(\s*+(?:\[\s*+)?" + _Q + r"(?P<detail>[^\"'`\n]{1,40})" + _Q),
     _JS, None),
    ("versioning", "Django REST framework", "global", re.compile(
        r"[\"']DEFAULT_VERSIONING_CLASS[\"']\s*+:\s*+[\"'](?P<detail>[\w.]{1,120})[\"']"), _PY, None),
    ("versioning", "Django REST framework", "class", re.compile(r"\bversioning_class\s*+=\s*+(?P<detail>[\w.]{1,120})"), _PY,
     _DRF),
    ("versioning", "Spring", "route", re.compile(
        r"@(?:Get|Post|Put|Patch|Delete|Request)Mapping\s*+\([^)\n]{0,300}?\bversion\s*+=\s*+\"(?P<detail>[^\"\n]{1,40})\""),
     _JVM, None),
    ("versioning", "Spring", "global", re.compile(r"\b(?P<detail>configureApiVersioning)\s*+\("), _JVM, None),
    ("versioning", "version header", "route", re.compile(r"(?i)[\"'](?P<detail>accept-version|x-api-version|api-version)[\"']"),
     _ALL, None),
    ("versioning", "media type", "route", re.compile(r"application/vnd\.[\w.-]{1,80}\.(?P<detail>v\d{1,3})\+(?:json|xml)"), _ALL,
     None),
    # -- rate limiting
    ("rate_limit", "express-rate-limit", "router", re.compile(r"\b(?:rateLimit|slowDown)\s*+\(\s*+\{(?P<detail>[^}]{0,200})"),
     _JS, _EXPRESS_RATE),
    ("rate_limit", "NestJS throttler", "global", re.compile(r"\bThrottlerModule\.forRoot(?:Async)?\s*+\("), _JS, None),
    ("rate_limit", "NestJS throttler", "route", re.compile(r"@Throttle\s*+\((?P<detail>[^)\n]{0,200})\)"), _JS,
     _NEST_THROTTLER),
    ("rate_limit", "NestJS throttler", "exemption", re.compile(r"@(?P<detail>SkipThrottle)\s*+\("), _JS, None),
    ("rate_limit", "Flask-Limiter/slowapi", "route", re.compile(
        r"@\w{1,40}\.limit\s*+\(\s*+[\"'](?P<detail>[^\"'\n]{1,80})[\"']"), _PY, _FLASK_LIMITER),
    ("rate_limit", "Flask-Limiter/slowapi", "global", re.compile(
        r"\bdefault_limits\s*+=\s*+\[\s*+[\"'](?P<detail>[^\"'\n]{1,80})[\"']"), _PY, _FLASK_LIMITER),
    ("rate_limit", "django-ratelimit", "route", re.compile(r"@ratelimit\s*+\((?P<detail>[^)\n]{0,200})\)"), _PY,
     _DJANGO_RATELIMIT),
    ("rate_limit", "Django REST framework", "global", re.compile(
        r"[\"']DEFAULT_THROTTLE_RATES[\"']\s*+:\s*+\{(?P<detail>[^}]{1,300})\}"), _PY, None),
    ("rate_limit", "Django REST framework", "class", re.compile(
        r"\bthrottle_classes\s*+=\s*+[\[(](?P<detail>[^\])\n]{1,200})[\])]"), _PY, _DRF),
    ("rate_limit", "ASP.NET Core", "global", re.compile(r"\.(?P<detail>AddRateLimiter|UseRateLimiter)\s*+\("), _CS, None),
    ("rate_limit", "ASP.NET Core", "route", re.compile(
        r"(?:\[EnableRateLimiting|\.RequireRateLimiting)\s*+\(\s*+\"(?P<detail>[^\"\n]{1,80})\""), _CS, None),
    ("rate_limit", "ASP.NET Core", "exemption", re.compile(r"\[(?P<detail>DisableRateLimiting)\b"), _CS, None),
    ("rate_limit", "Resilience4j", "route", re.compile(r"@RateLimiter\s*+\(\s*+name\s*+=\s*+\"(?P<detail>[^\"\n]{1,80})\""),
     _JVM, _RESILIENCE4J),
    ("rate_limit", "Bucket4j", "router", re.compile(r"\bBucket4?j?\.builder\s*+\(\s*+\)|\bBucket\.builder\s*+\(\s*+\)"), _JVM,
     None),
    ("rate_limit", "golang.org/x/time/rate", "router", re.compile(r"\brate\.NewLimiter\s*+\((?P<detail>[^)\n]{1,80})\)"), _GO,
     _GO_RATE),
    ("rate_limit", "tollbooth", "router", re.compile(r"\btollbooth\.NewLimiter\s*+\((?P<detail>[^)\n]{1,80})"), _GO, None),
    ("rate_limit", "Rack::Attack", "global", re.compile(
        r"\bRack::Attack\.throttle\s*+\(\s*+[\"'](?P<detail>[^\"'\n]{1,80})[\"']"), _RUBY, None),
    ("rate_limit", "Rails", "class", re.compile(r"\brate_limit\s++to:\s*+(?P<detail>\d{1,9}[^\n]{0,60})"), _RUBY, None),
    ("rate_limit", "Laravel", "route", re.compile(r"[\"']throttle:(?P<detail>[\w,-]{1,40})[\"']"), _PHP, None),
    ("rate_limit", "Laravel", "global", re.compile(r"\bRateLimiter::for\s*+\(\s*+[\"'](?P<detail>[^\"'\n]{1,80})[\"']"), _PHP,
     None),
    ("rate_limit", "tower-governor/actix-governor", "router", re.compile(r"\b(?P<detail>GovernorLayer|Governor::new)\b"), _RUST,
     None),
    # -- validation
    ("validation", "Pydantic", "model", re.compile(r"\bclass\s++(?P<detail>\w{1,120})\s*+\(\s*+(?:pydantic\.)?BaseModel\s*+\)"),
     _PY, _PYDANTIC),
    ("validation", "marshmallow", "model", re.compile(r"\bclass\s++(?P<detail>\w{1,120})\s*+\(\s*+(?:ma\.)?Schema\s*+\)"), _PY,
     _MARSHMALLOW),
    ("validation", "Django REST framework", "model", re.compile(
        r"\bclass\s++(?P<detail>\w{1,120})\s*+\(\s*+serializers\.(?:Model|Hyperlinked)?Serializer\s*+\)"), _PY, None),
    ("validation", "Django forms", "model", re.compile(r"\bclass\s++(?P<detail>\w{1,120})\s*+\(\s*+forms\.(?:Model)?Form\s*+\)"),
     _PY, None),
    ("validation", "jsonschema", "route", re.compile(r"\bjsonschema\.validate\s*+\("), _PY, None),
    ("validation", "Joi/celebrate", "model", re.compile(r"\bJoi\.object\s*+\(|\bcelebrate\s*+\(\s*+\{"), _JS, _JOI),
    ("validation", "express-validator", "route", re.compile(
        r"\b(?:body|query|param|check|header|cookie)\s*+\(\s*+" + _Q + r"(?P<detail>[\w.\[\]*-]{1,80})" + _Q
        + r"\s*+\)\s*+\.\s*+(?:is\w{1,30}|not\w{0,30}|exists|optional|trim|escape|matches|custom|equals|contains)\s*+\("),
     _JS, _EXPRESS_VALIDATOR),
    ("validation", "zod", "model", re.compile(r"\bz\.object\s*+\("), _JS, _ZOD),
    ("validation", "yup", "model", re.compile(r"\byup\.object\s*+\("), _JS, _YUP),
    ("validation", "Ajv", "model", re.compile(r"\bajv\.compile\s*+\(|\bnew\s++Ajv\s*+\("), _JS, None),
    ("validation", "class-validator", "model", re.compile(
        r"@(?P<detail>IsString|IsEmail|IsInt|IsNumber|IsBoolean|IsNotEmpty|IsOptional|MinLength|MaxLength|IsUUID|IsEnum|"
        r"IsDate|IsDateString|ValidateNested|Matches|IsUrl|ArrayNotEmpty|Length)\s*+\("), _JS, _CLASS_VALIDATOR),
    ("validation", "NestJS", "global", re.compile(r"\buseGlobalPipes\s*+\([^)\n]{0,200}?ValidationPipe\b"), _JS, None),
    ("validation", "NestJS", "route", re.compile(r"@UsePipes\s*+\([^)\n]{0,200}?ValidationPipe\b"), _JS, None),
    ("validation", "Fastify", "route", re.compile(r"\bschema\s*+:\s*+\{\s*+(?P<detail>body|querystring|params|headers)\s*+:"),
     _JS, None),
    ("validation", "Bean Validation", "route", re.compile(r"@(?P<detail>Valid|Validated)\b"), _JVM, _BEAN_VALIDATION),
    ("validation", "Bean Validation", "model", re.compile(
        r"@(?P<detail>NotNull|NotBlank|NotEmpty|Size|Email|Pattern|Min|Max|Positive|PositiveOrZero|Negative|Past|Future|"
        r"Digits|DecimalMin|DecimalMax)\b"), _JVM, _BEAN_VALIDATION),
    ("validation", "Data annotations", "model", re.compile(
        r"\[(?P<detail>Required|StringLength|Range|EmailAddress|RegularExpression|MaxLength|MinLength|Phone|Url|Compare)\b"),
     _CS, _DATA_ANNOTATIONS),
    ("validation", "ASP.NET Core", "class", re.compile(r"\[(?P<detail>ApiController)\]"), _CS, None),
    ("validation", "FluentValidation", "model", re.compile(r"\bAbstractValidator\s*+<\s*+(?P<detail>\w{1,120})\s*+>"), _CS,
     _FLUENT),
    ("validation", "go-playground/validator", "model", re.compile(
        r"`[^`\n]{0,200}?\b(?:validate|binding):\"(?P<detail>[^\"\n]{1,120})\""), _GO, _GO_VALIDATOR),
    ("validation", "Laravel", "route", re.compile(r"\$request->validate\s*+\(|\bValidator::make\s*+\("), _PHP, None),
    ("validation", "Laravel", "model", re.compile(r"\bclass\s++(?P<detail>\w{1,120})\s++extends\s++FormRequest\b"), _PHP, None),
    ("validation", "Symfony Validator", "model", re.compile(r"#\[Assert\\(?P<detail>\w{1,60})"), _PHP, _SYMFONY_ASSERT),
    ("validation", "Rails", "model", re.compile(r"\bvalidates(?:_\w{1,40}_of)?\s++:(?P<detail>\w{1,120})"), _RUBY, None),
    ("validation", "Rails", "route", re.compile(r"\bparams\.require\s*+\(\s*+:(?P<detail>\w{1,120})\s*+\)\s*+\.permit\b"), _RUBY,
     None),
    ("validation", "Ecto", "model", re.compile(r"\b(?P<detail>validate_required|validate_format|validate_length|"
                                               r"validate_inclusion|validate_number)\s*+\("), _ELIXIR, None),
    ("validation", "validator/garde", "model", re.compile(r"#\[(?:validate|garde)\s*+\((?P<detail>[^)\n]{1,120})\)"), _RUST,
     _RUST_VALIDATOR),
)
_CATEGORY_WORDS = {
    "auth": ("login_required", "permission", "authenticat", "authoriz", "jwt", "guard", "roles", "secured", "rolesallowed",
             "permitall", "denyall", "allowanonymous", "before_action", "middleware", "isgranted", "plug", "httpauthentication",
             "mixin", "oauth2", "apikey", "httpbearer", "httpbasic", "passport", "security", "depends", "requestmatchers"),
    "versioning": ("version", "vnd."),
    "rate_limit": ("ratelimit", "rate_limit", "rate-limit", "throttl", "slowdown", "limiter", ".limit(", "default_limits",
                   "bucket", "tollbooth", "rack::attack", "governor"),
    "validation": ("basemodel", "schema", "serializer", "forms.", "jsonschema", "joi", "celebrate", "express-validator",
                   "z.object", "yup", "ajv", "class-validator", "validationpipe", "@valid", "@notnull", "@notblank", "@size",
                   "@email", "@pattern", "@min", "@max", "@positive", "@past", "@future", "@digits", "@decimal", "[required",
                   "[stringlength", "[range", "[emailaddress", "[regularexpression", "[maxlength", "[minlength", "[phone",
                   "[url", "[compare", "apicontroller", "abstractvalidator", "validate:", "binding:", "->validate",
                   "validator::make", "formrequest", "assert\\", "validates", "permit", "validate_", "#[validate", "#[garde"),
}
_LABELS = {"auth": "authentication and authorization", "versioning": "versioning", "rate_limit": "rate limiting",
           "validation": "validation"}


def policies(text: str, extension: str) -> list[tuple[str, str, str, str, int]]:
    """(category, framework, scope, detail, line) of the policy declarations a source file makes."""
    lowered = text.lower()
    categories = {category for category, words in _CATEGORY_WORDS.items() if any(word in lowered for word in words)}
    if not categories:
        return []
    lines = _Lines(text)
    imports: dict[int, bool] = {}
    found = []
    for category, framework, scope, pattern, extensions, marker in _POLICIES:
        if category not in categories or extension not in extensions:
            continue
        if marker is not None:
            if id(marker) not in imports:
                imports[id(marker)] = marker.search(text) is not None
            if not imports[id(marker)]:
                continue
        for match in pattern.finditer(text):
            groups = match.groupdict()
            detail = " ".join((groups.get("detail") or "").split())[:120]
            if groups.get("path"):
                detail = f"{groups['path']} {detail}"
            found.append((category, framework, scope, detail, lines.line(match.start())))
            if len(found) >= MAX_POLICY_FACTS:
                return found
    return sorted(set(found), key=lambda item: (item[4], item[0], item[1], item[3]))


class PolicyAnalyzer(Analyzer):
    """Authentication, authorization, versioning, rate-limit and validation declarations, statically."""

    name = "api-policies"
    limits = AnalyzerLimits(MAX_POLICY_BYTES, "whole", {"evidence_lines": MAX_POLICY_EVIDENCE},
                            outcome="no finding past the budget")
    domains = ("authentication", "authorization", "api_rest")
    languages = ("Python", "JavaScript", "TypeScript", "Java", "Kotlin", "Scala", "Groovy", "C#", "Go", "Ruby", "PHP",
                 "Elixir", "Rust")

    def supports(self, record: FileRecord) -> bool:
        return record.error is None and record.extension in _CODE

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        if over_limit(record.size_bytes, MAX_POLICY_BYTES):
            return []
        try:
            text = read_text_bounded(path, MAX_POLICY_BYTES, errors="replace", expected_identity=record.analysis_identity)
        except (OSError, ValueError, SourceBudgetExceeded):
            return []
        found = policies(text, record.extension)
        if not found:
            return []
        for category, framework, scope, detail, line in found:
            code_facts.emit_fact("api_policy", detail or framework, category=category, framework=framework, scope=scope,
                                 detail=detail, line=line)
        counts = Counter(category for category, _, _, _, _ in found)
        return [Finding(
            "api", f"API policy declarations: {record.path}",
            "; ".join(f"{_LABELS[category]}: {counts[category]}" for category in _LABELS if counts[category])
            + ". A declaration shows a policy is configured here, not that it covers every route.",
            confidence="INFERRED", analyzer=self.name,
            evidence=[f"{record.path}:{line} {_LABELS[category]} {scope} {framework}" + (f": {detail}" if detail else "")
                      for category, framework, scope, detail, line in found[:MAX_POLICY_EVIDENCE]],
        )]
