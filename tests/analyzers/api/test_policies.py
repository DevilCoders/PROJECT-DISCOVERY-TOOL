"""Authentication and authorization, versioning, rate-limit and validation declarations."""
import json
import time
from pathlib import Path

from project_discovery.analyzers.api.policies import PolicyAnalyzer, policies
from project_discovery.cli import run_scan
from project_discovery.intelligence.facts import collecting_facts
from project_discovery.models import FileRecord


def _found(source: str, extension: str) -> set[tuple[str, str, str, str]]:
    return {(category, framework, scope, detail) for category, framework, scope, detail, _ in policies(source, extension)}


def test_authentication_and_authorization():
    python = ("from django.contrib.auth.decorators import login_required, permission_required\n@login_required\n"
              "@permission_required('polls.add_choice')\ndef vote(request):\n    pass\n"
              "class Dashboard(LoginRequiredMixin, View):\n    pass\n"
              "from rest_framework.permissions import IsAuthenticated\nclass Orders(APIView):\n"
              "    permission_classes = [IsAuthenticated, IsAdminUser]\n")
    assert _found(python, ".py") == {
        ("auth", "Django/Flask-Login", "route", ""), ("auth", "Django", "route", "polls.add_choice"),
        ("auth", "Django", "class", "LoginRequiredMixin"), ("auth", "Django REST framework", "class", "IsAuthenticated, IsAdminUser")}
    fastapi = ("from fastapi import Depends, FastAPI\nfrom fastapi.security import OAuth2PasswordBearer\n"
               "oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')\n"
               "async def me(user: User = Depends(get_current_active_user)):\n    return user\n")
    assert _found(fastapi, ".py") == {("auth", "FastAPI", "global", "OAuth2PasswordBearer"),
                                      ("auth", "FastAPI", "route", "get_current_active_user")}
    nest = ("@Controller('cats')\n@UseGuards(AuthGuard('jwt'), RolesGuard)\nexport class CatsController {\n"
            "  @Roles('admin')\n  @Post()\n  create() {}\n}\napp.use(passport.initialize());\n"
            "router.get('/profile', passport.authenticate('jwt', { session: false }), handler);\n")
    assert _found(nest, ".ts") == {
        ("auth", "NestJS", "route", "AuthGuard('jwt'), RolesGuard"), ("auth", "NestJS", "route", "'admin'"),
        ("auth", "Express", "global", "passport.initialize"), ("auth", "Passport", "route", "jwt")}
    java = ('@PreAuthorize("hasRole(\'ADMIN\')")\npublic void delete() {}\n@RolesAllowed({"admin", "ops"})\n'
            'http.authorizeHttpRequests(auth -> auth.requestMatchers("/admin/**").hasRole("ADMIN")\n'
            '    .requestMatchers("/public/**").permitAll());\n')
    assert _found(java, ".java") == {
        ("auth", "Spring Security", "route", "hasRole('ADMIN')"), ("auth", "Spring Security/JAX-RS", "route", "admin"),
        ("auth", "Spring Security", "global", "authorizeHttpRequests"), ("auth", "Spring Security", "global", "/admin/** hasRole"),
        ("auth", "Spring Security", "global", "/public/** permitAll")}
    csharp = ('[Authorize(Roles = "Admin")]\npublic class AdminController : ControllerBase {\n  [AllowAnonymous]\n'
              "  public IActionResult Ping() => Ok();\n}\napp.UseAuthentication();\n"
              'app.MapGet("/orders", Handler).RequireAuthorization("orders.read");\n')
    assert _found(csharp, ".cs") == {
        ("auth", "ASP.NET Core", "route", 'Roles = "Admin"'), ("auth", "ASP.NET Core", "exemption", "AllowAnonymous"),
        ("auth", "ASP.NET Core", "global", "UseAuthentication"), ("auth", "ASP.NET Core", "route", '"orders.read"')}
    ruby = "class OrdersController < ApplicationController\n  before_action :authenticate_user!\n" \
           "  skip_before_action :authenticate_user!, only: [:index]\nend\n"
    assert _found(ruby, ".rb") == {("auth", "Rails", "class", "authenticate_user!"),
                                   ("auth", "Rails", "exemption", "authenticate_user!")}
    php = "Route::middleware(['auth:sanctum'])->group(function () {});\nRoute::get('/x', $h)->middleware('can:update,post');\n"
    assert _found(php, ".php") == {("auth", "Laravel", "router", "auth:sanctum"), ("auth", "Laravel", "route", "can:update,post")}
    go = "r := chi.NewRouter()\nr.Use(jwtauth.Verifier(tokenAuth))\nr.Use(AuthMiddleware)\n"
    assert {item[3] for item in _found(go, ".go")} == {"jwtauth.Verifier", "AuthMiddleware", "Verifier"}
    elixir = "pipeline :protected do\n  plug :require_authenticated_user\nend\n"
    assert _found(elixir, ".ex") == {("auth", "Phoenix", "router", "require_authenticated_user")}


def test_versioning():
    assert _found('[ApiVersion("2.0")]\n[MapToApiVersion("2.0")]\nservices.AddApiVersioning(o => {});\n', ".cs") == {
        ("versioning", "ASP.NET API Versioning", "class", "2.0"), ("versioning", "ASP.NET API Versioning", "route", "2.0"),
        ("versioning", "ASP.NET API Versioning", "global", "AddApiVersioning")}
    assert _found("app.enableVersioning({ type: VersioningType.URI });\n@Version('2')\nfindAll() {}\n", ".ts") == {
        ("versioning", "NestJS", "global", "URI"), ("versioning", "NestJS", "route", "2")}
    assert _found("REST_FRAMEWORK = {'DEFAULT_VERSIONING_CLASS': 'rest_framework.versioning.URLPathVersioning'}\n"
                  "headers = {'Accept-Version': '2'}\n", ".py") == {
        ("versioning", "Django REST framework", "global", "rest_framework.versioning.URLPathVersioning"),
        ("versioning", "version header", "route", "Accept-Version")}
    assert {item[3] for item in _found('return "application/vnd.acme.v2+json";\n', ".java")} == {"v2"}


def test_rate_limits():
    javascript = ("import rateLimit from 'express-rate-limit';\nconst limiter = rateLimit({ windowMs: 15 * 60 * 1000, "
                  "max: 100 });\napp.use('/api', limiter);\n")
    assert _found(javascript, ".js") == {("rate_limit", "express-rate-limit", "router", "windowMs: 15 * 60 * 1000, max: 100")}
    assert _found("import { Throttle, SkipThrottle } from '@nestjs/throttler';\n@Throttle({ default: { limit: 3, ttl: 60000 } })"
                  "\n@SkipThrottle()\n", ".ts") == {
        ("rate_limit", "NestJS throttler", "route", "{ default: { limit: 3, ttl: 60000 } }"),
        ("rate_limit", "NestJS throttler", "exemption", "SkipThrottle")}
    python = ("from flask_limiter import Limiter\nlimiter = Limiter(get_remote_address, app=app, default_limits=['200 per day'])\n"
              "@limiter.limit('5 per minute')\ndef login():\n    pass\n")
    assert _found(python, ".py") == {("rate_limit", "Flask-Limiter/slowapi", "global", "200 per day"),
                                     ("rate_limit", "Flask-Limiter/slowapi", "route", "5 per minute")}
    assert _found('builder.Services.AddRateLimiter(o => {});\n[EnableRateLimiting("fixed")]\n[DisableRateLimiting]\n',
                  ".cs") == {("rate_limit", "ASP.NET Core", "global", "AddRateLimiter"),
                             ("rate_limit", "ASP.NET Core", "route", "fixed"),
                             ("rate_limit", "ASP.NET Core", "exemption", "DisableRateLimiting")}
    assert _found("Rack::Attack.throttle('req/ip', limit: 300, period: 5.minutes) do |req|\nend\n", ".rb") == {
        ("rate_limit", "Rack::Attack", "global", "req/ip")}
    assert _found("Route::middleware('throttle:60,1')->group(function () {});\n", ".php") == {
        ("rate_limit", "Laravel", "route", "60,1")}
    # Without the library imported, .limit() is a query builder's.
    assert _found("rows = query.limit('10')\n", ".py") == set()


def test_validation():
    python = ("from pydantic import BaseModel\nclass Item(BaseModel):\n    name: str\n"
              "from rest_framework import serializers\nclass OrderSerializer(serializers.ModelSerializer):\n    pass\n")
    assert _found(python, ".py") == {("validation", "Pydantic", "model", "Item"),
                                     ("validation", "Django REST framework", "model", "OrderSerializer")}
    javascript = ("const { body, validationResult } = require('express-validator');\n"
                  "app.post('/user', body('email').isEmail(), body('password').isLength({ min: 5 }), handler);\n"
                  "import { z } from 'zod';\nconst User = z.object({ name: z.string() });\n")
    assert _found(javascript, ".js") == {("validation", "express-validator", "route", "email"),
                                         ("validation", "express-validator", "route", "password"),
                                         ("validation", "zod", "model", "")}
    nest = ("import { IsEmail, IsNotEmpty } from 'class-validator';\nexport class CreateUserDto {\n  @IsEmail()\n"
            "  email: string;\n}\napp.useGlobalPipes(new ValidationPipe({ whitelist: true }));\n")
    assert _found(nest, ".ts") == {("validation", "class-validator", "model", "IsEmail"), ("validation", "NestJS", "global", "")}
    java = ("import jakarta.validation.Valid;\nimport jakarta.validation.constraints.NotBlank;\n"
            "public ResponseEntity<User> create(@Valid @RequestBody User user) {}\nclass User { @NotBlank String name; }\n")
    assert _found(java, ".java") == {("validation", "Bean Validation", "route", "Valid"),
                                     ("validation", "Bean Validation", "model", "NotBlank")}
    go = ('import "github.com/go-playground/validator/v10"\ntype User struct {\n'
          '    Email string `json:"email" validate:"required,email"`\n}\n')
    assert _found(go, ".go") == {("validation", "go-playground/validator", "model", "required,email")}
    php = "$validated = $request->validate(['title' => 'required']);\nclass StorePostRequest extends FormRequest {}\n"
    assert _found(php, ".php") == {("validation", "Laravel", "route", ""), ("validation", "Laravel", "model", "StorePostRequest")}
    ruby = "class User < ApplicationRecord\n  validates :email, presence: true\nend\nparams.require(:user).permit(:name)\n"
    assert _found(ruby, ".rb") == {("validation", "Rails", "model", "email"), ("validation", "Rails", "route", "user")}


def test_findings_and_facts(tmp_path: Path):
    path = tmp_path / "source"
    path.write_text("from flask_limiter import Limiter\n@limiter.limit('5 per minute')\n@login_required\ndef login():\n    pass\n",
                    encoding="utf-8")
    record = FileRecord("app/auth.py", path.stat().st_size, ".py", "Source")
    analyzer = PolicyAnalyzer()
    assert analyzer.supports(record)
    with collecting_facts() as facts:
        findings = analyzer.analyze(path, record)
    assert [finding.title for finding in findings] == ["API policy declarations: app/auth.py"]
    assert findings[0].detail.startswith("authentication and authorization: 1; rate limiting: 1.")
    assert "app/auth.py:2 rate limiting route Flask-Limiter/slowapi: 5 per minute" in findings[0].evidence
    assert [(name, json.loads(detail)["category"]) for kind, name, detail in facts.facts if kind == "api_policy"] == [
        ("5 per minute", "rate_limit"), ("Django/Flask-Login", "auth")]


def test_the_patterns_are_linear_on_adversarial_input():
    for extension, text in ((".py", "@login_required\n" * 30_000), (".java", '@PreAuthorize("' * 20_000),
                            (".ts", "@UseGuards(" * 30_000), (".go", "`validate:\"" * 20_000), (".cs", "[Authorize(" * 30_000)):
        started = time.perf_counter()
        policies(text, extension)
        assert time.perf_counter() - started < 10, extension


def test_the_code_index_summarizes_policies_and_versions(tmp_path: Path):
    project = tmp_path / "project"
    files = {
        "app.py": ("from flask import Flask\nfrom flask_limiter import Limiter\napp = Flask(__name__)\n\n\n"
                   '@app.get("/v1/users")\n@limiter.limit("5 per minute")\ndef users_v1():\n    return []\n\n\n'
                   '@app.get("/v2/users")\n@login_required\ndef users_v2():\n    return []\n\n\n'
                   '@app.get("/v2/orders")\ndef orders():\n    return []\n'),
    }
    for name, text in files.items():
        path = project / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 1, quiet=True) == 0
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    value = report["metrics"]["code_index"]["policies"]
    assert value["route_versions"] == {"v1": 1, "v2": 2}
    assert value["counts"] == {"auth": {"route": 1}, "rate_limit": {"route": 1}}
    titles = {item["title"] for item in report["findings"] if item["analyzer"] == "code-index"}
    assert {"API policy declarations", "API versions"} <= titles
