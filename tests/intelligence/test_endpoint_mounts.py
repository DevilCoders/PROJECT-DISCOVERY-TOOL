"""Routers mounted from other files: the code index gives their routes the full path, and the
integration summary uses it."""
import json
from pathlib import Path

from project_discovery.cli import run_scan


def _scan(tmp_path: Path, files: dict[str, str]) -> tuple[dict, dict]:
    project = tmp_path / "project"
    for name, text in files.items():
        path = project / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 1, quiet=True) == 0
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    return report["metrics"]["code_index"], {item["title"]: item for item in report["findings"]
                                             if item["analyzer"] == "code-index"}


def _routes(index: dict) -> set[str]:
    return {f"{item['method']} {item['path']}" for item in index["endpoints"]["routes"]}


def test_python_routers_mounted_from_other_modules(tmp_path: Path):
    index, findings = _scan(tmp_path, {
        "app/__init__.py": "",
        "app/main.py": (
            "from fastapi import FastAPI\n"
            "from app.routers import users\n"
            "from .routers.items import router as items_router\n"
            "app = FastAPI()\n"
            'app.include_router(users.router, prefix="/api")\n'
            'app.include_router(items_router, prefix="/api/v2")\n'
        ),
        "app/routers/__init__.py": "",
        "app/routers/users.py": ('from fastapi import APIRouter\nrouter = APIRouter(prefix="/users")\n\n'
                                 '@router.get("/{user_id}")\nasync def read(user_id: int): ...\n'),
        "app/routers/items.py": 'from fastapi import APIRouter\nrouter = APIRouter()\n\n@router.post("/items")\nasync def add(): ...\n',
        "web/__init__.py": "",
        "web/factory.py": ("from flask import Flask\nfrom .views import bp\n\ndef create_app():\n    app = Flask(__name__)\n"
                           '    app.register_blueprint(bp, url_prefix="/admin")\n    return app\n'),
        "web/views.py": 'from flask import Blueprint\nbp = Blueprint("views", __name__)\n\n@bp.route("/stats")\ndef stats(): ...\n',
        "project/__init__.py": "",
        "project/urls.py": ('from django.urls import include, path\n\nurlpatterns = [\n'
                            '    path("blog/", include("blog.urls")),\n    path("api/", include("missing.urls")),\n]\n'),
        "blog/__init__.py": "",
        "blog/urls.py": ('from django.urls import include, path\nfrom . import views\n\nurlpatterns = [\n'
                         '    path("posts/", views.posts),\n    path("archive/", include("blog.archive_urls")),\n]\n'),
        "blog/archive_urls.py": 'from django.urls import path\nurlpatterns = [path("<int:year>/", views.year)]\n',
    })
    assert _routes(index) >= {"GET /api/users/{user_id}", "POST /api/v2/items", "GET /admin/stats",
                              "ANY /blog/posts/", "ANY /blog/archive/<int:year>/"}
    assert [item["target"] for item in index["endpoints"]["unresolved_mounts"]] == ["missing.urls"]
    assert "Routes mounted from other files" in findings
    served = {(item["method"], item["path"]) for item in index["integration"]["endpoints"]}
    assert ("GET", "/api/users/{}") in served and ("ANY", "/blog/archive/{}/") in served


def test_javascript_routers_required_from_other_modules(tmp_path: Path):
    index, _ = _scan(tmp_path, {
        "server.js": ('const express = require("express");\nconst users = require("./routes/users");\n'
                      'import orders from "./routes/orders.js";\nconst app = express();\n'
                      'app.use("/api/users", users);\napp.use("/api/orders", orders);\napp.use("/health", require("express-healthcheck")());\n'),
        "routes/users.js": ('const router = require("express").Router();\nrouter.get("/:id", show);\n'
                            "module.exports = router;\n"),
        "routes/orders.js": ('import { Router } from "express";\nconst router = Router();\nrouter.post("/", create);\n'
                             "export default router;\n"),
    })
    assert _routes(index) == {"GET /api/users/:id", "POST /api/orders/"}


def test_routes_without_mounts_are_unchanged(tmp_path: Path):
    index, findings = _scan(tmp_path, {"app.py": 'from flask import Flask\napp = Flask(__name__)\n\n@app.get("/x")\ndef x(): ...\n'})
    assert index["endpoints"]["routes"] == [] and index["endpoints"]["route_count"] == 1
    assert "Routes mounted from other files" not in findings
    assert [(item["method"], item["path"]) for item in index["integration"]["endpoints"]] == [("GET", "/x")]
